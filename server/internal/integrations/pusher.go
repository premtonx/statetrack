// Package integrations pushes high-impact events to external systems:
// Grafana annotations, Slack/PagerDuty, and generic JSON webhooks. A worker
// consumes root events asynchronously so ingestion latency is unaffected.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/metrics"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// DefaultUIBaseURL is the deep-link base for the StateTrack web console.
const DefaultUIBaseURL = "http://localhost:5173"

// SeedTag is the tag carried by every StateTrack annotation — seeded and live
// alike. Grafana queries it to draw one "change happened here" series.
//
// Exported because the seeders need to *purge* by the same tag they push with;
// a private constant would let the two drift and leave stale flags (with dead
// deep links) on the dashboard.
const SeedTag = "statetrack"

// Options configures a Pusher.
type Options struct {
	Store      *storage.Store
	UIBaseURL  string
	HTTPClient *http.Client
	Logger     *slog.Logger
	Buffer     int
	// Metrics counts deliveries by provider and outcome. Optional.
	Metrics *metrics.Registry
	// Notifier renders and delivers to the enterprise providers (Slack Block
	// Kit, PagerDuty Events v2, Teams MessageCard, signed generic webhook).
	// Optional: without it the pusher still posts Grafana annotations.
	Notifier *Dispatcher
}

// Pusher is an asynchronous annotation/webhook worker.
type Pusher struct {
	opts Options
	ch   chan storage.Notification
}

// New builds a Pusher.
func New(opts Options) *Pusher {
	if opts.UIBaseURL == "" {
		opts.UIBaseURL = DefaultUIBaseURL
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.Buffer <= 0 {
		opts.Buffer = 1024
	}
	return &Pusher{opts: opts, ch: make(chan storage.Notification, opts.Buffer)}
}

func (p *Pusher) logger() *slog.Logger {
	if p.opts.Logger != nil {
		return p.opts.Logger
	}
	return slog.Default()
}

// Enqueue hands a notification to the worker; never blocks (drops when the
// buffer is full so ingestion is never stalled).
func (p *Pusher) Enqueue(n storage.Notification) {
	select {
	case p.ch <- n:
	default:
		p.logger().Warn("integration buffer full; dropping notification", "event", n.ID)
	}
}

// Run dispatches notifications until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case n := <-p.ch:
			p.dispatch(ctx, n)
		}
	}
}

func (p *Pusher) dispatch(ctx context.Context, n storage.Notification) {
	// Only root events trigger external notifications (children are grouped).
	if n.ParentEventID != "" {
		return
	}
	integrations, err := p.opts.Store.ListIntegrations(ctx, n.OrgID)
	if err != nil {
		p.logger().Error("list integrations", "err", err)
		return
	}
	// Build the provider-agnostic event once so every channel reports the same
	// facts about the same change.
	event := EventFromNotification(p.opts.UIBaseURL, n)

	for _, in := range integrations {
		// A storm carries its own opt-in: it is not a level, so the level filter
		// would otherwise swallow it even for an operator who wants storm pages.
		if event.IsStorm {
			if !in.NotifyStorms {
				continue
			}
		} else if int32(n.ImpactLevel) > in.MinImpactLevel {
			continue // impact_level <= min_impact_level triggers
		}
		switch in.Provider {
		case "grafana_annotations":
			p.postGrafana(ctx, in, n)
		case "slack", "pagerduty", "teams", "webhook", "siem":
			p.notify(ctx, in, n, event)
		default:
			p.logger().Warn("unknown integration provider", "provider", in.Provider)
		}
	}
}

// notify delivers an event through the enterprise dispatcher and records the
// outcome. The token is used as the PagerDuty routing key or the generic
// webhook's HMAC secret, depending on the provider.
func (p *Pusher) notify(ctx context.Context, in storage.Integration, n storage.Notification, ev Event) {
	// Without a dispatcher (a deployment that only wants Grafana annotations)
	// fall back to the original unsigned JSON POST so behaviour is unchanged.
	if p.opts.Notifier == nil {
		body, _ := FormatGeneric(ev)
		if err := p.post(ctx, in.EndpointURL, in.APIToken, body); err != nil {
			p.logger().Error("webhook dispatch failed", "provider", in.Provider, "event", ev.ID, "err", err)
		}
		return
	}

	target := in.EndpointURL
	secret := in.APIToken
	if strings.EqualFold(in.Provider, ProviderWebhook) || strings.EqualFold(in.Provider, "siem") {
		// Allow the HMAC secret to travel in the URL for the single-field test
		// form; the parameter is stripped before delivery so it never appears in
		// the receiver's access log.
		target, secret = SigningSecretFromURL(in.EndpointURL)
	}

	ch := Channel{
		Provider:       normalizeProvider(in.Provider),
		URL:            target,
		Secret:         secret,
		MinImpactLevel: in.MinImpactLevel,
		// A storm is a distinct notification class that the level filter would
		// otherwise swallow, so it rides its own opt-in flag.
		NotifyStorms: in.NotifyStorms,
		Severity:     in.Severity,
	}
	if !ch.Wants(ev) {
		return
	}

	started := time.Now()
	result := p.opts.Notifier.Dispatch(ctx, ch, ev)
	latency := int(time.Since(started).Milliseconds())

	// Record the attempt so the Integrations hub's delivery log reflects real
	// change notifications, not only the console's test sends.
	deliveryErr := p.opts.Store.LogWebhookDelivery(ctx, n.OrgID, storage.WebhookDelivery{
		Provider:   in.Provider,
		Endpoint:   target,
		EventID:    ev.ID,
		StatusCode: result.Status,
		LatencyMs:  latency,
		Success:    result.OK(),
		Attempts:   result.Attempts,
		Error:      errText(result.Err),
	})
	if deliveryErr != nil {
		p.logger().Warn("record webhook delivery", "provider", in.Provider, "err", deliveryErr)
	}

	if !result.OK() {
		p.logger().Error("notification delivery failed",
			"provider", ch.Provider, "event", ev.ID, "status", result.Status,
			"attempts", result.Attempts, "err", result.Err)
		return
	}
	p.logger().Debug("notification delivered",
		"provider", ch.Provider, "event", ev.ID, "status", result.Status)
}

// errText renders an error for the delivery log.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// normalizeProvider maps the integration row's provider onto a dispatchable
// provider name.
func normalizeProvider(provider string) string {
	switch strings.ToLower(provider) {
	case "siem":
		return ProviderWebhook
	default:
		return strings.ToLower(provider)
	}
}

func (p *Pusher) postGrafana(ctx context.Context, in storage.Integration, n storage.Notification) {
	body, _ := json.Marshal(FormatAnnotation(p.opts.UIBaseURL, n))
	if err := p.post(ctx, in.EndpointURL, in.APIToken, body); err != nil {
		p.logger().Error("grafana annotation failed", "event", n.ID, "err", err)
	}
}

func (p *Pusher) post(ctx context.Context, url, token string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := p.opts.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Grafana returns 200 on success.
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, string(msg))
	}
	return nil
}

// Annotation is a Grafana annotation payload.
//
// Deliberately only three fields. Grafana renders an annotation as a *region*
// curtain whenever it receives a timeEnd (or isRegion), and a curtain spanning
// the whole panel is exactly the artifact the dashboard used to be broken by.
// Posting `time` alone makes Grafana draw a single vertical line, which is what
// the hero panel is designed around; there is no optional field here that could
// reintroduce the region form.
type Annotation struct {
	Time int64    `json:"time"` // unix ms
	Text string   `json:"text"`
	Tags []string `json:"tags"`
}

// FormatAnnotation renders a Grafana annotation for a root event.
//
// Three lines, because that is what a viewer reads on hover: what changed, who
// did it to which host, and where to go for the diff. The level leads the text
// so a screenshot of the flag is self-describing, and the `level:L1` / `level:L2`
// tag is what lets the dashboard style the same series in two colours (two
// annotation layers, one per level — see the dashboard's annotations.list).
func FormatAnnotation(uiBaseURL string, n storage.Notification) Annotation {
	if uiBaseURL == "" {
		uiBaseURL = DefaultUIBaseURL
	}
	text := "<b>[" + LevelName(n.ImpactLevel) + "] " + n.Summary + "</b><br/>" +
		n.ActorName + " &middot; " + n.Hostname +
		"<br/><a href='" + uiBaseURL + "/events/" + n.ID + "?tab=diff' target='_blank'>Inspect in StateTrack &#8594;</a>"
	return Annotation{
		Time: n.OccurredAt.UnixMilli(),
		Text: text,
		Tags: []string{
			SeedTag,
			"host:" + n.Hostname,
			"level:" + LevelName(n.ImpactLevel),
			"category:" + CategoryName(n.Category),
		},
	}
}

// LevelName renders an impact level as a compact tag value.
func LevelName(l pb.ImpactLevel) string {
	switch l {
	case pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL:
		return "L1"
	case pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED:
		return "L2"
	case pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT:
		return "L3"
	case pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC:
		return "L4"
	default:
		return "L0"
	}
}

// CategoryName renders a category as a compact tag value.
func CategoryName(c pb.Category) string {
	switch c {
	case pb.Category_CATEGORY_CONFIG:
		return "config"
	case pb.Category_CATEGORY_PACKAGE:
		return "package"
	case pb.Category_CATEGORY_SERVICE:
		return "service"
	case pb.Category_CATEGORY_USER:
		return "user"
	case pb.Category_CATEGORY_REGISTRY:
		return "registry"
	case pb.Category_CATEGORY_NETWORK:
		return "network"
	case pb.Category_CATEGORY_PROCESS:
		return "process"
	case pb.Category_CATEGORY_AGENT_HEALTH:
		return "agent_health"
	default:
		return "unspecified"
	}
}

// ActionName renders an action as a compact value.
func ActionName(a pb.Action) string {
	switch a {
	case pb.Action_ACTION_CREATED:
		return "created"
	case pb.Action_ACTION_MODIFIED:
		return "modified"
	case pb.Action_ACTION_DELETED:
		return "deleted"
	case pb.Action_ACTION_RESTARTED:
		return "restarted"
	case pb.Action_ACTION_STARTED:
		return "started"
	case pb.Action_ACTION_STOPPED:
		return "stopped"
	case pb.Action_ACTION_UPGRADED:
		return "upgraded"
	case pb.Action_ACTION_THROTTLED:
		return "throttled"
	default:
		return "unspecified"
	}
}
