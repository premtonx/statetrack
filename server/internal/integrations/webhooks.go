// Outbound notification channels for high-impact changes.
//
// Four providers are supported, each with its own wire format but a shared
// dispatch path:
//
//	webhook    — generic JSON for SIEM/log shippers, signed with HMAC-SHA256
//	slack      — Block Kit message with a deep link to the diff drawer
//	pagerduty  — Events API v2 trigger, deduplicated per event
//	teams      — MessageCard with an "Open in StateTrack" action
//
// Design notes that matter operationally:
//
//   - The payload is built once (Event) and rendered per provider, so a provider
//     added later cannot drift from the others in which fields it reports.
//   - Formatters are pure functions of an Event. They are the unit under test;
//     the network path is a thin shell around them.
//   - Every attempt is counted in Prometheus with a *closed* set of labels
//     (provider, success/client_error/server_error/error), never the URL or the
//     event id.
package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/metrics"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// Provider identifiers. These strings are also the `integrations.provider`
// column values and the Prometheus `provider` label, so they are stable.
const (
	ProviderWebhook   = "webhook"
	ProviderSlack     = "slack"
	ProviderPagerDuty = "pagerduty"
	ProviderTeams     = "teams"
)

// SignatureHeader carries the HMAC of the request body for generic webhooks.
const SignatureHeader = "X-StateTrack-Signature"

// SignatureScheme prefixes the hex digest so a receiver can tell which
// algorithm produced it and rotate later without breaking the integration.
const SignatureScheme = "sha256="

// maxResponseBytes bounds how much of a failing provider's response is retained
// for the error message. A provider returning a gigabyte of HTML must not be
// able to exhaust the server's memory.
const maxResponseBytes = 4 << 10

// defaultRetries is how many additional attempts a retryable failure gets.
const defaultRetries = 2

// Event is the provider-agnostic description of a change. Every formatter
// renders from this, so adding a provider cannot silently omit the actor or the
// deep link.
type Event struct {
	ID         string
	Hostname   string
	OccurredAt time.Time

	Level    pb.ImpactLevel
	Category pb.Category
	Action   pb.Action

	Summary string
	Actor   string
	// Tool is the process that made the change ("vim", "apt"). Rendered
	// alongside the actor as "alice via vim".
	Tool   string
	Target string

	RuleName string

	// DeepLink opens the Monaco diff drawer for this change.
	DeepLink string

	Metadata map[string]string

	// IsStorm marks a change-storm summary rather than an individual mutation.
	// It is a distinct notification class because the useful response is
	// different: a storm means "something is writing in a loop", not "review
	// this diff".
	IsStorm bool
	// SuppressedMutations is how many mutations a storm swallowed.
	SuppressedMutations int
}

// EventFromNotification builds an Event from an ingested event, filling in the
// console deep link.
func EventFromNotification(uiBaseURL string, n storage.Notification) Event {
	if uiBaseURL == "" {
		uiBaseURL = DefaultUIBaseURL
	}
	ev := Event{
		ID:         n.ID,
		Hostname:   n.Hostname,
		OccurredAt: n.OccurredAt,
		Level:      n.ImpactLevel,
		Category:   n.Category,
		Action:     n.Action,
		Summary:    n.Summary,
		Actor:      n.ActorName,
		Target:     n.PathOrKey,
		Metadata:   n.Metadata,
		IsStorm:    n.Action == pb.Action_ACTION_THROTTLED,
	}
	if n.ID != "" {
		ev.DeepLink = strings.TrimRight(uiBaseURL, "/") + "/events/" + n.ID + "?tab=diff"
	}
	if n.Metadata != nil {
		ev.RuleName = n.Metadata["rule_name"]
		// The agent records the storm size in the summary's metadata.
		if raw := n.Metadata["mutation_count"]; raw != "" {
			var count int
			if _, err := fmt.Sscanf(raw, "%d", &count); err == nil {
				ev.SuppressedMutations = count
			}
		}
	}
	// The tool is carried as part of the actor rendering by the agent; the
	// notification exposes the process name separately when the storage layer
	// has it.
	if tool, ok := n.Metadata["process_name"]; ok {
		ev.Tool = tool
	}
	return ev
}

// Channel is one configured delivery target.
type Channel struct {
	Provider string
	// URL is the target endpoint. For every provider this is a URL we POST to,
	// including PagerDuty's Events API and Slack's incoming webhook.
	URL string
	// Secret is the HMAC signing key (generic webhook) or the provider's
	// credential: Slack's is unused, PagerDuty's is the routing key.
	Secret string
	// MinImpactLevel is the lowest numeric level that delivers (1 is most
	// severe, so `level <= MinImpactLevel` triggers).
	MinImpactLevel int32
	// NotifyStorms opts this channel into change-storm notifications, which are
	// reported at their own level and would otherwise be filtered out by a
	// Level 1-only channel.
	NotifyStorms bool
	// Severity overrides the provider's derived severity. Currently only
	// PagerDuty honors it (Events API v2 `severity`); empty means "derive it
	// from the impact level", which is the default for every other provider.
	Severity string
}

// Wants reports whether this channel should receive the event.
func (c Channel) Wants(ev Event) bool {
	if ev.IsStorm {
		return c.NotifyStorms
	}
	return int32(ev.Level) <= c.MinImpactLevel
}

// DeliveryResult records the outcome of one dispatch attempt.
type DeliveryResult struct {
	Provider string
	Status   int
	Attempts int
	Err      error
}

// OK reports whether the provider accepted the delivery.
func (r DeliveryResult) OK() bool { return r.Err == nil && r.Status >= 200 && r.Status < 300 }

// Dispatcher renders and delivers notifications to configured channels.
type Dispatcher struct {
	client  *http.Client
	uiBase  string
	metrics *metrics.Registry
	retries int
	sleep   func(time.Duration)
}

// DispatcherOptions configures a Dispatcher.
type DispatcherOptions struct {
	HTTPClient *http.Client
	UIBaseURL  string
	Metrics    *metrics.Registry
	// Retries is the number of *additional* attempts after the first.
	Retries int
}

// NewDispatcher builds a Dispatcher.
func NewDispatcher(opts DispatcherOptions) *Dispatcher {
	d := &Dispatcher{
		client:  opts.HTTPClient,
		uiBase:  opts.UIBaseURL,
		metrics: opts.Metrics,
		retries: opts.Retries,
		sleep:   time.Sleep,
	}
	if d.client == nil {
		d.client = &http.Client{Timeout: 10 * time.Second}
	}
	if d.uiBase == "" {
		d.uiBase = DefaultUIBaseURL
	}
	if d.retries < 0 {
		d.retries = 0
	} else if d.retries == 0 {
		d.retries = defaultRetries
	}
	return d
}

// Dispatch renders the event for the channel's provider, signs it where
// applicable, and delivers it with bounded retries.
func (d *Dispatcher) Dispatch(ctx context.Context, ch Channel, ev Event) DeliveryResult {
	result := DeliveryResult{Provider: ch.Provider}

	body, contentType, headers, err := Render(ch, ev)
	if err != nil {
		result.Err = err
		d.record(ch.Provider, 0, true)
		return result
	}

	// Attempt loop. Only transport failures and 5xx/429 are retried: a 4xx means
	// the request is wrong (bad token, bad payload) and repeating it would just
	// spam the provider and the logs.
	for attempt := 0; attempt <= d.retries; attempt++ {
		result.Attempts = attempt + 1
		status, retryable, err := d.attempt(ctx, ch.URL, contentType, headers, body)
		result.Status = status
		result.Err = err

		if err == nil && status >= 200 && status < 300 {
			d.record(ch.Provider, status, false)
			return result
		}
		if !retryable || attempt == d.retries {
			break
		}
		// Linear backoff, capped. A notification that is a few hundred
		// milliseconds late is fine; holding a worker for minutes is not.
		d.sleep(time.Duration(attempt+1) * 250 * time.Millisecond)
	}

	if result.Err == nil {
		result.Err = fmt.Errorf("%s: HTTP %d", ch.Provider, result.Status)
	}
	// `failed` means the request never produced an HTTP response. An HTTP error
	// status is reported through `status` instead, so the client_error and
	// server_error buckets stay reachable and an operator can tell "the
	// provider is rejecting us" from "we cannot reach the provider".
	d.record(ch.Provider, result.Status, result.Status == 0)
	return result
}

// attempt performs one HTTP POST. It reports whether the failure is retryable.
func (d *Dispatcher) attempt(ctx context.Context, url, contentType string, headers map[string]string, body []byte) (int, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		// A malformed URL will never succeed; not retryable.
		return 0, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "StateTrack-Notifier/1.0")
	for k, v := range headers {
		// Assign the map directly rather than through Header.Set: Set runs the
		// key through textproto.CanonicalMIMEHeaderKey, which would rewrite our
		// documented "X-StateTrack-Signature" to "X-Statetrack-Signature" on
		// the wire. Header names are case-insensitive per RFC 7230 so either
		// resolves, but SIEM receivers regularly match the configured header
		// name literally, and an operator debugging a rejection should see the
		// exact spelling the docs promise.
		req.Header[k] = []string{v}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		// Timeouts and connection failures can be transient.
		return 0, true, err
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused.
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return resp.StatusCode, false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return resp.StatusCode, true, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(payload))
	default:
		return resp.StatusCode, false, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(payload))
	}
}

func (d *Dispatcher) record(provider string, status int, failed bool) {
	if d.metrics == nil {
		return
	}
	d.metrics.RecordWebhookDelivery(provider, status, failed)
}

// snippet trims a provider response for an error message.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	if s == "" {
		return "(empty response)"
	}
	return s
}

/* -------------------------------------------------------------------------- */
/* Rendering                                                                  */
/* -------------------------------------------------------------------------- */

// Render produces the request body, content type and extra headers for a
// channel. It is a pure function so each provider's wire format can be tested
// without a network or a server.
func Render(ch Channel, ev Event) ([]byte, string, map[string]string, error) {
	switch ch.Provider {
	case ProviderSlack:
		body, err := FormatSlack(ev)
		return body, "application/json", nil, err
	case ProviderPagerDuty:
		body, err := FormatPagerDuty(ch.Secret, ch.Severity, ev)
		return body, "application/json", nil, err
	case ProviderTeams:
		body, err := FormatTeams(ev)
		return body, "application/json", nil, err
	case ProviderWebhook, "":
		body, err := FormatGeneric(ev)
		if err != nil {
			return nil, "", nil, err
		}
		headers := map[string]string{"X-StateTrack-Event": ev.ID}
		if ch.Secret != "" {
			// The signature covers the exact bytes on the wire, so the receiver
			// can verify before trusting any field inside.
			headers[SignatureHeader] = SignPayload(ch.Secret, body)
		}
		return body, "application/json", headers, nil
	default:
		return nil, "", nil, fmt.Errorf("unknown provider %q", ch.Provider)
	}
}

// SignPayload computes the HMAC-SHA256 of a payload:
//
//	sha256=<hex digest>
//
// The scheme prefix lets a receiver detect an algorithm change instead of
// silently comparing digests of different lengths.
func SignPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return SignatureScheme + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks a signature in constant time. Exported so receivers
// (and tests) use the same comparison rather than a naive string equality that
// leaks timing information.
func VerifySignature(secret string, body []byte, signature string) bool {
	expected := SignPayload(secret, body)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// SigningSecretFromURL extracts the shared secret from a generic webhook URL
// when it is supplied as a query parameter.
//
// This exists because the console's "test webhook" form takes a single URL, and
// requiring a second field for the secret would make the common
// "point it at my SIEM receiver" flow awkward. The query parameter is stripped
// from the delivered URL so the secret never lands in the receiver's access log
// alongside the payload.
func SigningSecretFromURL(raw string) (url string, secret string) {
	idx := strings.Index(raw, "?")
	if idx < 0 {
		return raw, ""
	}
	base, query := raw[:idx], raw[idx+1:]
	kept := make([]string, 0, 2)
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		switch key {
		case "secret", "signing_secret":
			secret = value
		default:
			kept = append(kept, pair)
		}
	}
	if len(kept) == 0 {
		return base, secret
	}
	return base + "?" + strings.Join(kept, "&"), secret
}

// GenericPayload is the SIEM-facing JSON document. Field names are stable and
// snake_cased to match the rest of the API.
type GenericPayload struct {
	Provider     string `json:"provider"`
	EventType    string `json:"event_type"`
	EventID      string `json:"event_id"`
	Host         string `json:"host"`
	OccurredAt   int64  `json:"occurred_at"` // unix ms
	ImpactLevel  string `json:"impact_level"`
	ImpactNumber int32  `json:"impact_number"`
	Category     string `json:"category"`
	Action       string `json:"action"`
	Summary      string `json:"summary"`
	Actor        string `json:"actor,omitempty"`
	Tool         string `json:"tool,omitempty"`
	TargetPath   string `json:"target_path,omitempty"`
	RuleName     string `json:"rule_name,omitempty"`
	Status       string `json:"status"`
	// Inspect opens the diff drawer; kept for compatibility with the original
	// payload field name, and DeepLink is the explicit alias.
	Inspect  string            `json:"inspect"`
	DeepLink string            `json:"deep_link"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// FormatGeneric builds the plain JSON body used for SIEM/log shippers.
func FormatGeneric(ev Event) ([]byte, error) {
	payload := GenericPayload{
		Provider:     "statetrack",
		EventType:    eventType(ev),
		EventID:      ev.ID,
		Host:         ev.Hostname,
		OccurredAt:   ev.OccurredAt.UnixMilli(),
		ImpactLevel:  LevelName(ev.Level),
		ImpactNumber: int32(ev.Level),
		Category:     CategoryName(ev.Category),
		Action:       ActionName(ev.Action),
		Summary:      ev.Summary,
		Actor:        ev.Actor,
		Tool:         ev.Tool,
		TargetPath:   ev.Target,
		RuleName:     ev.RuleName,
		Status:       statusLabel(ev),
		Inspect:      ev.DeepLink,
		DeepLink:     ev.DeepLink,
		Metadata:     ev.Metadata,
	}
	return json.Marshal(payload)
}

// eventType is the machine-readable classification a SIEM rules on. It is
// deliberately coarser than the category: a SIEM wants a handful of stable
// event types to write detections against, not one per category/action pair.
func eventType(ev Event) string {
	if ev.IsStorm {
		return "CHANGE_STORM"
	}
	if ev.Level == pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
		return "CRITICAL_MUTATION"
	}
	return "MUTATION"
}

// statusLabel describes the severity in the vocabulary a SIEM or a status page
// expects, so a receiver does not have to know StateTrack's level numbering.
func statusLabel(ev Event) string {
	switch {
	case ev.IsStorm:
		return "storm"
	case ev.Level == pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL:
		return "critical"
	case ev.Level == pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED:
		return "warning"
	default:
		return "info"
	}
}

// actorLabel renders "alice via vim", degrading gracefully when either half is
// missing. Used by Slack, Teams and PagerDuty so they read identically.
func actorLabel(ev Event) string {
	switch {
	case ev.Actor != "" && ev.Tool != "":
		return ev.Actor + " via " + ev.Tool
	case ev.Actor != "":
		return ev.Actor
	case ev.Tool != "":
		return "unknown actor via " + ev.Tool
	default:
		return "unknown actor"
	}
}

// FormatSlack builds a Block Kit message: a header, the impact badge with the
// host, a field grid (server, actor, path), and a primary button into the diff
// drawer.
func FormatSlack(ev Event) ([]byte, error) {
	badge := LevelName(ev.Level)
	headline := fmt.Sprintf("*%s: %s*", badge, ev.Summary)
	if ev.IsStorm {
		headline = fmt.Sprintf("*%s: Change storm on %s*", badge, ev.Hostname)
	}

	fields := []map[string]any{
		{"type": "mrkdwn", "text": fmt.Sprintf("*Server*\n`%s`", ev.Hostname)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Actor*\n%s", actorLabel(ev))},
	}
	if ev.Target != "" {
		fields = append(fields, map[string]any{
			"type": "mrkdwn", "text": fmt.Sprintf("*Path*\n`%s`", ev.Target),
		})
	}
	fields = append(fields, map[string]any{
		"type": "mrkdwn",
		"text": fmt.Sprintf("*Impact*\n%s · %s", badge, CategoryName(ev.Category)),
	})
	if ev.RuleName != "" {
		fields = append(fields, map[string]any{
			"type": "mrkdwn", "text": fmt.Sprintf("*Rule*\n%s", ev.RuleName),
		})
	}
	if ev.IsStorm && ev.SuppressedMutations > 0 {
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*Suppressed*\n%d mutations", ev.SuppressedMutations),
		})
	}

	l1 := map[string]any{
		"type": "section",
		"text": map[string]any{"type": "mrkdwn", "text": headline},
	}
	l2 := map[string]any{"type": "section", "fields": fields}

	blocks := []map[string]any{l1, l2}

	// The button is the whole point of the Slack message: one click to the diff.
	if ev.DeepLink != "" {
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{{
				"type":      "button",
				"text":      map[string]any{"type": "plain_text", "text": "Inspect Diff & Actor ↗", "emoji": true},
				"url":       ev.DeepLink,
				"style":     "primary",
				"action_id": "statetrack_inspect_diff",
			}},
		})
	}

	// context carries the event id and timestamp: the metadata an on-call
	// engineer copies into a ticket, kept out of the headline so it does not
	// compete with the summary.
	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{{
			"type": "mrkdwn",
			"text": fmt.Sprintf("StateTrack · `%s` · %s", ev.ID,
				ev.OccurredAt.UTC().Format(time.RFC3339)),
		}},
	})

	body := map[string]any{
		// `text` is the notification/fallback string Slack shows in the
		// sidebar and on devices that cannot render blocks.
		"text":   fmt.Sprintf("[%s] %s on %s by %s", badge, ev.Summary, ev.Hostname, actorLabel(ev)),
		"blocks": blocks,
	}
	return json.Marshal(body)
}

// FormatPagerDuty builds an Events API v2 trigger.
//
// dedup_key is the StateTrack event id, so a redelivery (or a retry after a
// timeout) collapses into the existing incident instead of paging twice.
//
// `override` is the channel's configured severity; when empty the severity is
// derived from the impact level, which is what most teams want. An explicit
// override exists because a team may route every StateTrack change at a fixed
// urgency (e.g. all "warning") and escalate in PagerDuty's own policies.
func FormatPagerDuty(routingKey, override string, ev Event) ([]byte, error) {
	severity := pagerDutySeverity(ev)
	if o := strings.ToLower(strings.TrimSpace(override)); pagerDutySeverities[o] {
		severity = o
	}

	summary := ev.Summary
	if summary == "" {
		summary = fmt.Sprintf("%s change on %s", LevelName(ev.Level), ev.Hostname)
	}
	if len(summary) > 1024 {
		// PagerDuty rejects an over-long summary outright.
		summary = summary[:1021] + "…"
	}

	customDetails := map[string]any{
		"host":         ev.Hostname,
		"impact_level": LevelName(ev.Level),
		"category":     CategoryName(ev.Category),
		"action":       ActionName(ev.Action),
		"actor":        actorLabel(ev),
		"summary":      ev.Summary,
		"occurred_at":  ev.OccurredAt.UTC().Format(time.RFC3339),
	}
	if ev.Target != "" {
		customDetails["target_path"] = ev.Target
	}
	if ev.RuleName != "" {
		customDetails["rule_name"] = ev.RuleName
	}
	if ev.IsStorm {
		customDetails["event_type"] = "CHANGE_STORM"
		customDetails["suppressed_mutations"] = ev.SuppressedMutations
	}
	if ev.DeepLink != "" {
		customDetails["inspect_diff"] = ev.DeepLink
	}
	if len(ev.Metadata) > 0 {
		// Fold the agent's metadata into the details rather than passing it as a
		// nested object: PagerDuty renders flat key/value pairs, and nesting
		// makes them unreadable in the incident timeline.
		for k, v := range ev.Metadata {
			if _, exists := customDetails[k]; exists {
				continue
			}
			customDetails["meta_"+k] = v
		}
	}

	body := map[string]any{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    ev.ID,
		"payload": map[string]any{
			"summary":        summary,
			"source":         ev.Hostname,
			"severity":       severity,
			"timestamp":      ev.OccurredAt.UTC().Format(time.RFC3339),
			"component":      CategoryName(ev.Category),
			"group":          "statetrack",
			"class":          eventType(ev),
			"custom_details": customDetails,
		},
		"links": pagerDutyLinks(ev),
	}
	return json.Marshal(body)
}

// pagerDutySeverities is the closed set Events API v2 accepts.
var pagerDutySeverities = map[string]bool{
	"critical": true,
	"error":    true,
	"warning":  true,
	"info":     true,
}

// pagerDutySeverity derives the severity from the impact level.
func pagerDutySeverity(ev Event) string {
	switch {
	case ev.IsStorm:
		return "warning"
	case ev.Level == pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL:
		return "critical"
	case ev.Level == pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED:
		return "warning"
	default:
		return "info"
	}
}

func pagerDutyLinks(ev Event) []map[string]any {
	if ev.DeepLink == "" {
		return []map[string]any{}
	}
	return []map[string]any{{
		"href": ev.DeepLink,
		"text": "Inspect Diff & Actor",
	}}
}

// FormatTeams builds a MessageCard (the format Zabbix-era Teams connectors and
// most existing incoming webhooks still accept; Adaptive Cards are only
// supported by the newer Workflows endpoints).
func FormatTeams(ev Event) ([]byte, error) {
	themeColor := "1a73e8"
	switch {
	case ev.IsStorm:
		themeColor = "7c3aed"
	case ev.Level == pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL:
		themeColor = "d93025"
	case ev.Level == pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED:
		themeColor = "7c3aed"
	case ev.Level == pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT:
		themeColor = "f9ab00"
	}

	facts := []map[string]string{
		{"name": "Server", "value": ev.Hostname},
		{"name": "Impact", "value": fmt.Sprintf("%s · %s", LevelName(ev.Level), statusLabel(ev))},
		{"name": "Actor", "value": actorLabel(ev)},
	}
	if ev.Target != "" {
		facts = append(facts, map[string]string{"name": "Path", "value": ev.Target})
	}
	if ev.RuleName != "" {
		facts = append(facts, map[string]string{"name": "Rule", "value": ev.RuleName})
	}
	if ev.IsStorm && ev.SuppressedMutations > 0 {
		facts = append(facts, map[string]string{
			"name": "Suppressed", "value": fmt.Sprintf("%d mutations", ev.SuppressedMutations),
		})
	}
	facts = append(facts, map[string]string{"name": "Category", "value": CategoryName(ev.Category)})

	section := map[string]any{
		"activityTitle":    ev.Summary,
		"activitySubtitle": fmt.Sprintf("%s change on %s", LevelName(ev.Level), ev.Hostname),
		"facts":            facts,
		"markdown":         true,
	}
	if ev.DeepLink != "" {
		section["potentialAction"] = []map[string]any{{
			"@type": "OpenUri",
			"name":  "Inspect Diff & Actor",
			"targets": []map[string]any{{
				"os": "default", "uri": ev.DeepLink,
			}},
		}}
	}

	body := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": themeColor,
		"summary":    fmt.Sprintf("[%s] %s on %s", LevelName(ev.Level), ev.Summary, ev.Hostname),
		"title":      "StateTrack change detected",
		"sections":   []map[string]any{section},
	}
	return json.Marshal(body)
}

// ErrNoChannels reports that nothing is configured to receive a notification.
var ErrNoChannels = errors.New("no notification channels configured")
