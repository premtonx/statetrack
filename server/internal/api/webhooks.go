package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/integrations"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// webhookChannelView is the console-facing shape of a channel. The token is
// never returned in full: an operator editing a Slack card sees "…abcd" and
// leaves the field untouched to keep the existing secret, which is both safer
// (no secret in the browser's memory or a screenshot) and less error-prone than
// a masked value the console would have to remember to not save back.
type webhookChannelView struct {
	storage.WebhookChannel
	// TokenSet reports whether a secret is stored, so the form can render
	// "configured" without seeing the value.
	TokenSet bool `json:"token_set"`
	// LastDelivery is the newest attempt, for the per-card status badge.
	LastDelivery *storage.WebhookDelivery `json:"last_delivery,omitempty"`
}

// webhookIntegrationsResponse is the GET /api/v1/integrations/webhooks payload.
type webhookIntegrationsResponse struct {
	Channels []webhookChannelView `json:"channels"`
	// RecentDeliveries is the cross-provider delivery log the hub's status table
	// renders.
	RecentDeliveries []storage.WebhookDelivery `json:"recent_deliveries"`
}

// webhookIntegrationsGet returns every notification channel plus the recent
// delivery log.
//
//	GET /api/v1/integrations/webhooks
func (s *Server) webhookIntegrationsGet(w http.ResponseWriter, r *http.Request) {
	channels, err := s.Store.ListWebhookChannels(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	recent, err := s.Store.ListWebhookDeliveries(r.Context(), s.OrgID, "", 50)
	if err != nil {
		writeErr(w, err)
		return
	}

	// Index the newest delivery per provider so each card can show its own
	// last result without a query per provider.
	lastByProvider := make(map[string]*storage.WebhookDelivery, len(storage.WebhookProviders))
	for i := range recent {
		d := recent[i]
		if _, seen := lastByProvider[d.Provider]; !seen {
			lastByProvider[d.Provider] = &d
		}
	}

	views := make([]webhookChannelView, 0, len(channels))
	for _, c := range channels {
		views = append(views, webhookChannelView{
			WebhookChannel: c,
			TokenSet:       strings.TrimSpace(c.Token) != "",
			LastDelivery:   lastByProvider[c.Provider],
		})
	}

	writeJSON(w, http.StatusOK, webhookIntegrationsResponse{
		Channels:         views,
		RecentDeliveries: recent,
	})
}

// webhookIntegrationsPut upserts one provider's configuration.
//
//	PUT /api/v1/integrations/webhooks
//
// The body names the provider and carries a partial update: a card saves only
// its own fields, so the console never has to round-trip another provider's
// secret. An absent token keeps the stored one; an explicitly empty token
// clears it (that is what "remove the signing secret" means).
func (s *Server) webhookIntegrationsPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider     string  `json:"provider"`
		URL          *string `json:"url"`
		Token        *string `json:"token"`
		Label        *string `json:"label"`
		Severity     *string `json:"severity"`
		NotifyL1     *bool   `json:"notify_l1"`
		NotifyStorms *bool   `json:"notify_storms"`
		Enabled      *bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	provider := strings.ToLower(strings.TrimSpace(body.Provider))
	if !storage.IsWebhookProvider(provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "provider must be one of teams, slack, pagerduty or webhook",
		})
		return
	}

	current, err := s.Store.GetWebhookChannel(r.Context(), s.OrgID, provider)
	if err != nil {
		writeErr(w, err)
		return
	}
	next := current

	if body.URL != nil {
		target := strings.TrimSpace(*body.URL)
		if target != "" {
			// A bad URL saved here would silently break every future
			// notification, so reject it at write time rather than at dispatch.
			// PagerDuty's routing key is not a URL, but its endpoint is, and the
			// form always supplies the Events API URL for it.
			if parsed, perr := url.Parse(target); perr != nil || parsed.Scheme == "" || parsed.Host == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "url must be an absolute URL, e.g. https://hooks.slack.com/services/…",
				})
				return
			}
		}
		next.URL = target
	}
	if body.Token != nil {
		next.Token = *body.Token
	}
	if body.Label != nil {
		next.Label = strings.TrimSpace(*body.Label)
	}
	if body.Severity != nil {
		next.Severity = strings.TrimSpace(*body.Severity)
	}
	if body.NotifyL1 != nil {
		next.NotifyL1 = *body.NotifyL1
	}
	if body.NotifyStorms != nil {
		next.NotifyStorms = *body.NotifyStorms
	}
	if body.Enabled != nil {
		// Enabling a channel with no target would fail on the first real change
		// with a confusing "unsupported protocol scheme" error; catch it now.
		if *body.Enabled && strings.TrimSpace(next.URL) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "cannot enable this channel without a target URL",
			})
			return
		}
		next.Enabled = *body.Enabled
	}

	saved, err := s.Store.SaveWebhookChannel(r.Context(), s.OrgID, next)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, webhookChannelView{
		WebhookChannel: saved,
		TokenSet:       strings.TrimSpace(saved.Token) != "",
	})
}

// webhookDeliveriesGet is the delivery log on its own, for the hub's
// auto-refreshing status table.
//
//	GET /api/v1/integrations/webhooks/deliveries?provider=slack&limit=50
func (s *Server) webhookDeliveriesGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	provider := strings.ToLower(strings.TrimSpace(q.Get("provider")))
	limit := 50
	if provider != "" && !storage.IsWebhookProvider(provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider"})
		return
	}
	rows, err := s.Store.ListWebhookDeliveries(r.Context(), s.OrgID, provider, limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": rows, "count": len(rows)})
}

// webhookTestRequest is the Settings → Integrations test form's payload.
type webhookTestRequest struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
	// Secret doubles as the HMAC signing key (generic webhook) or the PagerDuty
	// routing key. It may also be supplied inside the URL, which the tester
	// strips before delivery.
	Secret string `json:"secret"`
	// Sample lets the operator see how a real notification reads. Defaults to
	// a Level 1 critical example.
	Sample string `json:"sample"`
	// Save persists the supplied configuration alongside the test, so "send a
	// test" from a card doubles as "save and verify" without a second round
	// trip. Only honored when the config is valid.
	Save bool `json:"save"`
}

// webhookTestResponse reports what the provider actually said, so an operator
// can debug a rejection without tailing the server log.
type webhookTestResponse struct {
	OK       bool   `json:"ok"`
	Provider string `json:"provider"`
	Status   int    `json:"status"`
	Attempts int    `json:"attempts"`
	Detail   string `json:"detail"`
	// Rendered is the exact body that was POSTed (pretty JSON where possible),
	// so "my Slack message looks wrong" is diagnosable from the console.
	Rendered  string `json:"rendered,omitempty"`
	Signature string `json:"signature,omitempty"`
	TestedAt  string `json:"tested_at"`
	// LatencyMs is the wall-clock time the delivery took, which the hub's
	// status log also records.
	LatencyMs int `json:"latency_ms"`
}

// webhookTest sends a sample notification to a configured provider so an
// operator can validate credentials and formatting from the console.
//
//	POST /api/v1/integrations/webhooks/test
//
// The endpoint accepts the target inline rather than only reading it from the
// database: the natural workflow is "paste my Slack webhook URL and see if it
// works" *before* saving anything. When the channel is already saved and the
// body omits a target, the stored configuration is used instead, so a card's
// "Send Test" button works against what the operator actually configured.
func (s *Server) webhookTest(w http.ResponseWriter, r *http.Request) {
	var body webhookTestRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	provider := strings.ToLower(strings.TrimSpace(body.Provider))
	if provider == "" {
		provider = integrations.ProviderWebhook
	}
	if !storage.IsWebhookProvider(provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider " + provider})
		return
	}

	secret := body.Secret
	target := strings.TrimSpace(body.URL)
	severity := ""

	// Fall back to the saved channel so a card's test button can be pressed
	// without the console having to hold (and resend) the stored secret.
	if target == "" {
		if s.Store == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no target URL supplied"})
			return
		}
		saved, err := s.Store.GetWebhookChannel(r.Context(), s.OrgID, provider)
		if err != nil {
			writeErr(w, err)
			return
		}
		target = strings.TrimSpace(saved.URL)
		secret = saved.Token
		severity = saved.Severity
	}
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "no target URL configured for " + provider,
		})
		return
	}

	// Allow the generic webhook's HMAC secret to ride in the URL so the console
	// needs only one field for the common SIEM case.
	if provider == integrations.ProviderWebhook {
		stripped, urlSecret := integrations.SigningSecretFromURL(target)
		target = stripped
		if secret == "" {
			secret = urlSecret
		}
	}

	ch := integrations.Channel{
		Provider:       provider,
		URL:            target,
		Secret:         secret,
		MinImpactLevel: 1,
		NotifyStorms:   true,
		Severity:       severity,
	}

	event := sampleEvent(body.Sample)
	if event.DeepLink == "" {
		// The deep link needs the console base URL, which only the server
		// knows; without it the sample would not exercise the button the
		// operator is trying to validate.
		base := s.UIBaseURL
		if base == "" {
			base = integrations.DefaultUIBaseURL
		}
		event.DeepLink = strings.TrimRight(base, "/") + "/events/" + event.ID + "?tab=diff"
	}
	if event.Hostname == "" {
		event.Hostname = "prod-web-01"
	}
	rendered, _, _, err := integrations.Render(ch, event)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	dispatcher := integrations.NewDispatcher(integrations.DispatcherOptions{
		HTTPClient: s.integrationHTTPClient(),
		UIBaseURL:  s.UIBaseURL,
		Metrics:    s.Metrics,
	})
	started := time.Now()
	result := dispatcher.Dispatch(r.Context(), ch, event)
	latency := int(time.Since(started).Milliseconds())

	// Record the attempt so the hub's status log reflects the test. Best-effort:
	// a logging failure must not turn a successful delivery into an error, and a
	// server without a store (unit tests constructing a bare handler) still
	// serves the endpoint.
	if s.Store != nil {
		if err := s.Store.LogWebhookDelivery(r.Context(), s.OrgID, storage.WebhookDelivery{
			Provider:   provider,
			Endpoint:   target,
			EventID:    event.ID,
			StatusCode: result.Status,
			LatencyMs:  latency,
			Success:    result.OK(),
			Attempts:   result.Attempts,
			Sample:     true,
			Error:      errString(result.Err),
		}); err != nil {
			s.logger().Warn("record webhook delivery", "provider", provider, "err", err)
		}
	}

	resp := webhookTestResponse{
		OK:        result.OK(),
		Provider:  provider,
		Status:    result.Status,
		Attempts:  result.Attempts,
		Rendered:  prettyJSON(rendered),
		TestedAt:  time.Now().UTC().Format(time.RFC3339),
		LatencyMs: latency,
	}
	if provider == integrations.ProviderWebhook && secret != "" {
		// Echo the signature so the receiver's author can confirm their own
		// verification against the same value.
		resp.Signature = integrations.SignPayload(secret, rendered)
	}
	switch {
	case result.OK():
		resp.Detail = "delivered"
	case result.Err != nil:
		resp.Detail = result.Err.Error()
	default:
		resp.Detail = "the provider rejected the request"
	}

	// A failed test is a 502, not a 200 with ok=false: the console's fetch
	// wrapper keys off the status code, and the distinction between "the test
	// ran and the provider refused" and "the request was malformed" matters.
	status := http.StatusOK
	if !result.OK() {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, resp)
}

// errString renders an error for the delivery log.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// sampleEvent builds a realistic Level 1 notification. A test message that looks
// nothing like production is worse than none: it hides formatting problems such
// as a truncated path or a missing deep link.
func sampleEvent(kind string) integrations.Event {
	ev := integrations.Event{
		ID:         "00000000-0000-4000-8000-0000000000ff",
		Hostname:   "prod-web-01",
		OccurredAt: time.Now().UTC(),
		Level:      pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
		Category:   pb.Category_CATEGORY_CONFIG,
		Action:     pb.Action_ACTION_MODIFIED,
		Summary:    "Modified /etc/nginx/nginx.conf (+12 -3)",
		Actor:      "alice",
		Tool:       "vim",
		Target:     "/etc/nginx/nginx.conf",
	}
	if strings.EqualFold(kind, "storm") {
		ev.IsStorm = true
		ev.SuppressedMutations = 512
		ev.Level = pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT
		ev.Summary = "Change storm: 512 mutations by pid 4242 throttled for 30s"
		ev.Target = "/var/www/html"
	}
	return ev
}

// prettyJSON re-indents a compact JSON body so the console can show it in a
// readable code block. On failure the original bytes are returned unchanged.
func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
