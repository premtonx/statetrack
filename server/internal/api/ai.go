// Pluggable AI provider gateway endpoints.
//
// The analyzer answers one operational question — "how bad is this change, and
// what is the exact command to undo it?" — and this file is the boundary between
// that question and the org's choice of brain: a local Ollama model on an
// air-gapped network, an Azure deployment inside their tenant, a plain cloud API
// key, or the built-in offline heuristics. The gateway itself (internal/ai)
// always produces an answer; the work here is assembling the event faithfully,
// never leaking a secret into the prompt, and persisting settings with an audit
// trail.
package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/statetrack/statetrack/server/internal/ai"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// aiAnalysisTimeout bounds one analysis request end to end. It sits above the
// settings' own per-call timeout so the gateway's fallback (which is itself
// bounded) still has room to run and produce an answer before the HTTP request
// is cut off; a request that 504s would deny the operator the deterministic
// analysis the product promises.
const aiAnalysisTimeout = 45 * time.Second

// aiSettingsResponse is the GET /api/v1/integrations/ai payload.
type aiSettingsResponse struct {
	ai.Settings
	// Providers is the closed set the console renders, in display order, so the
	// selector cannot drift from what the server accepts.
	Providers []string `json:"providers"`
	// APIKeySet reports whether a credential is stored, so the form can render
	// "configured" without the browser ever receiving the secret.
	APIKeySet bool `json:"api_key_set"`
	// NeedsNetwork tells the console whether the selected provider transmits the
	// event off-host, which the UI warns about before an operator enables it.
	NeedsNetwork bool `json:"needs_network"`
	// EffectiveEndpoint and EffectiveModel are the values actually used after
	// applying the provider defaults, so the card can show the operator what
	// will run rather than what they left blank.
	EffectiveEndpoint string `json:"effective_endpoint"`
	EffectiveModel    string `json:"effective_model"`
}

// aiTestResponse is the POST /api/v1/integrations/ai/test payload.
type aiTestResponse struct {
	OK         bool   `json:"ok"`
	Provider   string `json:"provider"`
	Endpoint   string `json:"endpoint,omitempty"`
	Model      string `json:"model,omitempty"`
	Detail     string `json:"detail"`
	LatencyMS  int64  `json:"latency_ms"`
	BlastCheck string `json:"blast_check,omitempty"`
	CheckedAt  string `json:"checked_at"`
}

// aiGet returns the current AI gateway configuration.
//
//	GET /api/v1/integrations/ai
//
// The stored API key is never returned: the response carries `api_key_set`
// instead. An operator editing the card leaves the field untouched to keep the
// secret, which is both safer (no credential in the browser's memory or in a
// screenshot) and less error-prone than a masked value the console would have
// to remember not to save back.
func (s *Server) aiGet(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Store.GetAISettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.aiSettingsView(settings))
}

// aiPut updates the AI gateway configuration at runtime.
//
//	PUT /api/v1/integrations/ai
//
// The body is a partial update: omitted fields keep their current value, so the
// console can toggle live calls without round-tripping the credential. An
// explicitly empty `api_key` clears it (that is what "remove the key" means); an
// absent one keeps it.
func (s *Server) aiPut(w http.ResponseWriter, r *http.Request) {
	current, err := s.Store.GetAISettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}

	var body struct {
		Provider       *string  `json:"provider"`
		Endpoint       *string  `json:"endpoint"`
		Model          *string  `json:"model"`
		APIKey         *string  `json:"api_key"`
		APIVersion     *string  `json:"api_version"`
		Enabled        *bool    `json:"enabled"`
		Temperature    *float64 `json:"temperature"`
		MaxTokens      *int     `json:"max_tokens"`
		TimeoutSeconds *int     `json:"timeout_seconds"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	next := current
	if body.Provider != nil {
		provider := strings.ToLower(strings.TrimSpace(*body.Provider))
		if !ai.IsValidProvider(provider) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "provider must be one of deterministic, ollama, azure_openai, openai or anthropic",
			})
			return
		}
		next.Provider = ai.Provider(provider)
	}
	if body.Endpoint != nil {
		target := strings.TrimSpace(*body.Endpoint)
		// Validate now rather than at analysis time: a bad URL saved here would
		// silently break every future analysis, and the operator would only learn
		// about it during an incident.
		if target != "" {
			if parsed, perr := url.Parse(target); perr != nil || parsed.Scheme == "" || parsed.Host == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "endpoint must be an absolute URL, e.g. https://my-resource.openai.azure.com",
				})
				return
			}
		}
		next.Endpoint = target
	}
	if body.Model != nil {
		next.Model = strings.TrimSpace(*body.Model)
	}
	if body.APIKey != nil {
		next.APIKey = *body.APIKey
	}
	if body.APIVersion != nil {
		next.APIVersion = strings.TrimSpace(*body.APIVersion)
	}
	if body.Enabled != nil {
		next.Enabled = *body.Enabled
	}
	if body.Temperature != nil {
		next.Temperature = *body.Temperature
	}
	if body.MaxTokens != nil {
		next.MaxTokens = *body.MaxTokens
	}
	if body.TimeoutSeconds != nil {
		next.TimeoutSeconds = *body.TimeoutSeconds
	}

	// A provider that requires an endpoint must have one. Azure's resource URL
	// is mandatory, and while Ollama and OpenAI have defaults, validating here
	// turns a misconfiguration into a 400 at save time rather than a silent
	// fallback during an incident.
	if ai.NeedsNetwork(next.Provider) && ai.DefaultEndpoint(next.Provider) == "" && next.Endpoint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this provider requires an endpoint URL",
		})
		return
	}

	// Changing the endpoint, credential or provider invalidates the previous
	// test result: showing "Connected" for a configuration that has never been
	// probed is exactly the kind of stale green light that erodes trust.
	if next.Provider != current.Provider || next.Endpoint != current.Endpoint ||
		next.Model != current.Model || next.APIKey != current.APIKey {
		next.LastTestOK = false
		next.LastTestError = ""
		next.LastTestAt = nil
	}

	saved, err := s.Store.SaveAISettings(r.Context(), s.OrgID, next)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.aiSettingsView(saved))
}

// aiTest performs a live connectivity probe against the configured provider and
// records the outcome.
//
//	POST /api/v1/integrations/ai/test
//
// The probe runs the real provider path against a synthetic change, so a passing
// test proves the configuration works end to end rather than only that DNS
// resolves. It deliberately does *not* save the settings it probed: an operator
// testing a candidate endpoint before committing it must be able to walk away
// having changed nothing.
func (s *Server) aiTest(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Store.GetAISettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), aiAnalysisTimeout)
	defer cancel()

	res := s.aiGateway().Test(ctx, settings)
	if err := s.Store.RecordAITest(r.Context(), s.OrgID, res.OK, res.Detail); err != nil {
		s.logger().Warn("record ai test", "err", err)
	}

	status := http.StatusOK
	if !res.OK {
		// 502: the console succeeded, the upstream model did not. That
		// distinction matters for an operator reading a proxy log.
		status = http.StatusBadGateway
	}
	writeJSON(w, status, aiTestResponse{
		OK:         res.OK,
		Provider:   res.Provider,
		Endpoint:   res.Endpoint,
		Model:      res.Model,
		Detail:     res.Detail,
		LatencyMS:  res.LatencyMS,
		BlastCheck: res.BlastCheck,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	})
}

// analyzeEvent runs the configured AI provider (or the deterministic fallback)
// against one event.
//
//	POST /api/v1/events/{id}/analyze
//
// This is the endpoint behind the Inspector drawer's "✦ Analyze & Rollback"
// action. The event is assembled from the stored, already-scrubbed diff — the
// zero-secret guarantee is enforced here by construction: the only diff this
// handler can hand the gateway is the one the agent redacted at the edge, and
// there is no code path in this file that could fetch a raw one.
func (s *Server) analyzeEvent(w http.ResponseWriter, r *http.Request) {
	eventID := strings.TrimSpace(r.PathValue("id"))
	if eventID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event id is required"})
		return
	}

	detail, err := s.Store.GetEvent(r.Context(), s.OrgID, eventID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found", "id": eventID})
			return
		}
		writeErr(w, err)
		return
	}

	settings, err := s.Store.GetAISettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), aiAnalysisTimeout)
	defer cancel()

	analysis := s.aiGateway().Analyze(ctx, settings, s.eventForAnalysisFrom(ctx, s.OrgID, detail))
	writeJSON(w, http.StatusOK, analysis)
}

// requesterName is the actor recorded as the report's author. The MCP transport
// passes it explicitly so the stdio binary's HTTP client can be credited rather
// than only console sessions.
func requesterName(r *http.Request) string {
	if p := PrincipalFrom(r.Context()); p != nil {
		return p.ActorEmail()
	}
	return ""
}

// eventForAnalysis flattens a stored event into the gateway's input.
//
// Every field is taken from the stored row and none is invented: the prompt is
// only as good as this mapping, so it is the one place a "forgot to pass the
// cmdline" bug would hide. The OS family needs a second read because it lives on
// the host row, and a failure to resolve it degrades the remediation to the
// generic branch rather than failing the request — an analysis with a slightly
// less specific rollback command is still useful during an incident.
func (s *Server) eventForAnalysisFrom(ctx context.Context, orgID string, d storage.EventDetail) ai.Event {
	osFamily := ""
	if h, err := s.Store.GetHost(ctx, orgID, d.HostID); err == nil {
		osFamily = h.OSFamily
	}

	return ai.Event{
		ID:           d.ID,
		Host:         d.Hostname,
		OSFamily:     osFamily,
		OccurredAt:   d.OccurredAt,
		Level:        d.ImpactLevel,
		LevelLabel:   levelLabel(d.ImpactLevel),
		Category:     categoryName(d.Category),
		Action:       actionVerb(d.Action),
		Summary:      d.Summary,
		TargetType:   d.TargetType,
		PathOrKey:    d.PathOrKey,
		Actor:        d.ActorUsername,
		Process:      d.ProcessName,
		Cmdline:      d.Cmdline,
		RemoteIP:     d.RemoteIP,
		RuleName:     d.Metadata["rule_name"],
		Diff:         d.Diff,
		DiffRedacted: strings.Contains(d.Diff, "[REDACTED:"),
		Metadata:     d.Metadata,
	}
}

// aiSettingsView renders the stored settings for the console, replacing the
// credential with a presence flag and filling in the effective endpoint/model.
func (s *Server) aiSettingsView(settings ai.Settings) aiSettingsResponse {
	view := aiSettingsResponse{
		Settings:          settings,
		Providers:         providerStrings(),
		APIKeySet:         strings.TrimSpace(settings.APIKey) != "",
		NeedsNetwork:      ai.NeedsNetwork(settings.Provider),
		EffectiveEndpoint: effectiveEndpoint(settings),
		EffectiveModel:    effectiveModelName(settings),
	}
	// Never send the secret. Clearing it here rather than in a JSON tag means
	// the field cannot be re-introduced by a future embedding change.
	view.APIKey = ""
	return view
}

// effectiveEndpoint resolves the configured endpoint against the provider
// default, mirroring what the gateway will actually call.
func effectiveEndpoint(s ai.Settings) string {
	if e := strings.TrimSpace(s.Endpoint); e != "" {
		return e
	}
	return ai.DefaultEndpoint(s.Provider)
}

// effectiveModelName resolves the configured model against the provider
// default, mirroring what the gateway will actually request.
func effectiveModelName(s ai.Settings) string {
	if m := strings.TrimSpace(s.Model); m != "" {
		return m
	}
	return ai.DefaultModel(s.Provider)
}

// aiGateway returns the process-wide gateway. One instance is enough because it
// is stateless apart from its HTTP client (whose connection pool is what makes
// repeated analyses cheap), and it is never mutated after construction.
func (s *Server) aiGateway() *ai.Gateway {
	if s.ai == nil {
		opts := []ai.GatewayOption{}
		if s.HTTPClient != nil {
			opts = append(opts, ai.WithHTTPClient(s.HTTPClient))
		}
		s.ai = ai.New(opts...)
	}
	return s.ai
}

func providerStrings() []string {
	out := make([]string, 0, len(ai.Providers))
	for _, p := range ai.Providers {
		out = append(out, string(p))
	}
	return out
}
