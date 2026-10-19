// Package ai is StateTrack's provider-agnostic analysis gateway.
//
// # Why a gateway rather than a client
//
// The analyzer answers three operational questions about a change: how bad is
// it, what breaks if it is wrong, and what is the exact command to undo it.
// Every enterprise wants to answer those with a different brain — a local
// Ollama model on an air-gapped network, an Azure OpenAI deployment inside their
// tenant, or a plain cloud API key — and a change-management workflow cannot
// depend on any of them being reachable. So the gateway has one non-negotiable
// property: **it always returns an answer**. A configured model that is down,
// mis-authenticated or slow degrades to the built-in deterministic heuristics,
// which derive the same three answers from the event itself and work with no
// network at all.
//
// # Zero-secret guarantee
//
// The diff the gateway receives is the already-scrubbed unified diff the agent
// produced: secret-looking values were replaced with `[REDACTED:sha256:…]`
// stubs *at the edge*, before the change ever left the host. This package never
// sees, reconstructs or transmits a raw credential, and it never reads a file
// or a database — it is a pure function of the Event it is handed. That is the
// property an enterprise security review asks about, and it is enforced by the
// type system here: there is no field for a secret and no code path that could
// fetch one.
//
// # Determinism
//
// The deterministic engine is derived from internal/postmortem's remediation
// logic rather than reimplemented, so the risk sentence and rollback command a
// model-less deployment shows in the Inspector drawer are byte-identical to the
// ones in the exported post-mortem for the same change. Two implementations
// would drift, and then the console and the compliance record would disagree
// about the same incident.
package ai

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Provider identifies which engine answered. These strings persist in the
// settings row, so they are stable identifiers rather than display names.
type Provider string

const (
	// ProviderDeterministic is the offline fallback. It is a first-class
	// provider, not an error state: an air-gapped site can select it explicitly
	// and get a complete, useful analysis with no model at all.
	ProviderDeterministic Provider = "deterministic"
	// ProviderOllama is an OpenAI-compatible local endpoint.
	ProviderOllama Provider = "ollama"
	// ProviderAzureOpenAI is an Azure-hosted OpenAI deployment.
	ProviderAzureOpenAI Provider = "azure_openai"
	// ProviderOpenAI is the public OpenAI API.
	ProviderOpenAI Provider = "openai"
	// ProviderAnthropic is the Anthropic Messages API.
	ProviderAnthropic Provider = "anthropic"
)

// Providers is the closed set the console renders, in display order. The
// deterministic engine is listed first because it is the default and the one
// that always works.
var Providers = []Provider{
	ProviderDeterministic,
	ProviderOllama,
	ProviderAzureOpenAI,
	ProviderOpenAI,
	ProviderAnthropic,
}

// IsValidProvider reports whether a string is a known provider, so an API caller
// cannot persist a typo that would later disable analysis.
func IsValidProvider(p string) bool {
	for _, known := range Providers {
		if string(known) == p {
			return true
		}
	}
	return false
}

// ProviderLabel is the human-readable engine name the console badges. A reader
// must be able to tell at a glance whether a model or the offline heuristics
// answered, because that changes how much to trust a subtle judgement call.
func ProviderLabel(p string) string {
	switch Provider(strings.ToLower(strings.TrimSpace(p))) {
	case ProviderOllama:
		return "Local Ollama"
	case ProviderAzureOpenAI:
		return "Azure OpenAI"
	case ProviderOpenAI:
		return "OpenAI"
	case ProviderAnthropic:
		return "Anthropic"
	default:
		return "Built-in Offline Heuristics"
	}
}

// NeedsNetwork reports whether a provider transmits the event to a remote
// service, so the console can warn before an operator selects it.
func NeedsNetwork(p Provider) bool {
	switch p {
	case ProviderOllama:
		// Local by default, but an operator can point it at a shared host, so
		// the console treats it as an on-prem endpoint rather than "offline".
		return true
	case ProviderAzureOpenAI, ProviderOpenAI, ProviderAnthropic:
		return true
	default:
		return false
	}
}

// Settings is the org's analysis configuration. It is persisted as JSONB, so
// adding a knob does not require a migration, and this type is the contract the
// API, the storage layer and the gateway all share.
type Settings struct {
	Provider Provider `json:"provider"`
	// Endpoint is the base URL of the model service. Empty means "use the
	// provider's default", which is what makes the Ollama card work out of the
	// box at http://localhost:11434/v1.
	Endpoint string `json:"endpoint"`
	// Model is the OpenAI model id or the Azure deployment name.
	Model string `json:"model"`
	// APIKey is the bearer credential. Never returned in full by the API.
	APIKey string `json:"api_key,omitempty"`
	// APIVersion is Azure's required `api-version` query parameter.
	APIVersion string `json:"api_version,omitempty"`
	// Enabled gates live calls. A disabled gateway falls back to the
	// deterministic engine without attempting the network, which is how an
	// operator turns a misbehaving model off without deleting the config.
	Enabled bool `json:"enabled"`
	// Temperature is passed through to the model. Low by default: the task is
	// structured extraction, not creative writing.
	Temperature float64 `json:"temperature"`
	// MaxTokens bounds the model's reply so a runaway generation cannot hold a
	// request open.
	MaxTokens int `json:"max_tokens"`
	// TimeoutSeconds bounds one analysis call.
	TimeoutSeconds int `json:"timeout_seconds"`

	// LastTest* record the most recent connectivity test so the console can show
	// a result that survives a reload instead of forgetting it.
	LastTestAt    *time.Time `json:"last_test_at,omitempty"`
	LastTestOK    bool       `json:"last_test_ok"`
	LastTestError string     `json:"last_test_error,omitempty"`

	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// DefaultSettings returns the configuration used before an operator saves one.
//
// It is the deterministic engine, enabled: a fresh deployment produces a
// complete analysis on the first click with no model, no key and no network,
// which is the only honest default for a product that must work air-gapped.
func DefaultSettings() Settings {
	return Settings{
		Provider:       ProviderDeterministic,
		Endpoint:       "",
		Model:          "",
		Enabled:        true,
		Temperature:    0.1,
		MaxTokens:      700,
		TimeoutSeconds: 20,
	}
}

// DefaultEndpoint is the base URL a provider uses when the operator leaves the
// endpoint blank. Ollama's is the documented local default, which is what makes
// the air-gapped case a single click.
func DefaultEndpoint(p Provider) string {
	switch p {
	case ProviderOllama:
		return "http://localhost:11434/v1"
	case ProviderOpenAI:
		return "https://api.openai.com/v1"
	case ProviderAnthropic:
		return "https://api.anthropic.com"
	default:
		return ""
	}
}

// DefaultModel is the model a provider uses when none is configured.
func DefaultModel(p Provider) string {
	switch p {
	case ProviderOllama:
		return "llama3.1"
	case ProviderOpenAI:
		return "gpt-4o-mini"
	case ProviderAnthropic:
		return "claude-3-5-sonnet-latest"
	default:
		return ""
	}
}

// Event is the analysis input: a single change, flattened to what the analyzer
// needs and nothing more.
//
// Diff must arrive already scrubbed. There is deliberately no raw-content field
// and no way to fetch one: the guarantee is structural, not a promise.
type Event struct {
	ID         string
	Host       string
	OSFamily   string
	OccurredAt time.Time
	// Level is the numeric impact level (1 is most severe).
	Level int32
	// LevelLabel is the rendered severity ("Level 1 · Critical"), folded into
	// the risk sentence so the deterministic engine can reuse the report's
	// wording.
	LevelLabel string
	Category   string
	Action     string
	Summary    string
	TargetType string
	PathOrKey  string
	Actor      string
	Process    string
	Cmdline    string
	RemoteIP   string
	RuleName   string

	// Diff is the scrubbed unified diff, or empty when the change stored hashes
	// only. It is included in the model prompt verbatim.
	Diff string
	// DiffRedacted reports that the diff contains redaction stubs, so the
	// analysis can state that it reasoned over scrubbed content.
	DiffRedacted bool

	// Metadata is the agent's classification map, given to the model as context
	// (rule name, attribution source, mutation counts). Sorted on render so the
	// prompt is deterministic.
	Metadata map[string]string
}

// Blast radius vocabulary. It is a closed set because the console colours it and
// an alert may route on it.
const (
	BlastRadiusLow    = "Low"
	BlastRadiusMedium = "Medium"
	BlastRadiusHigh   = "High"
)

// Analysis is the gateway's answer. Every field is always populated: the
// deterministic engine guarantees an answer even when a model is unreachable, so
// a caller never has to handle a partial result.
type Analysis struct {
	// Provider is the engine that produced this answer. It is the *effective*
	// provider, which may differ from the configured one when a fallback fired.
	Provider      string `json:"provider"`
	ProviderLabel string `json:"provider_label"`
	// Model is the model id that answered, for the audit trail.
	Model string `json:"model,omitempty"`

	RiskSummary string `json:"risk_summary"`
	// BlastRadius is Low, Medium or High.
	BlastRadius      string   `json:"blast_radius"`
	AffectedServices []string `json:"affected_services,omitempty"`
	// RollbackCommand is the exact command to revert the change. Empty when no
	// safe generic command exists, in which case RollbackNotes explains why.
	RollbackCommand string `json:"rollback_command,omitempty"`
	// VerificationCommand proves the service is healthy after a rollback.
	VerificationCommand string `json:"verification_command,omitempty"`
	// RollbackNotes carries the caveat that belongs next to the command.
	RollbackNotes string `json:"rollback_notes,omitempty"`

	// Fallback reports that the deterministic engine answered because the
	// configured provider failed. The console surfaces this so an operator never
	// mistakes a heuristic for a model's judgement.
	Fallback bool `json:"fallback"`
	// FallbackReason explains why, in one clause, for the operator debugging
	// their endpoint.
	FallbackReason string `json:"fallback_reason,omitempty"`
	// Scrubbed reports that the analysis reasoned over content with redaction
	// stubs in it.
	Scrubbed bool `json:"scrubbed"`

	GeneratedAt time.Time `json:"generated_at"`
	// LatencyMS is the wall-clock time the call took, which is what makes a slow
	// model diagnosable from the console.
	LatencyMS int64 `json:"latency_ms"`
}

// Gateway runs the analysis. It is safe for concurrent use.
type Gateway struct {
	client *http.Client
	now    func() time.Time
}

// GatewayOption customises a Gateway. Used by tests to inject a client pointed
// at an httptest server.
type GatewayOption func(*Gateway)

// WithHTTPClient substitutes the HTTP client. A nil client is ignored.
func WithHTTPClient(c *http.Client) GatewayOption {
	return func(g *Gateway) {
		if c != nil {
			g.client = c
		}
	}
}

// WithClock substitutes the clock, so a test can assert a stable timestamp.
func WithClock(now func() time.Time) GatewayOption {
	return func(g *Gateway) {
		if now != nil {
			g.now = now
		}
	}
}

// New builds a Gateway.
func New(opts ...GatewayOption) *Gateway {
	g := &Gateway{
		// A generous overall timeout: the per-request deadline is set from the
		// settings, and this is the backstop for a client that ignores it.
		client: &http.Client{Timeout: 60 * time.Second},
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Analyze runs the configured provider against the event, degrading to the
// deterministic engine when the provider is unavailable. It never returns an
// error: an analysis is always produced, and `Fallback`/`FallbackReason` record
// that a model was not the source.
func (g *Gateway) Analyze(ctx context.Context, settings Settings, ev Event) Analysis {
	settings = NormalizeSettings(settings)
	started := g.now()

	provider := settings.Provider
	if provider == ProviderDeterministic || !settings.Enabled || !NeedsNetwork(provider) {
		out := g.deterministic(ev)
		out.GeneratedAt = started.UTC()
		out.LatencyMS = 0
		if provider != ProviderDeterministic && !settings.Enabled {
			// Settings plainly say "disabled": that is a configuration choice,
			// not a failure, so it is not reported as a fallback.
			out.Fallback = false
		}
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(settings.TimeoutSeconds)*time.Second)
	defer cancel()

	reply, err := g.callProvider(ctx, settings, ev)
	latency := g.now().Sub(started).Milliseconds()
	if err != nil {
		out := g.deterministic(ev)
		out.Provider = string(ProviderDeterministic)
		out.ProviderLabel = ProviderLabel(string(ProviderDeterministic))
		out.Model = ""
		out.Fallback = true
		out.FallbackReason = err.Error()
		out.GeneratedAt = started.UTC()
		out.LatencyMS = latency
		return out
	}

	// A model answers in prose even when asked for JSON. The parse is lenient
	// where it can be (fences, surrounding text) and strict about the fields:
	// a reply that does not yield a risk summary is treated as a failure and
	// degrades, rather than rendering an empty drawer.
	parsed, err := parseModelReply(reply)
	if err != nil {
		out := g.deterministic(ev)
		out.Provider = string(ProviderDeterministic)
		out.ProviderLabel = ProviderLabel(string(ProviderDeterministic))
		out.Model = ""
		out.Fallback = true
		out.FallbackReason = err.Error()
		out.GeneratedAt = started.UTC()
		out.LatencyMS = latency
		return out
	}

	// The rollback and verification commands must be runnable. A model that
	// returns a risk assessment but no command has not answered the question the
	// operator clicked for, so the deterministic engine fills the gaps — a
	// hybrid that is strictly more useful than discarding the model's prose.
	deterministic := g.deterministic(ev)
	out := Analysis{
		Provider:            string(provider),
		ProviderLabel:       ProviderLabel(string(provider)),
		Model:               effectiveModel(settings),
		RiskSummary:         parsed.RiskSummary,
		BlastRadius:         normalizeBlastRadius(parsed.BlastRadius),
		AffectedServices:    parsed.AffectedServices,
		RollbackCommand:     strings.TrimSpace(parsed.RollbackCommand),
		VerificationCommand: strings.TrimSpace(parsed.VerificationCommand),
		RollbackNotes:       strings.TrimSpace(parsed.RollbackNotes),
		Scrubbed:            ev.DiffRedacted || HasRedactions(ev.Diff),
		GeneratedAt:         started.UTC(),
		LatencyMS:           latency,
	}
	if out.RollbackCommand == "" {
		out.RollbackCommand = deterministic.RollbackCommand
		out.RollbackNotes = deterministic.RollbackNotes
	}
	if out.VerificationCommand == "" {
		out.VerificationCommand = deterministic.VerificationCommand
	}
	if len(out.AffectedServices) == 0 {
		out.AffectedServices = deterministic.AffectedServices
	}
	return out
}

// effectiveModel is the model actually used, applying the provider default.
func effectiveModel(s Settings) string {
	if m := strings.TrimSpace(s.Model); m != "" {
		return m
	}
	return DefaultModel(s.Provider)
}

// normalizeBlastRadius folds an arbitrary model answer onto the closed set. An
// unrecognized value becomes Medium: guessing "Low" could understate a risky
// change, and guessing "High" on everything would make the field useless.
func normalizeBlastRadius(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "low":
		return BlastRadiusLow
	case "high", "critical", "severe":
		return BlastRadiusHigh
	case "medium", "moderate", "med":
		return BlastRadiusMedium
	default:
		return BlastRadiusMedium
	}
}

// HasRedactions reports whether a diff contains the agent scrubber's stubs. The
// placeholder shape is the contract between the agent's edge scrubber and every
// consumer, so it is defined once here.
func HasRedactions(diff string) bool {
	return strings.Contains(diff, "[REDACTED:")
}
