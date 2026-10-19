// Security administration endpoints: scoped API keys, agent enrollment tokens,
// and the control-plane audit trail.
//
// These handlers mint credentials, so they follow one rule throughout: a secret
// is returned exactly once, in the response that created it, and never again.
// The database holds only a hash, which means "show me my key again" is
// deliberately not implementable — the console offers rotate instead.
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/statetrack/statetrack/server/internal/security"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// knownScopes is the closed scope vocabulary the console offers. Kept server-side
// so a typo'd scope cannot be minted (a key with an unusable scope looks valid in
// the UI but fails every call it was created for).
var knownScopes = []string{"read:summary", "read:annotations", "read:mcp", "admin:write"}

func isKnownScope(s string) bool {
	for _, known := range knownScopes {
		if known == s {
			return true
		}
	}
	return false
}

/* -------------------------------------------------------------------------- */
/* API keys                                                                   */
/* -------------------------------------------------------------------------- */

// apiKeyView is the console-facing key row. It never carries the secret.
type apiKeyView struct {
	storage.APIKey
	// Active is computed server-side from revoked_at/expires_at so the console's
	// "active / expired / revoked" badge cannot disagree with what
	// authentication actually enforces.
	Active     bool         `json:"active"`
	LastUsedAt *time.Time   `json:"last_used_at,omitempty"`
	ExpiresIn  *durationStr `json:"expires_in,omitempty"`
}

// durationStr renders a remaining lifetime as a human string ("in 180 days"), so
// the console shows the same phrasing everywhere rather than formatting a
// timestamp three different ways.
type durationStr string

func apiKeyViewFor(k storage.APIKey, now time.Time) apiKeyView {
	v := apiKeyView{APIKey: k, Active: k.Active(now), LastUsedAt: k.LastUsedAt}
	if k.ExpiresAt != nil {
		remaining := k.ExpiresAt.Sub(now)
		d := humanDuration(remaining)
		v.ExpiresIn = &d
	}
	return v
}

// humanDuration renders a duration in the largest sensible unit for a credential
// lifetime, which is the range where "in 12 days" is more useful than "in 288h".
func humanDuration(d time.Duration) durationStr {
	switch {
	case d <= 0:
		return "expired"
	case d < time.Hour:
		return durationStr(inUnit(int(d.Minutes()), "minute"))
	case d < 48*time.Hour:
		return durationStr(inUnit(int(d.Hours()), "hour"))
	default:
		return durationStr(inUnit(int(d.Hours()/24), "day"))
	}
}

// inUnit renders "in 1 day" / "in 12 days", pluralising only when it reads
// correctly.
func inUnit(n int, unit string) string {
	if n == 1 {
		return "in 1 " + unit
	}
	return "in " + strconv.Itoa(n) + " " + unit + "s"
}

// listAPIKeys returns every key in the org, active first.
//
//	GET /api/v1/security/api-keys
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(r); !ok {
		writeUnauthorized(w)
		return
	}
	keys, err := s.Store.ListAPIKeys(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	now := time.Now()
	views := make([]apiKeyView, 0, len(keys))
	for _, k := range keys {
		views = append(views, apiKeyViewFor(k, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_keys": views,
		"scopes":   knownScopes,
	})
}

// createAPIKeyRequest is the mint form.
type createAPIKeyRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// Scopes default to read-only when omitted, because the failure mode of a
	// too-broad key is worse than that of a too-narrow one an operator widens.
	Scopes []string `json:"scopes"`
	// ExpiresInDays of 0 means "never expires", which the console warns about.
	ExpiresInDays int `json:"expires_in_days"`
}

// createAPIKey mints a key and returns the secret once.
//
//	POST /api/v1/security/api-keys
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var body createAPIKeyRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = string(storage.RoleOperator)
	}
	if !storage.IsValidRole(role) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "role must be one of admin, operator, policy_admin or auditor",
		})
		return
	}
	scopes := normalizeScopes(body.Scopes)
	for _, sc := range scopes {
		if !isKnownScope(sc) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "unknown scope " + sc + "; allowed scopes are " + strings.Join(knownScopes, ", "),
			})
			return
		}
	}
	if len(scopes) == 0 {
		scopes = []string{"read:summary"}
	}
	if body.ExpiresInDays < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_in_days cannot be negative"})
		return
	}

	token, prefix, err := security.GenerateToken(security.APIKeyPrefix)
	if err != nil {
		writeErr(w, err)
		return
	}

	var expiresAt *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().Add(time.Duration(body.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}

	key, err := s.Store.CreateAPIKey(r.Context(), s.OrgID, storage.APIKey{
		Name: name, KeyPrefix: prefix, Role: storage.Role(role),
		Scopes: scopes, ExpiresAt: expiresAt,
	}, security.HashToken(token))
	if err != nil {
		writeErr(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		// The only time the secret is ever returned.
		"token":      token,
		"key_prefix": prefix,
		"api_key":    apiKeyViewFor(key, time.Now()),
		"warning":    "store this token now — it cannot be retrieved later",
	})
}

// normalizeScopes trims, drops empty entries and de-duplicates. A repeated scope
// is harmless but makes the stored array misleading, and an empty string from a
// form's trailing comma would fail the known-scope check with a confusing error.
func normalizeScopes(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, sc := range in {
		sc = strings.TrimSpace(sc)
		if sc == "" || seen[sc] {
			continue
		}
		seen[sc] = true
		out = append(out, sc)
	}
	return out
}

// revokeAPIKey revokes a key.
//
//	DELETE /api/v1/security/api-keys/{id}
//
// Self-revocation is allowed: an operator rotating the key their own automation
// uses needs to be able to. The audit row records the actor, so the action is
// visible even when it removes the credential that made it.
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	key, err := s.Store.RevokeAPIKey(r.Context(), s.OrgID, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "revoked", "id": key.ID, "name": key.Name,
	})
}

/* -------------------------------------------------------------------------- */
/* Enrollment tokens                                                          */
/* -------------------------------------------------------------------------- */

// enrollmentView is the console-facing token row, including the ready-to-paste
// bootstrap commands so the console never has to build a shell command itself
// (where a quoting bug would ship a broken, or worse, an injectable one-liner).
type enrollmentView struct {
	storage.EnrollmentToken
	Active       bool   `json:"active"`
	BootstrapURL string `json:"bootstrap_url"`
	// LinuxCommand and WindowsCommand embed the token, so they are only returned
	// in full by the create response. In a list they are returned with the token
	// redacted, because a list is loaded on every visit to the tab.
	LinuxCommand   string `json:"linux_command"`
	WindowsCommand string `json:"windows_command"`
}

// bootstrapBaseURL resolves the server address an agent should call home to.
// The configured UI base URL is the operator-declared public address, which is
// the right value to bake into an install command; the request host is only a
// fallback so the command is still usable when nothing has been configured.
func (s *Server) bootstrapBaseURL(r *http.Request) string {
	if s.UIBaseURL != "" {
		return strings.TrimRight(s.UIBaseURL, "/")
	}
	scheme := "http"
	if requestIsTLS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// enrollmentCommands builds the one-line Linux and Windows bootstrap commands.
//
// Both are single-line and copy-pasteable, and both quote the token: a token is
// alphanumeric today, but a command that would break (or execute something else)
// if that ever changed is a landmine, not a shortcut.
func enrollmentCommands(baseURL, token string) (linux, windows string, bootstrapURL string) {
	bootstrapURL = baseURL + "/api/v1/agent/enroll"
	linux = "curl -fsSL " + shellSingleQuote(bootstrapURL) +
		" | sudo STATETRACK_ENROLL_TOKEN=" + shellSingleQuote(token) + " bash"
	windows = "iwr -UseBasicParsing " + shellSingleQuote(bootstrapURL) +
		" | iex; $env:STATETRACK_ENROLL_TOKEN=" + shellSingleQuote(token)
	return linux, windows, bootstrapURL
}

// shellSingleQuote wraps a value in single quotes, escaping any embedded quote.
// The single-quoted form is the only one in POSIX sh where no character is
// special, which is what makes the generated command safe by construction.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// redactToken replaces the token in a prepared command with a placeholder, for
// list responses where the real secret is not available.
func redactToken(cmd string) string {
	if i := strings.Index(cmd, "st_enroll_"); i >= 0 {
		end := i
		for end < len(cmd) && isTokenChar(cmd[end]) {
			end++
		}
		return cmd[:i] + "st_enroll_••••••••" + cmd[end:]
	}
	return cmd
}

func isTokenChar(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// listEnrollmentTokens returns every bootstrap token with redacted commands.
//
//	GET /api/v1/security/enrollment-tokens
func (s *Server) listEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(r); !ok {
		writeUnauthorized(w)
		return
	}
	tokens, err := s.Store.ListEnrollmentTokens(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	baseURL := s.bootstrapBaseURL(r)
	now := time.Now()

	views := make([]enrollmentView, 0, len(tokens))
	for _, t := range tokens {
		// The real token is unrecoverable, so the commands are rendered against a
		// placeholder prefix and the literal is redacted out.
		linux, windows, burl := enrollmentCommands(baseURL, t.TokenPrefix+"…")
		views = append(views, enrollmentView{
			EnrollmentToken: t,
			Active:          t.Active(now),
			BootstrapURL:    burl,
			LinuxCommand:    redactToken(linux),
			WindowsCommand:  redactToken(windows),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollment_tokens": views})
}

// createEnrollmentTokenRequest is the mint form.
type createEnrollmentTokenRequest struct {
	Name string `json:"name"`
	// MaxUses of 0 means unlimited, which the console warns about.
	MaxUses       int `json:"max_uses"`
	ExpiresInDays int `json:"expires_in_days"`
}

// createEnrollmentToken mints a bootstrap token and returns it once, together
// with ready-to-paste install commands.
//
//	POST /api/v1/security/enrollment-tokens
func (s *Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var body createEnrollmentTokenRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if body.MaxUses < 0 || body.ExpiresInDays < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "max_uses and expires_in_days cannot be negative",
		})
		return
	}

	token, prefix, err := security.GenerateToken(security.EnrollmentPrefix)
	if err != nil {
		writeErr(w, err)
		return
	}

	var maxUses *int
	// Zero means unlimited, and an unbounded enrollment token is a fleet-takeover
	// primitive, so the default is a finite cap rather than none.
	if body.MaxUses > 0 {
		maxUses = &body.MaxUses
	} else {
		d := 25
		maxUses = &d
	}
	// Likewise a token with no expiry is a permanent skeleton key; default to 30
	// days when the form omits one.
	days := body.ExpiresInDays
	if days <= 0 {
		days = 30
	}
	expiresAt := time.Now().Add(time.Duration(days) * 24 * time.Hour)

	created, err := s.Store.CreateEnrollmentToken(r.Context(), s.OrgID, storage.EnrollmentToken{
		Name: name, TokenPrefix: prefix, MaxUses: maxUses, ExpiresAt: &expiresAt,
	}, security.HashToken(token))
	if err != nil {
		writeErr(w, err)
		return
	}

	baseURL := s.bootstrapBaseURL(r)
	linux, windows, burl := enrollmentCommands(baseURL, token)

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":        token,
		"token_prefix": prefix,
		"enrollment_token": enrollmentView{
			EnrollmentToken: created, Active: true, BootstrapURL: burl,
			LinuxCommand: linux, WindowsCommand: windows,
		},
		"warning": "store this token now — the installer needs it and it cannot be retrieved later",
	})
}

// revokeEnrollmentToken revokes a bootstrap token.
//
//	DELETE /api/v1/security/enrollment-tokens/{id}
func (s *Server) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tok, err := s.Store.RevokeEnrollmentToken(r.Context(), s.OrgID, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "revoked", "id": tok.ID, "name": tok.Name,
	})
}

/* -------------------------------------------------------------------------- */
/* Audit log                                                                  */
/* -------------------------------------------------------------------------- */

// listAuditLogs returns the control-plane audit trail, newest first.
//
//	GET /api/v1/security/audit-logs?action=rule.applied&actor=pk@statetrack.io&limit=200
func (s *Server) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(r); !ok {
		writeUnauthorized(w)
		return
	}
	q := r.URL.Query()
	action := strings.TrimSpace(q.Get("action"))
	actor := strings.TrimSpace(q.Get("actor"))
	limit := clamp(atoi(q.Get("limit")), 200)

	logs, err := s.Store.ListAuditLogs(r.Context(), action, actor, limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"audit_logs": logs,
		"count":      len(logs),
		// The console's filter dropdowns are populated from the server's own
		// vocabulary so a new action type shows up without a frontend release.
		"actions": auditActions,
	})
}

// auditActions is the closed set of actions the console offers as filters.
var auditActions = []string{
	storage.ActionLogin,
	storage.ActionLogout,
	storage.ActionRoleSwitched,
	storage.Action2FAEnabled,
	storage.Action2FADisabled,
	storage.ActionRuleApplied,
	storage.ActionRuleDismissed,
	// Custom watched targets, so "who widened the watch scope?" is filterable.
	storage.ActionWatchRuleCreated,
	storage.ActionWatchRuleDeleted,
	storage.ActionIntegrationUpd,
	storage.ActionAPIKeyCreated,
	storage.ActionAPIKeyRevoked,
	storage.ActionTokenCreated,
	storage.ActionTokenRevoked,
	storage.ActionSSOUpdated,
	storage.ActionSettingsUpd,
	storage.ActionForensicSet,
	storage.ActionAISettingsUpdated,
	storage.ActionITSMSettingsUpd,
	storage.ActionITSMTicketSynced,
	storage.ActionITSMTicketUpserted,
	storage.ActionITSMTicketDeleted,
}
