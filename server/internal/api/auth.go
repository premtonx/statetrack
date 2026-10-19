package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/statetrack/statetrack/server/internal/security"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// Session cookie / token parameters.
const (
	sessionCookieName = "st_session"
	sessionIssuer     = "statetrack"
	// sessionTTL is deliberately short. The console is an operational tool
	// holding administrative rights; a long-lived bearer token in a cookie is
	// the most likely way it leaks, so a working day is the outside bound.
	sessionTTL = 12 * time.Hour
	// sessionTokenPermittedClockSkew is the leeway applied to `exp` so a
	// console running slightly behind the server does not fail open.
	sessionClockSkew = 60 * time.Second
)

// contextKey types are unexported and distinct so a handler cannot accidentally
// read a value some other middleware stored under a colliding string key.
type contextKey struct{ name string }

var principalKey = &contextKey{"principal"}

// auditRecord is the mutable slot through which a handler contributes fields
// to the audit row the mutation wrapper writes after it returns.
//
// The wrapper owns the write because it is the only place that knows the action
// succeeded. A handler that wrote its own row would produce two entries for one
// click, which is worse than a sparse trail: it makes the count of "who changed
// what" wrong. A handler with more to say than the URL target sets details here
// and the wrapper merges them into its single row.
type auditRecord struct {
	// Details are merged into the row's JSONB payload.
	Details map[string]any
	// Target overrides the wrapper's route-derived target. A delete route only
	// knows the rule id until it has read the row, so the handler that learns
	// the watched path sets it here rather than auditing a UUID.
	Target string
}

var auditRecordKey = &contextKey{"audit_record"}

// addAuditDetail contributes one field to the current request's audit row.
func addAuditDetail(r *http.Request, key string, value any) {
	rec, ok := r.Context().Value(auditRecordKey).(*auditRecord)
	if !ok || rec == nil || rec.Details == nil {
		return
	}
	rec.Details[key] = value
}

// setAuditTarget makes the audit row name a subject the handler discovered
// while running, instead of the route's wildcard segment.
func setAuditTarget(r *http.Request, target string) {
	rec, ok := r.Context().Value(auditRecordKey).(*auditRecord)
	if !ok || rec == nil {
		return
	}
	rec.Target = strings.TrimSpace(target)
}

// Principal is the authenticated actor behind a request: either a console
// session (a human) or an API key (a machine). Both carry an effective role so
// RBAC is one check rather than two parallel code paths.
type Principal struct {
	// Email is empty for API-key principals.
	Email string
	Name  string
	Role  storage.Role
	// RealRole is the role actually granted, which may be more privileged than
	// Role when a session is deliberately acting as a lesser role.
	RealRole storage.Role
	// APIKeyID and APIKeyName are set only for machine principals.
	APIKeyID   string
	APIKeyName string
	Scopes     []string
	// UserID is set for console sessions.
	UserID string
	// TOTPEnabled reports whether the console identity has a second factor,
	// which /auth/me surfaces as a badge.
	TOTPEnabled bool
	// AuthMethod is 'session', 'api_key' or 'dev_autologin', recorded in the
	// audit trail so a reviewer can see how an action was authenticated.
	AuthMethod string
}

// IsAPIKey reports whether the request authenticated with a machine credential.
func (p *Principal) IsAPIKey() bool { return p.APIKeyID != "" }

// ActorEmail is the value recorded in the audit trail. An API key has no human
// identity, so it is attributed to the key's display name — an auditor needs to
// see "Checkmk & Zabbix Poller did this", not an empty actor.
func (p *Principal) ActorEmail() string {
	if p.Email != "" {
		return p.Email
	}
	if p.APIKeyName != "" {
		return "apikey:" + p.APIKeyName
	}
	return "unknown"
}

func (p *Principal) ActorRole() string { return string(p.Role) }

// PrincipalFrom returns the authenticated actor, or nil for an anonymous
// request (only reachable on routes the middleware left open).
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey).(*Principal)
	return p
}

/* -------------------------------------------------------------------------- */
/* Session tokens (signed HS256 JWT)                                          */
/* -------------------------------------------------------------------------- */

// sessionClaims is a standard JWT claim set. Using the JWS compact form rather
// than a bespoke opaque token means a deployment can verify a StateTrack session
// with any standard JWT library, which is what lets an enterprise put the
// console behind their own auth-aware gateway.
type sessionClaims struct {
	Subject   string `json:"sub"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	RealRole  string `json:"real_role"`
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// sessionSigner signs and verifies session tokens with HMAC-SHA256.
type sessionSigner struct {
	secret []byte
}

func newSessionSigner(secret []byte) *sessionSigner {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		// A crypto/rand read cannot realistically fail; if it did, an all-zero
		// key would be far worse than a panic at boot, so fail loudly instead.
		if _, err := rand.Read(secret); err != nil {
			panic(fmt.Sprintf("statetrack: cannot generate a session secret: %v", err))
		}
	}
	return &sessionSigner{secret: secret}
}

// Sign returns a compact JWS for the claims.
func (s *sessionSigner) Sign(c sessionClaims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	c.Issuer = sessionIssuer
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(sessionTTL).Unix()

	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode session claims: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)

	signingInput := header + "." + body
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// Verify parses and authenticates a token, returning its claims.
//
// The signature is checked before the payload is trusted in any way, and the
// comparison is constant-time so a forged token cannot be narrowed down byte by
// byte through timing.
func (s *sessionSigner) Verify(token string) (sessionClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return sessionClaims{}, errors.New("malformed session token")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	want := mac.Sum(nil)

	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return sessionClaims{}, errors.New("malformed session signature")
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return sessionClaims{}, errors.New("invalid session signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return sessionClaims{}, errors.New("malformed session payload")
	}
	var c sessionClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return sessionClaims{}, fmt.Errorf("decode session claims: %w", err)
	}
	if c.Issuer != sessionIssuer {
		return sessionClaims{}, errors.New("invalid session issuer")
	}
	if time.Now().After(time.Unix(c.ExpiresAt, 0).Add(sessionClockSkew)) {
		return sessionClaims{}, errors.New("session expired")
	}
	// Re-validate the claim against the closed role set: the DB constrains the
	// column, but a token is attacker-supplied input until proven otherwise, and
	// an unknown role must never be treated as a privileged one.
	if !storage.IsValidRole(c.Role) {
		return sessionClaims{}, errors.New("invalid session role")
	}
	if c.RealRole != "" && !storage.IsValidRole(c.RealRole) {
		return sessionClaims{}, errors.New("invalid session real_role")
	}
	return c, nil
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

// demoMode reports whether the server is running the local demo workflow. It
// gates the developer conveniences (auto-login, anonymous datasource reads, the
// seeded fleet heartbeat) that would be a security hole in a real deployment, so
// it is the single switch those features read.
//
// Parsed as a boolean rather than "is the variable set": an operator who writes
// `STATETRACK_DEMO_MODE: "false"` in a compose file means off, and treating a
// non-empty string as on would silently open auto-login on a production host.
// The default is off, so a plain `docker compose up` is a clean install.
func demoMode() bool { return envBool("STATETRACK_DEMO_MODE", false) }

// envBool reads a tri-state boolean env var: "0"/"false" is off, "1"/"true" is
// on, and empty is `def`. Written out because the auto-login decision must be
// unambiguous — an unset variable that defaulted to "on" would hand every
// production visitor an administrator session.
func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	default:
		return def
	}
}

// envOr is env() with a fallback, local to this file to avoid reaching for the
// cmd package's copy.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// authDisabled reports whether authentication is deliberately bypassed. Off
// unless explicitly requested, so the default posture is "authenticated".
func authDisabled() bool { return envBool("STATETRACK_AUTH_DISABLED", false) }

// devAutoLogin reports whether an anonymous request is signed in automatically.
//
// Defaults to on in demo mode only. A production server with no environment
// configuration therefore has no auto-login, and the switch is explicit rather
// than inferred from the build.
func devAutoLogin() bool {
	// An explicit setting always wins, including an explicit "off" inside demo
	// mode — that is how a developer exercises the login screen locally.
	if v := strings.TrimSpace(os.Getenv("STATETRACK_DEV_AUTOLOGIN")); v != "" {
		return envBool("STATETRACK_DEV_AUTOLOGIN", false)
	}
	return demoMode()
}

// allowAnonymousDatasource reports whether the Grafana data-source query
// endpoints may be read without credentials. On in demo mode so the provisioned
// dashboard works out of the box; off otherwise, because the event stream is
// exactly the data those endpoints expose.
func allowAnonymousDatasource() bool {
	return envBool("STATETRACK_ALLOW_ANONYMOUS_DATASOURCE", demoMode())
}

// sessionSecret resolves the signing key. A configured secret keeps sessions
// valid across restarts and across replicas; without one the server generates a
// per-boot key and says so, because silently invalidating every session on
// deploy is a support ticket waiting to happen.
func sessionSecret(logger func(string, ...any)) []byte {
	if v := os.Getenv("STATETRACK_SESSION_SECRET"); v != "" {
		return []byte(v)
	}
	logger("STATETRACK_SESSION_SECRET is not set; generated a per-boot session key " +
		"(console sessions will not survive a restart, and multiple replicas will not share sessions)")
	return nil
}

/* -------------------------------------------------------------------------- */
/* Middleware                                                                 */
/* -------------------------------------------------------------------------- */

// openRoutes are the only paths reachable without a principal. Everything else
// under /api/v1 requires authentication; /healthz and /metrics are infrastructure
// endpoints (a load balancer and Prometheus have no session).
func openRoute(path string) bool {
	switch path {
	case "/healthz", "/metrics",
		"/api/v1/auth/login", "/api/v1/auth/me",
		"/api/v1/auth/totp/setup", "/api/v1/auth/totp/verify",
		"/api/v1/auth/switch-role", "/api/v1/auth/logout":
		return true
	}
	// The Grafana data-source endpoints are decided by configuration, not by
	// path, so the caller handles them.
	return false
}

// withIdentity resolves the authenticated principal and stores it on the
// request context. It never rejects: authorization is enforced by each route,
// because "this endpoint needs a read-only key" and "this endpoint needs a
// session" are different requirements that a single gate cannot express.
func (s *Server) withIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := s.resolvePrincipal(r); p != nil {
			r = r.WithContext(context.WithValue(r.Context(), principalKey, p))
			// Stamp last-used on machine credentials so the console can show
			// a dormant key. Best-effort: never fail a valid request for it.
			if p.IsAPIKey() && s.Store != nil {
				if err := s.Store.TouchAPIKeyLastUsed(r.Context(), p.APIKeyID); err != nil {
					s.logger().Debug("touch api key", "err", err)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// resolvePrincipal attempts every supported authentication method in order of
// specificity, returning nil when the request is anonymous.
func (s *Server) resolvePrincipal(r *http.Request) *Principal {
	if authDisabled() {
		// Explicit opt-out. Attributed as an administrator so the audit trail
		// records that the action happened with authentication bypassed.
		return &Principal{
			Email: "auth-disabled@localhost", Name: "Auth Disabled",
			Role: storage.RoleAdmin, RealRole: storage.RoleAdmin,
			AuthMethod: "disabled",
		}
	}

	if token := bearerToken(r); token != "" {
		// A live key is self-identifying by its prefix, which keeps the two
		// bearer types apart without attempting a JWT parse on every API call.
		if strings.HasPrefix(token, security.APIKeyPrefix) {
			return s.principalFromAPIKey(r, token)
		}
		if p := s.principalFromSession(r, token); p != nil {
			return p
		}
	}

	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		if p := s.principalFromSession(r, c.Value); p != nil {
			return p
		}
	}

	if devAutoLogin() && s.Store != nil {
		// Sign in as the seeded administrator so `dev.ps1 run-all` produces a
		// usable console without a login step. The session is attributed as
		// 'dev_autologin' so an audit reviewer can never mistake it for a real
		// credential exchange.
		orgID, err := s.Store.DefaultOrg(r.Context())
		if err == nil {
			if u, err := s.Store.DefaultUser(r.Context(), orgID); err == nil {
				return &Principal{
					UserID: u.ID, Email: u.Email, Name: u.Name,
					Role: u.Role, RealRole: u.Role, TOTPEnabled: u.TOTPEnabled,
					AuthMethod: "dev_autologin",
				}
			}
		}
	}
	return nil
}

func (s *Server) principalFromAPIKey(r *http.Request, token string) *Principal {
	if s.Store == nil {
		return nil
	}
	key, err := s.Store.AuthenticateAPIKey(r.Context(), security.HashToken(token))
	if err != nil {
		// Deliberately indistinguishable from "no such key": a caller probing
		// for valid prefixes learns nothing from the response.
		s.logger().Debug("api key rejected", "prefix", security.TokenPrefixOf(token, security.APIKeyPrefix))
		return nil
	}
	if !key.Active(time.Now()) {
		return nil
	}
	return &Principal{
		Role: key.Role, RealRole: key.Role,
		APIKeyID: key.ID, APIKeyName: key.Name,
		// The key's scopes are carried rather than enforced here, because
		// whether a scope is required depends on the route being called.
		Scopes: key.Scopes, AuthMethod: "api_key",
	}
}

func (s *Server) principalFromSession(r *http.Request, token string) *Principal {
	if s.signer == nil {
		return nil
	}
	claims, err := s.signer.Verify(token)
	if err != nil {
		return nil
	}
	realRole := storage.Role(claims.RealRole)
	if claims.RealRole == "" {
		realRole = storage.Role(claims.Role)
	}
	return &Principal{
		UserID: claims.Subject, Email: claims.Email, Name: claims.Name,
		Role: storage.Role(claims.Role), RealRole: realRole,
		AuthMethod: "session",
	}
}

// bearerToken extracts a bearer credential, preferring the Authorization header
// and falling back to the query string so an SSE/WebSocket client that cannot
// set headers can still authenticate.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		parts := strings.SplitN(h, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	// Grafana's data source proxy cannot always set an Authorization header, so
	// an API key may arrive as ?token=st_live_… on the datasource routes only.
	if allowAnonymousDatasource() || r.URL.Path == "/api/v1/stream" {
		if t := r.URL.Query().Get("token"); t != "" {
			return t
		}
	}
	return ""
}

// requirePrincipal rejects an anonymous request with 401.
func (s *Server) requirePrincipal(r *http.Request) (*Principal, bool) {
	p := PrincipalFrom(r.Context())
	return p, p != nil
}

/* -------------------------------------------------------------------------- */
/* Authorization helpers                                                      */
/* -------------------------------------------------------------------------- */

// ErrReadOnly is the sentinel every authorization failure returns, so the
// message a CISO sees in the UI is the same one the tests assert on.
var ErrReadOnly = errors.New("read-only Auditor role cannot modify configuration")

// canWrite decides whether a principal may mutate configuration.
//
// Two independent gates, both must pass:
//   - the role must not be the read-only auditor role;
//   - an API key that declares scopes must carry `admin:write`, so a key minted
//     as "read:summary" for a monitoring poller stays read-only no matter what
//     role it was given.
func canWrite(p *Principal) error {
	if p == nil {
		return errors.New("authentication required")
	}
	if !p.Role.CanWrite() {
		return ErrReadOnly
	}
	if p.IsAPIKey() && len(p.Scopes) > 0 && !hasScope(p.Scopes, "admin:write") {
		return errors.New("this API key is scoped to reads only")
	}
	return nil
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// scopeSatisfied reports whether a principal's scopes permit an access class.
// A principal with no declared scopes (a console session) is unrestricted here;
// scope enforcement is a property of machine credentials.
func scopeSatisfied(p *Principal, required string) bool {
	if p == nil || !p.IsAPIKey() || len(p.Scopes) == 0 {
		return true
	}
	return hasScope(p.Scopes, required)
}

// mutation wraps a state-changing handler with RBAC enforcement and automatic
// audit logging.
//
// Ordering is deliberate: authorization is decided before the handler runs, and
// the audit row is written only after the handler reports success. That means an
// auditor's rejected attempt leaves no audit row (there was no change to audit)
// while every accepted change is recorded — including changes made through the
// API by a machine credential.
func (s *Server) mutation(action string, target targetFunc, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if err := canWrite(p); err != nil {
			// p may be nil here (an anonymous caller), so the role is read
			// defensively. Dereferencing it unconditionally would turn an
			// unauthenticated POST into a panic instead of a 401.
			body := map[string]string{"error": err.Error()}
			if p != nil {
				body["role"] = p.ActorRole()
			}
			status := http.StatusForbidden
			if p == nil {
				status = http.StatusUnauthorized
			}
			writeJSON(w, status, body)
			return
		}

		// Capture the status so only a successful change is audited. A 4xx/5xx
		// means nothing was modified, and auditing it would make the trail lie
		// about what the system's state actually is.
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		audit := &auditRecord{Details: map[string]any{}}
		r = r.WithContext(context.WithValue(r.Context(), auditRecordKey, audit))

		// Resolve the target before the handler runs. A body-derived target
		// (bodyTarget) has to read the request body, and the handler consumes
		// it while decoding — resolving afterwards would audit an empty
		// subject on exactly the creation routes the trail exists to explain.
		t := ""
		if target != nil {
			t = target(r)
		}
		next(rec, r)

		if rec.status >= 400 {
			return
		}
		// A handler that read the stored row may know a better subject than the
		// route did (a deleted rule's pattern, not its id).
		if audit.Target != "" {
			t = audit.Target
		}
		s.recordAudit(r, p, action, t, audit.Details)
	}
}

// targetFunc derives the human-readable subject of an audited action.
type targetFunc func(*http.Request) string

// recordAudit appends a control-plane audit row. Best-effort by design: a failed
// audit write is logged at error level and never turns an already-applied
// administrative change into a response the caller would retry.
func (s *Server) recordAudit(r *http.Request, p *Principal, action, target string, details map[string]any) {
	if s.Store == nil || p == nil {
		return
	}
	entry := storage.AuditLog{
		ActorEmail: p.ActorEmail(),
		ActorRole:  p.ActorRole(),
		Action:     action,
		Target:     target,
		SourceIP:   clientIP(r),
		Details:    details,
	}
	if entry.Details == nil {
		entry.Details = map[string]any{"method": r.Method, "path": r.URL.Path}
	} else {
		entry.Details["method"] = r.Method
		entry.Details["path"] = r.URL.Path
	}
	if p.IsAPIKey() {
		entry.Details["auth"] = "api_key"
		entry.Details["api_key"] = p.APIKeyName
	} else if p.AuthMethod != "" {
		entry.Details["auth"] = p.AuthMethod
	}

	// A detached context, not r.Context(): the audit row must still be written
	// when the client has already disconnected, which is common on a 200 the
	// browser navigated away from.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := s.Store.AppendAuditLog(ctx, entry); err != nil {
		s.logger().Error("write control-plane audit log", "action", action, "err", err)
	}
}

/* -------------------------------------------------------------------------- */
/* Route guards                                                               */
/* -------------------------------------------------------------------------- */

// pathTarget names a target after the route's wildcard segment (an id), which
// is what makes "which recommendation did they approve?" answerable.
func pathTarget(wildcard string) targetFunc {
	return func(r *http.Request) string { return r.PathValue(wildcard) }
}

// namedTarget returns a fixed label for routes that act on a singleton resource
// (the SSO configuration, the platform settings).
func namedTarget(name string) targetFunc {
	return func(*http.Request) string { return name }
}

// bodyTarget names an audited action after a field in the request body.
//
// It reads and restores the body, like providerTarget, because the handler that
// runs next still needs to decode the same request. A watched-target creation is
// audited by the path the operator named rather than by an id that only exists
// after the insert — "who started watching D:\Apps\Billing\Config\**" is the
// question an auditor asks, and the id would answer none of it.
func bodyTarget(field string) targetFunc {
	return func(r *http.Request) string {
		if r.Body == nil {
			return ""
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return ""
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return ""
		}
		v, _ := body[field].(string)
		return strings.TrimSpace(v)
	}
}

// providerTarget names an audited action after the resource named in the request
// body, for routes that act on one of several providers (the webhook hub).
//
// It reads and restores the body rather than consuming it, because the wrapped
// handler still needs to decode the same request. Reading it afterwards instead
// would silently yield an empty target — every webhook audit row would read
// "webhook" regardless of which card was saved.
func providerTarget(fallback string) targetFunc {
	return func(r *http.Request) string {
		if r.Body == nil {
			return fallback
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return fallback
		}
		// Restore the body for the handler, preserving the original failure mode
		// if ReadAll errored partway through.
		r.Body = io.NopCloser(bytes.NewReader(raw))

		var body struct {
			Provider string `json:"provider"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || strings.TrimSpace(body.Provider) == "" {
			return fallback
		}
		return strings.TrimSpace(body.Provider)
	}
}

// readOnly guards an endpoint that requires a principal but no particular scope.
func (s *Server) readOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.requirePrincipal(r); !ok {
			writeUnauthorized(w)
			return
		}
		next(w, r)
	}
}

// apiRead guards an endpoint a machine credential is expected to call, requiring
// a specific scope when the caller is an API key. A console session passes: a
// human reading the console is not subject to machine scopes.
func (s *Server) apiRead(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.requirePrincipal(r)
		if !ok {
			writeUnauthorized(w)
			return
		}
		if !scopeSatisfied(p, scope) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "this API key does not carry the " + scope + " scope",
			})
			return
		}
		next(w, r)
	}
}

// datasource guards the Grafana data-source query endpoints. These are special:
// a provisioned dashboard is configured with a datasource URL and, in demo
// deployments, no credentials, so anonymous read is permitted only when
// explicitly configured (demo mode by default, never in production).
func (s *Server) datasource(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowAnonymousDatasource() {
			next(w, r)
			return
		}
		s.readOnly(next)(w, r)
	}
}

// writeUnauthorized is the single 401 body, so the console has one shape to
// branch on when deciding to show the login screen.
func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="statetrack"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error": "authentication required",
	})
}

// statusRecorder captures the status code of a wrapped handler.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

// clientIP extracts the caller's address for the audit trail, preferring a
// proxy's X-Forwarded-For so the recorded address is the human's, not the load
// balancer's.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// setSessionCookie writes the signed session as an HttpOnly cookie.
//
// HttpOnly and Secure are not optional: the token is a full administrative
// bearer credential, so it must be unreadable from JavaScript (an XSS bug then
// cannot exfiltrate it) and must never travel over plaintext.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   requestIsTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie expires the session cookie.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// requestIsTLS reports whether the request arrived over TLS, directly or via a
// proxy that terminated it. Marking a cookie Secure on a plain-HTTP development
// origin would make the browser drop it and silently break login.
func requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
