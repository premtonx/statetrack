package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/statetrack/statetrack/server/internal/security"
	"github.com/statetrack/statetrack/server/internal/storage"
	"github.com/statetrack/statetrack/server/internal/testdb"
)

/* -------------------------------------------------------------------------- */
/* Session token signing                                                      */
/* -------------------------------------------------------------------------- */

func TestSessionSignAndVerify(t *testing.T) {
	signer := newSessionSigner([]byte("test-signing-key"))

	token, err := signer.Sign(sessionClaims{
		Subject: "user-1", Email: "pk@statetrack.io", Name: "P. K",
		Role: string(storage.RoleAdmin), RealRole: string(storage.RoleAdmin),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token %q is not a three-part compact JWS", token)
	}

	claims, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.Role != string(storage.RoleAdmin) {
		t.Errorf("claims round-tripped as %+v", claims)
	}
}

// A token signed with a different key must be rejected. Without this, rotating
// the session secret would not actually invalidate anything.
func TestSessionVerifyRejectsForeignSignature(t *testing.T) {
	issuer := newSessionSigner([]byte("issuer-key"))
	attacker := newSessionSigner([]byte("attacker-key"))

	token, err := attacker.Sign(sessionClaims{
		Subject: "user-1", Email: "attacker@example.com", Role: string(storage.RoleAdmin),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(token); err == nil {
		t.Fatal("a token signed with a different key was accepted")
	}
}

func TestSessionVerifyRejectsTamperedPayload(t *testing.T) {
	signer := newSessionSigner([]byte("key"))
	token, err := signer.Sign(sessionClaims{
		Subject: "u1", Email: "pk@statetrack.io", Role: string(storage.RoleAuditor),
		RealRole: string(storage.RoleAuditor),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Swap the payload for an admin claim, keeping the original signature: the
	// classic privilege-escalation attempt against a naive JWT verifier.
	parts := strings.Split(token, ".")
	forged, _ := json.Marshal(sessionClaims{
		Subject: "u1", Email: "pk@statetrack.io", Role: string(storage.RoleAdmin),
		RealRole: string(storage.RoleAdmin), Issuer: sessionIssuer,
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	parts[1] = b64(forged)
	tampered := strings.Join(parts, ".")

	if _, err := signer.Verify(tampered); err == nil {
		t.Fatal("a token with a tampered payload was accepted")
	}
}

func TestSessionVerifyRejectsMalformedAndExpired(t *testing.T) {
	signer := newSessionSigner([]byte("key"))

	for _, bad := range []string{"", "a", "a.b", "a.b.c.d", "not.a.token", ".."} {
		if _, err := signer.Verify(bad); err == nil {
			t.Errorf("malformed token %q was accepted", bad)
		}
	}

	// Hand-build an expired token that is otherwise correctly signed.
	expired, err := signer.Sign(sessionClaims{
		Subject: "u1", Email: "pk@statetrack.io", Role: string(storage.RoleAdmin),
		RealRole: string(storage.RoleAdmin),
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(expired, ".")
	var claims sessionClaims
	raw, err := decodeB64(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	claims.ExpiresAt = time.Now().Add(-2 * time.Hour).Unix()
	body, _ := json.Marshal(claims)
	parts[1] = b64(body)
	signingInput := parts[0] + "." + parts[1]
	parts[2] = b64(signBytes([]byte("key"), []byte(signingInput)))

	if _, err := signer.Verify(strings.Join(parts, ".")); err == nil {
		t.Fatal("an expired session was accepted")
	}
}

// The role claim is attacker-supplied input until proven otherwise; an unknown
// role must never be interpreted as an administrator.
func TestSessionVerifyRejectsUnknownRole(t *testing.T) {
	signer := newSessionSigner([]byte("key"))
	token, err := signer.Sign(sessionClaims{
		Subject: "u1", Email: "pk@statetrack.io", Role: "superuser", RealRole: "superuser",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(token); err == nil {
		t.Fatal("a token carrying an unknown role was accepted")
	}
}

/* -------------------------------------------------------------------------- */
/* Authorization predicates                                                   */
/* -------------------------------------------------------------------------- */

func TestCanWriteEnforcesAuditorReadOnly(t *testing.T) {
	cases := []struct {
		name    string
		p       *Principal
		wantErr bool
	}{
		{"admin", &Principal{Role: storage.RoleAdmin}, false},
		{"operator", &Principal{Role: storage.RoleOperator}, false},
		{"policy admin", &Principal{Role: storage.RolePolicyAdmin}, false},
		{"auditor", &Principal{Role: storage.RoleAuditor}, true},
		{"nil principal", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := canWrite(c.p)
			if c.wantErr && err == nil {
				t.Fatal("expected a write to be refused")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
	// The auditor refusal must be the specific, documented message: it is what
	// the console surfaces and what the CISO-facing claim rests on.
	if err := canWrite(&Principal{Role: storage.RoleAuditor}); err != ErrReadOnly {
		t.Fatalf("auditor refusal = %v, want ErrReadOnly", err)
	}
}

// A key minted for reading must stay read-only even if its role would allow
// writes, which is the point of scoping a credential more narrowly than a role.
func TestCanWriteEnforcesAPIKeyScopes(t *testing.T) {
	readOnlyKey := &Principal{
		Role: storage.RoleOperator, RealRole: storage.RoleOperator,
		APIKeyID: "k1", APIKeyName: "Checkmk & Zabbix Poller",
		Scopes: []string{"read:summary", "read:mcp"},
	}
	if err := canWrite(readOnlyKey); err == nil {
		t.Fatal("a read-scoped API key was allowed to mutate")
	}

	writeKey := &Principal{
		Role: storage.RoleOperator, RealRole: storage.RoleOperator,
		APIKeyID: "k2", Scopes: []string{"admin:write"},
	}
	if err := canWrite(writeKey); err != nil {
		t.Fatalf("an admin:write key was refused: %v", err)
	}

	// An unscoped key defers to its role, which is how a key created before
	// scoping existed keeps working.
	unscoped := &Principal{Role: storage.RoleOperator, APIKeyID: "k3"}
	if err := canWrite(unscoped); err != nil {
		t.Fatalf("an unscoped key was refused: %v", err)
	}
}

func TestScopeSatisfied(t *testing.T) {
	console := &Principal{Role: storage.RoleOperator}
	if !scopeSatisfied(console, "read:summary") {
		t.Error("a console session should not be subject to machine scopes")
	}

	key := &Principal{Role: storage.RoleOperator, APIKeyID: "k", Scopes: []string{"read:summary"}}
	if !scopeSatisfied(key, "read:summary") {
		t.Error("a key holding read:summary was denied read:summary")
	}
	if scopeSatisfied(key, "read:mcp") {
		t.Error("a key without read:mcp was allowed read:mcp")
	}
}

// The switch-role demo must only ever narrow privilege, never widen it.
func TestRoleAtLeastOnlyNarrows(t *testing.T) {
	cases := []struct {
		granted, target storage.Role
		want            bool
	}{
		{storage.RoleAdmin, storage.RoleAdmin, true},
		{storage.RoleAdmin, storage.RoleOperator, true},
		{storage.RoleAdmin, storage.RoleAuditor, true},
		{storage.RoleOperator, storage.RoleAuditor, true},
		{storage.RoleOperator, storage.RoleOperator, true},
		{storage.RoleOperator, storage.RoleAdmin, false},
		{storage.RoleAuditor, storage.RoleAdmin, false},
		{storage.RoleAuditor, storage.RoleOperator, false},
		{storage.RoleAuditor, storage.RoleAuditor, true},
	}
	for _, c := range cases {
		if got := roleAtLeast(c.granted, c.target); got != c.want {
			t.Errorf("roleAtLeast(%s, %s) = %v, want %v", c.granted, c.target, got, c.want)
		}
	}
}

// Switching roles must narrow the *effective* role without collapsing the
// granted ceiling.
//
// Regression test: the handler used to hand the target role to issueSession as
// if it were the user's own role, so the re-issued session recorded real_role
// = auditor. The switcher then read its own grant back as "auditor", every
// recovery option greyed out, and a demo could never return to Administrator —
// the read-only banner was a one-way door.
func TestSwitchRolePreservesGrantedCeiling(t *testing.T) {
	t.Setenv("STATETRACK_DEMO_MODE", "1")
	srv := &Server{}

	p := &Principal{
		UserID: "00000000-0000-4000-8000-0000000000cc",
		Email:  "pk@statetrack.io", Name: "P. K",
		Role: storage.RoleAdmin, RealRole: storage.RoleAdmin,
		AuthMethod: "session",
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/switch-role",
		strings.NewReader(`{"role":"auditor"}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, p))
	rec := httptest.NewRecorder()

	srv.authSwitchRole(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("switch-role = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Role     string `json:"role"`
		ReadOnly bool   `json:"read_only"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode switch-role response: %v", err)
	}
	if body.Role != string(storage.RoleAuditor) || !body.ReadOnly {
		t.Errorf("switch-role returned %+v, want the auditor role marked read-only", body)
	}

	// The re-issued session must carry the narrowed role *and* the original
	// grant, which is the ceiling roleAtLeast reads on the next switch.
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("switch-role set no session cookie")
	}
	claims, err := srv.sessionSignerFor().Verify(session)
	if err != nil {
		t.Fatalf("verify re-issued session: %v", err)
	}
	if claims.Role != string(storage.RoleAuditor) {
		t.Errorf("session effective role = %q, want auditor", claims.Role)
	}
	if claims.RealRole != string(storage.RoleAdmin) {
		t.Errorf("session real_role = %q, want admin — the granted ceiling must survive the switch",
			claims.RealRole)
	}
}

/* -------------------------------------------------------------------------- */
/* Bootstrap command rendering                                                */
/* -------------------------------------------------------------------------- */

func TestEnrollmentCommandsAreCopyPasteable(t *testing.T) {
	linux, windows, url := enrollmentCommands("https://statetrack.internal", "st_enroll_abc123")

	if url != "https://statetrack.internal/api/v1/agent/enroll" {
		t.Errorf("bootstrap URL = %q", url)
	}
	if strings.Contains(linux, "\n") || strings.Contains(windows, "\n") {
		t.Error("bootstrap commands must be single-line so they paste as one command")
	}
	for _, want := range []string{"curl", "sudo", "bash", "st_enroll_abc123", url} {
		if !strings.Contains(linux, want) {
			t.Errorf("linux command %q is missing %q", linux, want)
		}
	}
	for _, want := range []string{"iwr", "iex", "st_enroll_abc123", url} {
		if !strings.Contains(windows, want) {
			t.Errorf("windows command %q is missing %q", windows, want)
		}
	}
}

// A generated shell command must quote interpolated values, so a future token
// format (or a hostile one) cannot break out of the command.
func TestShellSingleQuoteIsSafe(t *testing.T) {
	cases := map[string]string{
		"abc":         `'abc'`,
		`a'b`:         `'a'\''b'`,
		`$(rm -rf /)`: `'$(rm -rf /)'`,
		"":            `''`,
	}
	for in, want := range cases {
		if got := shellSingleQuote(in); got != want {
			t.Errorf("shellSingleQuote(%q) = %q, want %q", in, got, want)
		}
	}
	// The invariant that matters: every apostrophe in the output is part of the
	// wrapper or of an escaped `'\''` sequence, so no quote can terminate the
	// string early. One embedded quote becomes three apostrophes; the wrapper
	// contributes two.
	for _, in := range []string{"", "plain", `a'b`, `''''`, "$(id)"} {
		out := shellSingleQuote(in)
		want := 2 + 3*strings.Count(in, "'")
		if got := strings.Count(out, "'"); got != want {
			t.Errorf("shellSingleQuote(%q) = %q has %d apostrophes, want %d (escaped-form invariant)",
				in, out, got, want)
		}
	}
}

func TestRedactTokenHidesSecretButKeepsShape(t *testing.T) {
	cmd := "curl -fsSL 'https://x/api/v1/agent/enroll' | sudo STATETRACK_ENROLL_TOKEN='st_enroll_deadbeefcafe' bash"
	out := redactToken(cmd)
	if strings.Contains(out, "deadbeefcafe") {
		t.Fatalf("redactToken leaked the secret: %q", out)
	}
	if !strings.Contains(out, "st_enroll_") || !strings.Contains(out, "bash") {
		t.Errorf("redactToken destroyed the command's shape: %q", out)
	}
	// A command with no token is returned unchanged rather than corrupted.
	if got := redactToken("echo hello"); got != "echo hello" {
		t.Errorf("redactToken mangled a tokenless command: %q", got)
	}
}

func TestHumanDuration(t *testing.T) {
	now := time.Now()
	cases := map[time.Duration]string{
		0:                               "expired",
		-1 * time.Hour:                  "expired",
		30 * time.Minute:                "in 30 minutes",
		2 * time.Hour:                   "in 2 hours",
		24 * time.Hour:                  "in 24 hours",
		72 * time.Hour:                  "in 3 days",
		180 * 24 * time.Hour:            "in 180 days",
		time.Duration(61) * time.Minute: "in 1 hour",
	}
	for d, want := range cases {
		if got := string(humanDuration(d)); got != want {
			t.Errorf("humanDuration(%s) = %q, want %q", d, got, want)
		}
	}
	_ = now
}

/* -------------------------------------------------------------------------- */
/* Scope and role validation                                                  */
/* -------------------------------------------------------------------------- */

func TestIsKnownScopeAndNormalize(t *testing.T) {
	for _, s := range knownScopes {
		if !isKnownScope(s) {
			t.Errorf("known scope %q not recognised", s)
		}
	}
	for _, s := range []string{"", "read:everything", "ADMIN:WRITE", "read:summary "} {
		if isKnownScope(s) {
			t.Errorf("unknown scope %q was accepted", s)
		}
	}

	got := normalizeScopes([]string{"read:summary", "", " read:summary ", "admin:write"})
	if len(got) != 2 || got[0] != "read:summary" || got[1] != "admin:write" {
		t.Errorf("normalizeScopes = %v, want [read:summary admin:write]", got)
	}
}

/* -------------------------------------------------------------------------- */
/* Route protection                                                           */
/* -------------------------------------------------------------------------- */

// Every administrative route must be unreachable anonymously. This is the test
// that fails loudly if a new endpoint is added to Routes() without a guard.
func TestRoutesRequireAuthentication(t *testing.T) {
	// Force production-like posture: no demo auto-login, no auth bypass.
	t.Setenv("STATETRACK_DEV_AUTOLOGIN", "0")
	t.Setenv("STATETRACK_ALLOW_ANONYMOUS_DATASOURCE", "0")

	srv := &Server{OrgID: "00000000-0000-4000-8000-000000000000", Store: nil}
	handler := srv.Routes()

	protected := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/hosts"},
		{http.MethodGet, "/api/v1/events"},
		{http.MethodGet, "/api/v1/recommendations"},
		{http.MethodGet, "/api/v1/integrations/grafana"},
		{http.MethodGet, "/api/v1/integrations/webhooks"},
		{http.MethodGet, "/api/v1/security/api-keys"},
		{http.MethodGet, "/api/v1/security/enrollment-tokens"},
		{http.MethodGet, "/api/v1/security/audit-logs"},
		{http.MethodGet, "/api/v1/security/sso"},
		{http.MethodGet, "/api/v1/auth/users"},
		{http.MethodPost, "/api/v1/recommendations/x/apply"},
		{http.MethodPut, "/api/v1/integrations/grafana"},
		{http.MethodPut, "/api/v1/security/sso"},
		{http.MethodPost, "/api/v1/security/api-keys"},
		{http.MethodPost, "/api/v1/security/enrollment-tokens"},
	}
	for _, route := range protected {
		req := httptest.NewRequest(route.method, route.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401 for an anonymous caller", route.method, route.path, rec.Code)
		}
	}
}

// An explicit auth bypass must still work, because a deployment behind a
// trusted gateway needs it.
func TestAuthDisabledBypassesIdentity(t *testing.T) {
	t.Setenv("STATETRACK_AUTH_DISABLED", "1")

	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	srv.withIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil {
			t.Fatal("expected a principal with auth disabled")
		}
		if p.Role != storage.RoleAdmin {
			t.Errorf("role = %s, want admin", p.Role)
		}
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

/* -------------------------------------------------------------------------- */
/* Status recorder                                                            */
/* -------------------------------------------------------------------------- */

// Only a successful mutation may be audited, so the recorder must see the first
// status written and not be confused by an implicit 200.
func TestStatusRecorderCapturesStatus(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	rec.WriteHeader(http.StatusForbidden)
	rec.WriteHeader(http.StatusOK) // a second call must not overwrite
	if rec.status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.status)
	}
	if !rec.wrote {
		t.Error("recorder did not record that a header was written")
	}

	implicit := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	_, _ = implicit.Write([]byte("ok"))
	if implicit.status != http.StatusOK {
		t.Errorf("implicit status = %d, want 200", implicit.status)
	}
}

/* -------------------------------------------------------------------------- */
/* Database-backed RBAC and auditing                                          */
/* -------------------------------------------------------------------------- */

// securityTestServer builds a Server backed by a real database, or skips.
// The schema is applied if the database is bare, so the suite runs against an
// empty CI service container as well as a migrated developer database.
func securityTestServer(t *testing.T) (*Server, *storage.Store, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	pool := testdb.Pool(t)

	store := storage.New(pool, nil, 0)
	org, err := store.DefaultOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Store: store, OrgID: org}, store, org
}

// An auditor must be refused every mutation, and the refusal must not leave an
// audit row behind: no change occurred, so there is nothing to audit.
func TestAuditorMutationIsForbiddenAndUnaudited(t *testing.T) {
	srv, store, org := securityTestServer(t)
	t.Setenv("STATETRACK_AUTH_DISABLED", "0")

	ctx := context.Background()
	before, err := store.ListAuditLogs(ctx, "", "", 500)
	if err != nil {
		t.Fatal(err)
	}

	auditor := &Principal{
		UserID: "00000000-0000-4000-8000-0000000000aa",
		Email:  "compliance@statetrack.io", Name: "Dana Whitfield",
		Role: storage.RoleAuditor, RealRole: storage.RoleAuditor,
		AuthMethod: "session",
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/security/sso", strings.NewReader(`{"enabled":true}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, auditor))
	rec := httptest.NewRecorder()

	srv.mutation(storage.ActionSSOUpdated, namedTarget("sso"), srv.ssoPut).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor PUT = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "read-only Auditor") {
		t.Errorf("403 body = %q, want it to name the read-only Auditor role", rec.Body.String())
	}

	after, err := store.ListAuditLogs(ctx, "", "", 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("a rejected mutation wrote %d audit rows, want 0", len(after)-len(before))
	}
	_ = org
}

// Every successful administrative mutation must leave a control-plane audit row
// naming the actor, the role, the action and the source address.
func TestSuccessfulMutationWritesAuditRow(t *testing.T) {
	srv, store, _ := securityTestServer(t)
	t.Setenv("STATETRACK_AUTH_DISABLED", "0")

	ctx := context.Background()
	admin := &Principal{
		UserID: "00000000-0000-4000-8000-0000000000bb",
		Email:  "pk@statetrack.io", Name: "P. K",
		Role: storage.RoleAdmin, RealRole: storage.RoleAdmin,
		AuthMethod: "session",
	}

	// A uniquely-named target makes the assertion independent of whatever else
	// the shared development database already contains.
	target := "audit-test-" + time.Now().UTC().Format("20060102T150405.000000000")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/enrollment-tokens",
		strings.NewReader(`{"name":"`+target+`","max_uses":1,"expires_in_days":1}`))
	req.Header.Set("X-Forwarded-For", "10.9.9.9, 10.0.0.1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, admin))
	rec := httptest.NewRecorder()

	handler := srv.mutation(storage.ActionTokenCreated,
		func(r *http.Request) string { return target }, srv.createEnrollmentToken)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create token = %d: %s", rec.Code, rec.Body.String())
	}

	logs, err := store.ListAuditLogs(ctx, storage.ActionTokenCreated, "pk@statetrack.io", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("no audit row was written for a successful mutation")
	}
	entry := logs[0]
	if entry.ActorRole != string(storage.RoleAdmin) {
		t.Errorf("audit actor_role = %q, want admin", entry.ActorRole)
	}
	if entry.Target != target {
		t.Errorf("audit target = %q, want %q", entry.Target, target)
	}
	// The forwarded address must win: the recorded IP is the operator's, not
	// the proxy's.
	if entry.SourceIP != "10.9.9.9" {
		t.Errorf("audit source_ip = %q, want the first X-Forwarded-For hop", entry.SourceIP)
	}
	if entry.Details["method"] != http.MethodPost {
		t.Errorf("audit details = %v, want the method recorded", entry.Details)
	}

	// The minted credential must be usable and must not be stored in cleartext.
	var body struct {
		Token      string `json:"token"`
		APIKeyID   string `json:"id"`
		Enrollment struct {
			ID string `json:"id"`
		} `json:"enrollment_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !strings.HasPrefix(body.Token, security.EnrollmentPrefix) {
		t.Fatalf("minted token %q lacks the enrollment prefix", body.Token)
	}

	// Round-trip the credential through the store's own hashing path.
	hash := security.HashToken(body.Token)
	if hash == body.Token {
		t.Fatal("the stored value equals the token; it must be a hash")
	}
	var stored string
	if err := srv.Store.Pool().QueryRow(ctx,
		`SELECT token_hash FROM enrollment_tokens WHERE token_hash = $1`, hash).Scan(&stored); err != nil {
		t.Fatalf("the minted token's hash was not stored: %v", err)
	}
}

// An API key must authenticate from its Bearer token, and the hash — not the
// token — must be what the database holds.
func TestAPIKeyBearerAuthentication(t *testing.T) {
	srv, store, _ := securityTestServer(t)
	t.Setenv("STATETRACK_AUTH_DISABLED", "0")
	t.Setenv("STATETRACK_DEV_AUTOLOGIN", "0")

	ctx := context.Background()
	admin := &Principal{
		Role: storage.RoleAdmin, RealRole: storage.RoleAdmin,
		Email: "pk@statetrack.io", AuthMethod: "session",
	}
	token, prefix, err := security.GenerateToken(security.APIKeyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	name := "Bearer test key " + time.Now().UTC().Format("150405.000")
	if _, err := store.CreateAPIKey(ctx, srv.OrgID, storage.APIKey{
		Name: name, KeyPrefix: prefix, Role: storage.RoleOperator,
		Scopes: []string{"read:summary"},
	}, security.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.Pool().Exec(context.Background(),
			`DELETE FROM api_keys WHERE name = $1`, name)
	})
	_ = admin

	// The raw token must not be stored anywhere.
	var count int
	if err := store.Pool().QueryRow(ctx,
		`SELECT count(*) FROM api_keys WHERE key_hash = $1`, token).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("the raw API key was found in the key_hash column")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	p := srv.resolvePrincipal(req)
	if p == nil {
		t.Fatal("a valid Bearer API key did not authenticate")
	}
	if !p.IsAPIKey() {
		t.Error("the principal is not marked as an API key")
	}
	if p.Role != storage.RoleOperator {
		t.Errorf("role = %q, want operator", p.Role)
	}
	if p.APIKeyName != name {
		t.Errorf("api key name = %q, want %q", p.APIKeyName, name)
	}
	// An API key has no user identity, so the audit trail must attribute its
	// actions to the key by name rather than leaving the actor blank.
	if !strings.Contains(p.ActorEmail(), name) {
		t.Errorf("ActorEmail = %q, want it to name the key", p.ActorEmail())
	}

	// A revoked key must stop authenticating immediately.
	if _, err := store.RevokeAPIKey(ctx, srv.OrgID, p.APIKeyID); err != nil {
		t.Fatal(err)
	}
	if got := srv.resolvePrincipal(req); got != nil {
		t.Error("a revoked API key still authenticated")
	}
}

// An unknown or malformed Bearer token must not authenticate, and must not
// produce a principal with a usable role.
func TestInvalidBearerTokenIsAnonymous(t *testing.T) {
	srv, _, _ := securityTestServer(t)
	t.Setenv("STATETRACK_AUTH_DISABLED", "0")
	t.Setenv("STATETRACK_DEV_AUTOLOGIN", "0")

	for _, tok := range []string{
		"st_live_deadbeefdeadbeefdeadbeef", // well-shaped, unknown
		"st_live_",                         // truncated
		"garbage.token.value",              // not an API key, not a valid JWT
		"Bearer",                           // not a scheme-prefixed credential
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if p := srv.resolvePrincipal(req); p != nil {
			t.Errorf("token %q authenticated as %+v", tok, p)
		}
	}
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

// b64 mirrors the token encoding the signer uses, so a test can hand-build a
// token with a modified payload while keeping the rest of the wire format.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// signBytes reproduces the HS256 signature over a signing input, used to build
// a correctly-signed token whose claims a test has tampered with deliberately.
func signBytes(key, signingInput []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(signingInput)
	return mac.Sum(nil)
}
