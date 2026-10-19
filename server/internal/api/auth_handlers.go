package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/statetrack/statetrack/server/internal/security"
	"github.com/statetrack/statetrack/server/internal/storage"
)

/* -------------------------------------------------------------------------- */
/* Identity: /auth/me, login, logout, switch-role                             */
/* -------------------------------------------------------------------------- */

// userView is the console-facing identity payload. It never includes a password
// hash or a TOTP secret; the console learns only whether a second factor exists.
type userView struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	Initials     string `json:"initials"`
	Role         string `json:"role"`
	RoleLabel    string `json:"role_label"`
	TOTPEnabled  bool   `json:"totp_enabled"`
	AuthProvider string `json:"auth_provider"`
	// LastLoginAt lets an auditor see a dormant account. Omitted when the user
	// has never signed in, which is the state that matters.
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	// CanWrite is computed server-side so the console disables mutating controls
	// from the same predicate the API enforces, rather than re-deriving it in
	// TypeScript where the two could drift.
	CanWrite bool `json:"can_write"`
}

func userViewFor(p *Principal) userView {
	v := userView{
		Email:     p.Email,
		Name:      p.Name,
		Role:      string(p.Role),
		RoleLabel: p.Role.RoleLabel(),
		// A machine credential is never represented as having a second factor.
		TOTPEnabled:  p.TOTPEnabled,
		AuthProvider: storage.AuthProviderLocal,
		CanWrite:     p.Role.CanWrite(),
	}
	// The initials the avatar shows, derived from the display name.
	name := strings.TrimSpace(p.Name)
	if name != "" {
		parts := strings.Fields(name)
		if len(parts) >= 2 {
			v.Initials = strings.ToUpper(parts[0][:1] + parts[len(parts)-1][:1])
		} else {
			v.Initials = strings.ToUpper(name[:1])
		}
	} else if p.Email != "" {
		v.Initials = strings.ToUpper(p.Email[:1])
	} else {
		v.Initials = "?"
	}
	return v
}

// authMeResponse is the payload every console bootstrap loads first. It carries
// the profile, the effective and granted roles, and the enterprise security
// posture so the header and the Auditor banner render from one request.
type authMeResponse struct {
	Authenticated bool     `json:"authenticated"`
	User          userView `json:"user"`
	// RealRole is the granted role; Role above is what is currently being
	// exercised. They differ only while a demo switched into a lesser role, and
	// the console shows a "viewing as" banner exactly when they do.
	RealRole      string `json:"real_role"`
	RealRoleLabel string `json:"real_role_label"`
	// Scopes is populated for API-key principals, so a machine caller can
	// discover what it is allowed to do rather than failing endpoint by
	// endpoint.
	Scopes []string `json:"scopes,omitempty"`
	// AuthMethod and ReadOnly drive the console's read-only presentation.
	AuthMethod string `json:"auth_method"`
	ReadOnly   bool   `json:"read_only"`
	// SSO is the org's enterprise sign-on posture, surfaced here so the login
	// screen can decide whether to offer a password form.
	SSO ssoSummary `json:"sso"`
	// DemoMode tells the console it may offer the role switcher (a demo/profiling
	// affordance) without exposing it in a production deployment.
	DemoMode bool `json:"demo_mode"`
	// DevAutoLogin reports that the session was established automatically, so
	// the console can say so instead of pretending the user signed in.
	DevAutoLogin bool `json:"dev_autologin"`
}

// ssoSummary is the non-secret slice of the SSO configuration.
type ssoSummary struct {
	Provider string `json:"provider"`
	Enabled  bool   `json:"enabled"`
	// RequireSSO reports whether local password sign-in is disabled, which the
	// login screen needs to know.
	RequireSSO     bool   `json:"require_sso"`
	EnforcedDomain string `json:"enforced_domain,omitempty"`
}

// authMe returns the current principal. Anonymous callers get authenticated=false
// with 200 rather than 401: the console calls this on every load, and a 401 would
// make the first paint a console error instead of the login screen.
//
//	GET /api/v1/auth/me
func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	summary := ssoSummary{Provider: storage.SSOMicrosoftEntra}
	if s.Store != nil {
		if cfg, err := s.Store.GetSSOConfig(r.Context(), s.OrgID); err == nil {
			summary = ssoSummary{
				Provider: cfg.Provider, Enabled: cfg.Enabled,
				RequireSSO: cfg.RequireSSO, EnforcedDomain: cfg.EnforcedDomain,
			}
		}
	}

	p := PrincipalFrom(r.Context())
	if p == nil {
		writeJSON(w, http.StatusOK, authMeResponse{
			Authenticated: false,
			User:          userView{Role: string(storage.RoleAuditor), RoleLabel: storage.RoleAuditor.RoleLabel(), CanWrite: false},
			ReadOnly:      true,
			SSO:           summary,
			DemoMode:      demoMode(),
		})
		return
	}

	// An API key has no user row, so its profile is synthesized from the key
	// itself rather than reported as an anonymous user.
	resp := authMeResponse{
		Authenticated: true,
		User:          userViewFor(p),
		RealRole:      string(p.RealRole),
		RealRoleLabel: p.RealRole.RoleLabel(),
		Scopes:        p.Scopes,
		AuthMethod:    p.AuthMethod,
		ReadOnly:      !p.Role.CanWrite(),
		SSO:           summary,
		DemoMode:      demoMode(),
		DevAutoLogin:  p.AuthMethod == "dev_autologin",
	}
	if p.IsAPIKey() {
		resp.User.Email = ""
		resp.User.Name = p.APIKeyName
		resp.User.Initials = "AK"
		resp.User.AuthProvider = "api_key"
	}
	writeJSON(w, http.StatusOK, resp)
}

// authLoginRequest is the password sign-in form.
type authLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// TOTPCode is required only when the account has a second factor.
	TOTPCode string `json:"totp_code"`
}

// authLogin authenticates a console user with a password, plus a TOTP code when
// the account has 2FA enabled.
//
//	POST /api/v1/auth/login
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	var body authLoginRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "identity store unavailable"})
		return
	}

	email := strings.TrimSpace(strings.ToLower(body.Email))
	if email == "" || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password are required"})
		return
	}

	// SSO enforcement is checked before anything else so a misconfigured
	// password cannot be a way around a mandatory IdP.
	if cfg, err := s.Store.GetSSOConfig(r.Context(), s.OrgID); err == nil && cfg.RequireSSO && cfg.Enabled {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "this organization requires single sign-on; contact your administrator",
		})
		return
	}

	// One error for "no such user" and "wrong password" alike: distinguishing
	// them would let an unauthenticated caller enumerate valid accounts.
	invalid := func() {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
	}

	user, err := s.loadUserForLogin(r, email)
	if err != nil {
		invalid()
		return
	}
	if user.PasswordHash == "" || !security.VerifyPassword(user.PasswordHash, body.Password) {
		invalid()
		return
	}

	if user.TOTPEnabled {
		// A 428 tells the console "credentials accepted, second factor needed"
		// so it can reveal the code field without re-asking for the password.
		if strings.TrimSpace(body.TOTPCode) == "" {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{
				"error": "a two-factor code is required", "totp_required": true,
			})
			return
		}
		if !security.VerifyTOTP(user.TOTPSecret, body.TOTPCode, time.Now()) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "invalid two-factor code", "totp_required": true,
			})
			return
		}
	}

	token, err := s.issueSession(user, user.Role)
	if err != nil {
		writeErr(w, err)
		return
	}
	setSessionCookie(w, r, token)

	if err := s.Store.TouchUserLogin(r.Context(), user.ID); err != nil {
		s.logger().Debug("touch user login", "err", err)
	}
	s.recordAudit(r, &Principal{
		UserID: user.ID, Email: user.Email, Name: user.Name,
		Role: user.Role, RealRole: user.Role, AuthMethod: "session",
	}, storage.ActionLogin, "Console session", map[string]any{
		"method": "password", "mfa": user.TOTPEnabled,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  userViewFor(&Principal{Email: user.Email, Name: user.Name, Role: user.Role, TOTPEnabled: user.TOTPEnabled}),
	})
}

// loadUserForLogin resolves a user and falls back to a demo account when the
// emailed identity does not exist, so `dev.ps1` demo logins keep working after
// an operator renames the seeded administrator.
func (s *Server) loadUserForLogin(r *http.Request, email string) (storage.User, error) {
	user, err := s.Store.GetUserByEmail(r.Context(), s.OrgID, email)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, storage.ErrNotFound) || !demoMode() {
		return storage.User{}, err
	}
	if demoUser, derr := s.Store.DefaultUser(r.Context(), s.OrgID); derr == nil {
		// Only substitute the seeded administrator for its own address; any
		// other unknown email is simply unknown.
		if strings.EqualFold(demoUser.Email, email) {
			return demoUser, nil
		}
	}
	return storage.User{}, err
}

// authLogout clears the session cookie.
//
//	POST /api/v1/auth/logout
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if p := PrincipalFrom(r.Context()); p != nil && p.AuthMethod == "session" {
		s.recordAudit(r, p, storage.ActionLogout, "Console session", nil)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

// switchRoleRequest is the demo RBAC switcher's payload.
type switchRoleRequest struct {
	Role string `json:"role"`
}

// authSwitchRole re-issues the session with a different effective role, which is
// how the console demonstrates RBAC live: switching to Auditor immediately makes
// every mutating endpoint return 403.
//
//	POST /api/v1/auth/switch-role
//
// Guard rails that make this a demo affordance rather than a privilege
// escalation hole:
//   - it is refused unless demo mode is on;
//   - it can only ever narrow privilege. The granted role is carried in the new
//     token as real_role, and a request may not claim a role more privileged
//     than the one it already holds.
func (s *Server) authSwitchRole(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil {
		writeUnauthorized(w)
		return
	}
	if !demoMode() {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "role switching is a demo affordance and is disabled in this deployment",
		})
		return
	}

	var body switchRoleRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	target := storage.Role(strings.TrimSpace(body.Role))
	if !storage.IsValidRole(string(target)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "role must be one of admin, operator, policy_admin or auditor",
		})
		return
	}
	// The granted role is the ceiling. Re-granting the same role is allowed so
	// the banner can be dismissed by switching back to Administrator.
	if !roleAtLeast(p.RealRole, target) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "cannot switch to a role more privileged than the granted role",
		})
		return
	}

	// The granted role, not the effective one, is carried across the switch:
	// issueSession records user.Role as the token's real_role ceiling, so
	// passing `target` here would collapse the grant to the role being acted as
	// and make the demo switcher one-way.
	user := storage.User{ID: p.UserID, Email: p.Email, Name: p.Name, Role: p.RealRole}
	token, err := s.issueSession(user, target)
	if err != nil {
		writeErr(w, err)
		return
	}
	setSessionCookie(w, r, token)

	s.recordAudit(r, p, storage.ActionRoleSwitched, string(target), map[string]any{
		"from": string(p.Role), "to": string(target), "granted": string(p.RealRole),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"role":      string(target),
		"read_only": target == storage.RoleAuditor,
	})
}

// roleAtLeast reports whether `granted` permits acting as `target`. Only the
// administrator grant is a superset of every other role; the rest may only act
// as themselves or as the read-only auditor.
func roleAtLeast(granted, target storage.Role) bool {
	switch granted {
	case storage.RoleAdmin:
		return true
	default:
		return target == granted || target == storage.RoleAuditor
	}
}

// issueSession signs a session token for a user acting in a role.
func (s *Server) issueSession(user storage.User, effective storage.Role) (string, error) {
	signer := s.sessionSignerFor()
	return signer.Sign(sessionClaims{
		Subject: user.ID, Email: user.Email, Name: user.Name,
		Role: string(effective), RealRole: string(user.Role),
	})
}

/* -------------------------------------------------------------------------- */
/* TOTP enrollment                                                            */
/* -------------------------------------------------------------------------- */

// authTOTPSetup begins two-factor enrollment: it generates a secret and returns
// the otpauth URI plus the manual entry key.
//
//	POST /api/v1/auth/totp/setup
//
// The secret is stored but totp_enabled stays false until a code is verified, so
// a user who scans the QR and closes the tab has not locked themselves out.
func (s *Server) authTOTPSetup(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil || p.IsAPIKey() || p.UserID == "" {
		writeUnauthorized(w)
		return
	}
	if err := canWrite(p); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	if s.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "identity store unavailable"})
		return
	}

	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.Store.SetUserTOTP(r.Context(), s.OrgID, p.UserID, secret, false); err != nil {
		writeErr(w, err)
		return
	}

	account := p.Email
	if account == "" {
		account = p.UserID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_uri": security.TOTPUri(account, secret),
		// Repeating the parameters here lets the console render the manual-entry
		// instructions without hardcoding them and drifting from the server.
		"issuer":    security.TOTPIssuer,
		"algorithm": "SHA1",
		"digits":    security.TOTPDigits,
		"period":    security.TOTPPeriod,
		// The QR is generated client-side from otpauth_uri, so no image is
		// returned and the secret never has to survive in a cache.
	})
}

// authTOTPVerifyRequest completes enrollment with the first code.
type authTOTPVerifyRequest struct {
	Code string `json:"code"`
	// Disable turns the factor off. Requires a valid code, so a stolen session
	// cannot remove a second factor without the device.
	Disable bool `json:"disable"`
}

// authTOTPVerify completes (or disables) two-factor enrollment.
//
//	POST /api/v1/auth/totp/verify
func (s *Server) authTOTPVerify(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil || p.IsAPIKey() || p.UserID == "" {
		writeUnauthorized(w)
		return
	}
	if err := canWrite(p); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	if s.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "identity store unavailable"})
		return
	}

	var body authTOTPVerifyRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	user, err := s.Store.GetUser(r.Context(), s.OrgID, p.UserID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if strings.TrimSpace(user.TOTPSecret) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "no two-factor enrollment is in progress; start setup first",
		})
		return
	}
	// Verification is against the stored secret, so a client cannot enable 2FA
	// for a secret it invented.
	if !security.VerifyTOTP(user.TOTPSecret, body.Code, time.Now()) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid two-factor code"})
		return
	}

	if body.Disable {
		if err := s.Store.SetUserTOTP(r.Context(), s.OrgID, p.UserID, "", false); err != nil {
			writeErr(w, err)
			return
		}
		s.recordAudit(r, p, storage.Action2FADisabled, p.Email, map[string]any{"method": "totp"})
		writeJSON(w, http.StatusOK, map[string]any{"totp_enabled": false, "status": "disabled"})
		return
	}

	// Re-store the secret with the flag on: the secret was already persisted by
	// setup, and this is the transition that makes the factor active.
	if err := s.Store.SetUserTOTP(r.Context(), s.OrgID, p.UserID, user.TOTPSecret, true); err != nil {
		writeErr(w, err)
		return
	}
	s.recordAudit(r, p, storage.Action2FAEnabled, p.Email, map[string]any{"method": "totp"})
	writeJSON(w, http.StatusOK, map[string]any{"totp_enabled": true, "status": "enabled"})
}

/* -------------------------------------------------------------------------- */
/* Users                                                                      */
/* -------------------------------------------------------------------------- */

// listUsers returns the org's console identities, for the Security tab's member
// list and the audit log's actor lookup.
//
//	GET /api/v1/auth/users
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(r); !ok {
		writeUnauthorized(w)
		return
	}
	users, err := s.Store.ListUsers(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	views := make([]userView, 0, len(users))
	for _, u := range users {
		v := userViewFor(&Principal{
			Email: u.Email, Name: u.Name, Role: u.Role, TOTPEnabled: u.TOTPEnabled,
		})
		// The row's own identity fields, which a synthesized Principal cannot
		// carry: the id for keying, the login provider (local vs oidc), and the
		// last sign-in the "is this account dormant?" question needs.
		v.ID = u.ID
		v.AuthProvider = u.AuthProvider
		v.LastLoginAt = u.LastLoginAt
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": views})
}

/* -------------------------------------------------------------------------- */
/* SSO configuration                                                          */
/* -------------------------------------------------------------------------- */

// ssoView is the console-facing SSO configuration. The client secret is never
// returned; the console shows whether one is stored.
type ssoView struct {
	storage.SSOConfig
	ClientSecretSet bool `json:"client_secret_set"`
}

func ssoViewFor(cfg storage.SSOConfig) ssoView {
	return ssoView{
		SSOConfig:       cfg,
		ClientSecretSet: strings.TrimSpace(cfg.ClientSecret) != "",
	}
}

// ssoGet returns the org's OIDC configuration.
//
//	GET /api/v1/security/sso
func (s *Server) ssoGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(r); !ok {
		writeUnauthorized(w)
		return
	}
	cfg, err := s.Store.GetSSOConfig(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ssoViewFor(cfg))
}

// ssoPut updates the OIDC configuration.
//
//	PUT /api/v1/security/sso
//
// A partial update: an omitted client secret keeps the stored one, so the console
// never has to round-trip (and therefore never holds) the secret to change a
// checkbox. An explicitly empty secret clears it.
func (s *Server) ssoPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider          *string `json:"provider"`
		IssuerURL         *string `json:"issuer_url"`
		ClientID          *string `json:"client_id"`
		ClientSecret      *string `json:"client_secret"`
		EnforcedDomain    *string `json:"enforced_domain"`
		AutoProvisionRole *string `json:"auto_provision_role"`
		RequireSSO        *bool   `json:"require_sso"`
		Enabled           *bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cfg, err := s.Store.GetSSOConfig(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}

	if body.Provider != nil {
		p := strings.TrimSpace(*body.Provider)
		if !storage.IsValidSSOProvider(p) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "provider must be one of microsoft_entra, okta, google_workspace or custom_oidc",
			})
			return
		}
		cfg.Provider = p
	}
	if body.IssuerURL != nil {
		cfg.IssuerURL = strings.TrimSpace(*body.IssuerURL)
	}
	if body.ClientID != nil {
		cfg.ClientID = strings.TrimSpace(*body.ClientID)
	}
	if body.ClientSecret != nil {
		cfg.ClientSecret = *body.ClientSecret
	}
	if body.EnforcedDomain != nil {
		cfg.EnforcedDomain = strings.TrimSpace(*body.EnforcedDomain)
	}
	if body.AutoProvisionRole != nil {
		role := strings.TrimSpace(*body.AutoProvisionRole)
		if !storage.IsValidRole(role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "auto_provision_role must be one of admin, operator, policy_admin or auditor",
			})
			return
		}
		cfg.AutoProvisionRole = storage.Role(role)
	}
	if body.RequireSSO != nil {
		cfg.RequireSSO = *body.RequireSSO
	}
	if body.Enabled != nil {
		cfg.Enabled = *body.Enabled
	}

	// Enabling SSO without an issuer or client id would lock every user out at
	// the next sign-in, so it is refused at write time. Requiring SSO is stricter
	// still: it turns off the password path, so the config must be complete.
	if cfg.Enabled || cfg.RequireSSO {
		var missing []string
		if cfg.IssuerURL == "" {
			missing = append(missing, "issuer_url")
		}
		if cfg.ClientID == "" {
			missing = append(missing, "client_id")
		}
		if len(missing) > 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "cannot enable or require single sign-on without " + strings.Join(missing, " and "),
			})
			return
		}
	}

	saved, err := s.Store.SaveSSOConfig(r.Context(), s.OrgID, cfg)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ssoViewFor(saved))
}
