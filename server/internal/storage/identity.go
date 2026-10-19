package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Role is an RBAC grant. Roles are ordered from most to least privileged for
// display, but privilege is a closed set rather than a rank: `policy_admin` is
// not "between" operator and admin, it is a different set of permissions, so
// callers switch on the value instead of comparing magnitudes.
type Role string

const (
	RoleAdmin       Role = "admin"
	RoleOperator    Role = "operator"
	RolePolicyAdmin Role = "policy_admin"
	// RoleAuditor is strictly read-only. It is enforced in middleware, not just
	// hidden in the UI, because the point of the role is that a compliance
	// reviewer cannot change the system they are reviewing.
	RoleAuditor Role = "auditor"
)

// Roles is the closed set the API validates against, in display order.
var Roles = []Role{RoleAdmin, RoleOperator, RolePolicyAdmin, RoleAuditor}

// IsValidRole reports whether a string is a known role, so an API caller cannot
// persist a typo'd role that would then fail a CHECK constraint as a 500.
func IsValidRole(r string) bool {
	for _, known := range Roles {
		if string(known) == r {
			return true
		}
	}
	return false
}

// CanWrite reports whether the role may perform mutating requests. Auditor is
// the only read-only role; the others differ in what they own, which handlers
// check individually where it matters.
func (r Role) CanWrite() bool { return r != RoleAuditor }

// RoleLabel is the human-readable name the console shows.
func (r Role) RoleLabel() string {
	switch r {
	case RoleAdmin:
		return "Administrator"
	case RoleOperator:
		return "SRE Operator"
	case RolePolicyAdmin:
		return "Policy Admin"
	case RoleAuditor:
		return "Compliance Auditor"
	default:
		return string(r)
	}
}

// AuthProvider is how an identity authenticates.
const (
	AuthProviderLocal = "local"
	AuthProviderOIDC  = "oidc"
)

// User is a console identity.
type User struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	Role         Role       `json:"role"`
	PasswordHash string     `json:"-"`
	TOTPSecret   string     `json:"-"`
	TOTPEnabled  bool       `json:"totp_enabled"`
	AuthProvider string     `json:"auth_provider"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Initials derives the two-letter avatar text the console renders. Falls back to
// the email's first character so a user with no display name still gets a
// sensible avatar rather than an empty circle.
func (u User) Initials() string {
	name := strings.TrimSpace(u.Name)
	if name != "" {
		parts := strings.Fields(name)
		if len(parts) >= 2 {
			return strings.ToUpper(parts[0][:1] + parts[len(parts)-1][:1])
		}
		if len(parts[0]) >= 1 {
			return strings.ToUpper(parts[0][:1])
		}
	}
	if u.Email != "" {
		return strings.ToUpper(u.Email[:1])
	}
	return "?"
}

// ListUsers returns every console identity in the org.
func (s *Store) ListUsers(ctx context.Context, orgID string) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, email, name, role, totp_enabled, auth_provider, last_login_at, created_at
		FROM users WHERE org_id = $1::uuid
		ORDER BY created_at`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.TOTPEnabled,
			&u.AuthProvider, &u.LastLoginAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// userColumns is the column list every identity lookup outside the list view
// selects.
//
// password_hash and totp_secret are here because the login handler compares
// against them: without them in the SELECT, scanUser left PasswordHash empty and
// every login failed with "invalid email or password" while the hash sat in the
// database. COALESCE keeps a NULL (an SSO-only identity, or one whose password
// has not been set yet) as "". Both carry `json:"-"`, so a handler that serializes
// a User still cannot leak them; ListUsers deliberately selects its own narrower
// list so a fleet-wide roster never reads secrets at all.
const userColumns = `id::text, email, name, role, totp_enabled, auth_provider,
	last_login_at, created_at,
	COALESCE(password_hash, '') AS password_hash,
	COALESCE(totp_secret, '') AS totp_secret`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.TOTPEnabled,
		&u.AuthProvider, &u.LastLoginAt, &u.CreatedAt,
		&u.PasswordHash, &u.TOTPSecret)
	return u, err
}

// GetUserByEmail resolves an identity for login. Email is matched
// case-insensitively because a user typing "PK@StateTrack.io" must not fail to
// find the account "pk@statetrack.io".
func (s *Store) GetUserByEmail(ctx context.Context, orgID, email string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE org_id = $1::uuid AND lower(email) = lower($2)`, orgID, strings.TrimSpace(email)))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// GetUser returns one identity by id.
func (s *Store) GetUser(ctx context.Context, orgID, id string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE org_id = $1::uuid AND id = $2::uuid`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// DefaultUser returns the org's primary administrator — the lowest-created
// admin. Used by the dev auto-session so the console logs in as a real seeded
// account instead of a synthetic one, which keeps "who is the actor?" honest.
func (s *Store) DefaultUser(ctx context.Context, orgID string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE org_id = $1::uuid AND role = 'admin'
		ORDER BY created_at LIMIT 1`, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("default user: %w", err)
	}
	return u, nil
}

// CountUsers returns how many console identities exist in the org. The server
// uses it to decide whether a fresh deployment still needs its bootstrap
// administrator, which is the difference between "first boot" and "an operator
// deleted every account".
//
// Rows still carrying the bootstrap marker are not counted: they cannot
// authenticate, so they are not identities yet. Counting them made a fresh
// install look "past bootstrap" whenever 009_bootstrap_admin.sql had inserted
// its placeholder — which is every install — and silently skipped creating the
// administrator the operator asked for with STATETRACK_ADMIN_EMAIL.
func (s *Store) CountUsers(ctx context.Context, orgID string) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE org_id = $1::uuid
		  AND COALESCE(password_hash, '') <> 'bootstrap-pending'`,
		orgID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// CreateUser inserts a console identity with an already-hashed password.
//
// The hash is a parameter rather than computed here so the storage layer never
// depends on the password KDF and so the bootstrap path can hash once with the
// same parameters as a login.
func (s *Store) CreateUser(ctx context.Context, orgID string, u User, passwordHash string) (User, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (org_id, email, name, role, password_hash, auth_provider)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5, ''), $6)
		ON CONFLICT (email) DO NOTHING
		RETURNING id::text`,
		orgID, strings.TrimSpace(strings.ToLower(u.Email)), u.Name, string(u.Role),
		passwordHash, AuthProviderLocal).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// The account already exists (a concurrent boot, or a re-run); return
		// the stored row rather than failing the server start.
		return s.GetUserByEmail(ctx, orgID, u.Email)
	}
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return s.GetUser(ctx, orgID, id)
}

// SetUserPassword rotates a password hash.
func (s *Store) SetUserPassword(ctx context.Context, orgID, id, passwordHash string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET password_hash = NULLIF($3, '')
		WHERE org_id = $1::uuid AND id = $2::uuid`, orgID, id, passwordHash)
	if err != nil {
		return fmt.Errorf("set user password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserEmail changes an identity's login address. Used only by the bootstrap
// path, when the migration's placeholder row is claimed for the address the
// operator configured with STATETRACK_ADMIN_EMAIL.
//
// The unique index on lower(email) is the real guard here: if the target address
// is already taken, the update fails rather than silently merging two accounts.
func (s *Store) SetUserEmail(ctx context.Context, orgID, id, email string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET email = lower(trim($3))
		WHERE org_id = $1::uuid AND id = $2::uuid`,
		orgID, id, email)
	if err != nil {
		return fmt.Errorf("set user email: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteBootstrapPlaceholders removes rows that still carry the migration's
// unusable password marker.
//
// These rows cannot authenticate, so they are not accounts: they exist only to
// hand the server a row to complete on first boot. Once the bootstrap
// administrator has been created under a different address, the placeholder is
// dead weight — and worse, a later restart with no STATETRACK_ADMIN_EMAIL would
// find it and quietly mint a second, generated-password administrator.
func (s *Store) DeleteBootstrapPlaceholders(ctx context.Context, orgID string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM users
		WHERE org_id = $1::uuid AND COALESCE(password_hash, '') = 'bootstrap-pending'`,
		orgID)
	if err != nil {
		return 0, fmt.Errorf("delete bootstrap placeholders: %w", err)
	}
	return tag.RowsAffected(), nil
}

// UpdateUserRole changes an identity's RBAC grant and returns the updated row.
func (s *Store) UpdateUserRole(ctx context.Context, orgID, id string, role Role) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET role = $3 WHERE org_id = $1::uuid AND id = $2::uuid
		RETURNING `+userColumns, orgID, id, string(role)))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("update user role: %w", err)
	}
	return u, nil
}

// SetUserTOTP stores the TOTP secret and whether 2FA is active. The secret is
// written at setup and only "enabled" after a code has been verified, so a
// half-finished enrollment cannot lock a user out of their own account.
func (s *Store) SetUserTOTP(ctx context.Context, orgID, id, secret string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET totp_secret = NULLIF($3, ''), totp_enabled = $4
		WHERE org_id = $1::uuid AND id = $2::uuid`, orgID, id, secret, enabled)
	if err != nil {
		return fmt.Errorf("set user totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchUserLogin records a successful authentication.
func (s *Store) TouchUserLogin(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET last_login_at = NOW() WHERE id = $1::uuid`, id); err != nil {
		return fmt.Errorf("touch user login: %w", err)
	}
	return nil
}

/* -------------------------------------------------------------------------- */
/* API keys                                                                   */
/* -------------------------------------------------------------------------- */

// APIKey is a scoped machine credential. The secret itself is never part of
// this struct: only its hash reaches the database, and only its prefix reaches
// the console.
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Role       Role       `json:"role"`
	Scopes     []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Active reports whether the key may authenticate right now: not revoked, not
// past its expiry. Checked in one place so "why is my key rejected?" has exactly
// one answer.
func (k APIKey) Active(now time.Time) bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
		return false
	}
	return true
}

// ListAPIKeys returns every key (including revoked ones, which the console
// shows greyed out as history rather than hiding).
func (s *Store) ListAPIKeys(ctx context.Context, orgID string) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, name, key_prefix, role, scopes, last_used_at, expires_at, revoked_at, created_at
		FROM api_keys WHERE org_id = $1::uuid
		ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()
	return scanAPIKeys(rows)
}

func scanAPIKeys(rows pgx.Rows) ([]APIKey, error) {
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.Role, &k.Scopes,
			&k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CreateAPIKey stores a key's hash and returns the row. The caller passes the
// hash, never the secret, so the plaintext exists only in the HTTP response.
func (s *Store) CreateAPIKey(ctx context.Context, orgID string, k APIKey, keyHash string) (APIKey, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (org_id, name, key_prefix, key_hash, role, scopes, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
		RETURNING id::text, name, key_prefix, role, scopes, last_used_at, expires_at, revoked_at, created_at`,
		orgID, k.Name, k.KeyPrefix, keyHash, string(k.Role), k.Scopes, k.ExpiresAt).
		Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.Role, &k.Scopes,
			&k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt)
	if err != nil {
		return APIKey{}, fmt.Errorf("create api key: %w", err)
	}
	return k, nil
}

// AuthenticateAPIKey resolves a hashed key to its row. Only non-revoked keys are
// returned, so a revoked credential is indistinguishable from an unknown one to
// a caller probing with secrets.
func (s *Store) AuthenticateAPIKey(ctx context.Context, keyHash string) (APIKey, error) {
	var k APIKey
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, name, key_prefix, role, scopes, last_used_at, expires_at, revoked_at, created_at
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`, keyHash).
		Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.Role, &k.Scopes,
			&k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("authenticate api key: %w", err)
	}
	return k, nil
}

// TouchAPIKeyLastUsed records usage. Best-effort at the call site: failing to
// stamp a timestamp must never reject an otherwise valid request.
func (s *Store) TouchAPIKeyLastUsed(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET last_used_at = NOW() WHERE id = $1::uuid`, id); err != nil {
		return fmt.Errorf("touch api key: %w", err)
	}
	return nil
}

// RevokeAPIKey marks a key revoked. A soft delete is deliberate: the audit log
// references the key, and "which credential was revoked and when" must stay
// answerable.
func (s *Store) RevokeAPIKey(ctx context.Context, orgID, id string) (APIKey, error) {
	var k APIKey
	err := s.pool.QueryRow(ctx, `
		UPDATE api_keys SET revoked_at = NOW()
		WHERE org_id = $1::uuid AND id = $2::uuid AND revoked_at IS NULL
		RETURNING id::text, name, key_prefix, role, scopes, last_used_at, expires_at, revoked_at, created_at`,
		orgID, id).
		Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.Role, &k.Scopes,
			&k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("revoke api key: %w", err)
	}
	return k, nil
}

/* -------------------------------------------------------------------------- */
/* Enrollment tokens                                                          */
/* -------------------------------------------------------------------------- */

// EnrollmentToken is the bootstrap secret an agent installs with.
type EnrollmentToken struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	MaxUses     *int       `json:"max_uses,omitempty"`
	UsesCount   int        `json:"uses_count"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Exhausted reports whether the token has hit its use cap. A nil cap means
// unlimited, which the console warns about.
func (t EnrollmentToken) Exhausted() bool {
	return t.MaxUses != nil && t.UsesCount >= *t.MaxUses
}

// Active reports whether the token can still enroll an agent.
func (t EnrollmentToken) Active(now time.Time) bool {
	if t.RevokedAt != nil || t.Exhausted() {
		return false
	}
	if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
		return false
	}
	return true
}

// ListEnrollmentTokens returns every token, newest first.
func (s *Store) ListEnrollmentTokens(ctx context.Context, orgID string) ([]EnrollmentToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, name, token_prefix, max_uses, uses_count, expires_at, revoked_at, created_at
		FROM enrollment_tokens WHERE org_id = $1::uuid
		ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list enrollment tokens: %w", err)
	}
	defer rows.Close()

	out := []EnrollmentToken{}
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.MaxUses, &t.UsesCount,
			&t.ExpiresAt, &t.RevokedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateEnrollmentToken stores a token's hash and returns the row.
func (s *Store) CreateEnrollmentToken(ctx context.Context, orgID string, t EnrollmentToken, tokenHash string) (EnrollmentToken, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO enrollment_tokens (org_id, name, token_prefix, token_hash, max_uses, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		RETURNING id::text, name, token_prefix, max_uses, uses_count, expires_at, revoked_at, created_at`,
		orgID, t.Name, t.TokenPrefix, tokenHash, t.MaxUses, t.ExpiresAt).
		Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.MaxUses, &t.UsesCount,
			&t.ExpiresAt, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		return EnrollmentToken{}, fmt.Errorf("create enrollment token: %w", err)
	}
	return t, nil
}

// RevokeEnrollmentToken marks a token revoked (soft delete, for the audit trail).
func (s *Store) RevokeEnrollmentToken(ctx context.Context, orgID, id string) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := s.pool.QueryRow(ctx, `
		UPDATE enrollment_tokens SET revoked_at = NOW()
		WHERE org_id = $1::uuid AND id = $2::uuid AND revoked_at IS NULL
		RETURNING id::text, name, token_prefix, max_uses, uses_count, expires_at, revoked_at, created_at`,
		orgID, id).
		Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.MaxUses, &t.UsesCount,
			&t.ExpiresAt, &t.RevokedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollmentToken{}, ErrNotFound
	}
	if err != nil {
		return EnrollmentToken{}, fmt.Errorf("revoke enrollment token: %w", err)
	}
	return t, nil
}

/* -------------------------------------------------------------------------- */
/* Control-plane audit log                                                    */
/* -------------------------------------------------------------------------- */

// AuditLog is one administrative action. Append-only: the store exposes no
// update or delete, so the trail cannot be rewritten through the application.
type AuditLog struct {
	ID         int64          `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	ActorEmail string         `json:"actor_email"`
	ActorRole  string         `json:"actor_role"`
	Action     string         `json:"action"`
	Target     string         `json:"target"`
	SourceIP   string         `json:"source_ip"`
	Details    map[string]any `json:"details"`
}

// Audit actions. Stable dotted identifiers rather than display strings, because
// they are a filter key in the console and a match target for SIEM rules.
const (
	ActionLogin         = "auth.login"
	ActionLogout        = "auth.logout"
	ActionRoleSwitched  = "auth.role_switched"
	Action2FAEnabled    = "auth.2fa_enabled"
	Action2FADisabled   = "auth.2fa_disabled"
	ActionRuleApplied   = "rule.applied"
	ActionRuleDismissed = "rule.dismissed"
	// Custom watched targets authored in the console. Distinct verbs from
	// rule.applied because an auditor wants "who widened the watch scope?"
	// separated from "who accepted a discovery suggestion?".
	ActionWatchRuleCreated = "rule.watch_created"
	ActionWatchRuleDeleted = "rule.watch_deleted"
	ActionIntegrationUpd   = "integration.updated"
	ActionAPIKeyCreated    = "apikey.created"
	ActionAPIKeyRevoked    = "apikey.revoked"
	ActionTokenCreated     = "token.created"
	ActionTokenRevoked     = "agent.revoked"
	ActionSSOUpdated       = "sso.updated"
	ActionSettingsUpd      = "settings.updated"
	ActionForensicSet      = "host.forensic_enabled"
	// ITSM change-ticket bridge. Kept as distinct verbs rather than folded into
	// integration.updated because an auditor filtering the trail wants "who
	// changed the compliance control?" separated from "who edited a webhook?".
	ActionITSMSettingsUpd    = "itsm.settings_updated"
	ActionITSMTicketSynced   = "itsm.tickets_synced"
	ActionITSMTicketUpserted = "itsm.ticket_recorded"
	ActionITSMTicketDeleted  = "itsm.ticket_deleted"

	// AI analysis gateway. A distinct verb from integration.updated because the
	// provider selection and the credential that goes with it are a security-
	// relevant control ("which model saw our diffs?"), and an auditor filtering
	// the trail needs that separated from a webhook URL edit.
	ActionAISettingsUpdated = "ai.settings_updated"
)

// AppendAuditLog writes one row. Callers treat failure as best-effort: an audit
// write must never turn a successful administrative action into an error the
// user has to retry (which would double-apply it), but it is logged loudly.
func (s *Store) AppendAuditLog(ctx context.Context, e AuditLog) error {
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO control_plane_audit_logs
		    (actor_email, actor_role, action, target, source_ip, details)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		e.ActorEmail, e.ActorRole, e.Action, e.Target, e.SourceIP, raw)
	if err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}

// ListAuditLogs returns the newest entries first. `action` and `actor` narrow
// the result; both are matched exactly so a filtered view is a predictable
// index scan rather than a substring search over the whole trail.
func (s *Store) ListAuditLogs(ctx context.Context, action, actor string, limit int) ([]AuditLog, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, occurred_at, actor_email, actor_role, action, target, source_ip, details
		FROM control_plane_audit_logs
		WHERE ($1 = '' OR action = $1) AND ($2 = '' OR actor_email = $2)
		ORDER BY occurred_at DESC, id DESC
		LIMIT $3`, action, actor, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	out := []AuditLog{}
	for rows.Next() {
		var e AuditLog
		var raw []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorEmail, &e.ActorRole,
			&e.Action, &e.Target, &e.SourceIP, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			// A malformed details blob must not blank the whole row: the audit
			// entry's existence (who did what, when) is the load-bearing part.
			if err := json.Unmarshal(raw, &e.Details); err != nil {
				e.Details = map[string]any{}
			}
		}
		if e.Details == nil {
			e.Details = map[string]any{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

/* -------------------------------------------------------------------------- */
/* SSO configuration                                                          */
/* -------------------------------------------------------------------------- */

// ProviderSSO is the integration_settings provider key for OIDC SSO.
const ProviderSSO = "sso"

// SSOProvider identifies the IdP. The value drives the setup hints the console
// shows (issuer URL shape, claim mapping) rather than runtime behaviour, which
// is plain OIDC for all four.
const (
	SSOMicrosoftEntra = "microsoft_entra"
	SSOOkta           = "okta"
	SSOGoogle         = "google_workspace"
	SSOCustom         = "custom_oidc"
)

// SSOConfig is the enterprise single-sign-on configuration.
type SSOConfig struct {
	Provider  string `json:"provider"`
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
	// ClientSecret is stored but never returned by the API; the console shows
	// whether one is set instead of the value.
	ClientSecret string `json:"client_secret"`
	// EnforcedDomain restricts sign-in to one email domain, so a personal
	// account at the same IdP cannot be used to reach the console.
	EnforcedDomain string `json:"enforced_domain"`
	// AutoProvisionRole is the role granted to a first-time SSO user.
	AutoProvisionRole Role `json:"auto_provision_role"`
	// RequireSSO disables local password sign-in for the org.
	RequireSSO bool      `json:"require_sso"`
	Enabled    bool      `json:"enabled"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

// SSOProviderOptions is the closed set the console renders.
var SSOProviderOptions = []string{SSOMicrosoftEntra, SSOOkta, SSOGoogle, SSOCustom}

// IsValidSSOProvider reports whether the string is a known provider.
func IsValidSSOProvider(p string) bool {
	for _, known := range SSOProviderOptions {
		if known == p {
			return true
		}
	}
	return false
}

// DefaultSSOConfig returns the configuration shown before anything is saved.
func DefaultSSOConfig() SSOConfig {
	return SSOConfig{
		Provider:          SSOMicrosoftEntra,
		AutoProvisionRole: RoleAuditor,
		EnforcedDomain:    "statetrack.io",
		RequireSSO:        false,
		Enabled:           false,
	}
}

// GetSSOConfig loads the org's SSO configuration, falling back to the defaults.
func (s *Store) GetSSOConfig(ctx context.Context, orgID string) (SSOConfig, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT settings FROM integration_settings
		WHERE org_id = $1::uuid AND provider = $2`, orgID, ProviderSSO).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultSSOConfig(), nil
	}
	if err != nil {
		return SSOConfig{}, fmt.Errorf("load sso config: %w", err)
	}

	// Start from defaults so a row written by an older build still decodes into
	// a complete struct rather than silently flipping a security toggle.
	cfg := DefaultSSOConfig()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return SSOConfig{}, fmt.Errorf("decode sso config: %w", err)
	}
	if !IsValidSSOProvider(cfg.Provider) {
		cfg.Provider = DefaultSSOConfig().Provider
	}
	// An empty auto-provision role would mint users with no grant; auditor is
	// the safe default (least privilege) rather than admin.
	if !IsValidRole(string(cfg.AutoProvisionRole)) {
		cfg.AutoProvisionRole = RoleAuditor
	}
	return cfg, nil
}

// SaveSSOConfig upserts the org's SSO configuration.
func (s *Store) SaveSSOConfig(ctx context.Context, orgID string, cfg SSOConfig) (SSOConfig, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return SSOConfig{}, fmt.Errorf("encode sso config: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO integration_settings (org_id, provider, settings, updated_at)
		VALUES ($1::uuid, $2, $3, NOW())
		ON CONFLICT (org_id, provider)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		orgID, ProviderSSO, raw); err != nil {
		return SSOConfig{}, fmt.Errorf("save sso config: %w", err)
	}
	cfg.UpdatedAt = time.Now().UTC()
	return cfg, nil
}
