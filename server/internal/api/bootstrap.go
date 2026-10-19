package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/statetrack/statetrack/server/internal/security"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// BootstrapCredentials reports the console login created on a fresh install.
type BootstrapCredentials struct {
	Email    string
	Password string
	// Generated is true when the password was randomly generated and is only
	// ever shown in the server log (never written to the database in clear).
	Generated bool
}

const (
	// defaultBootstrapEmail is the identity a fresh install signs in with. It is
	// a local-only address rather than a vendor domain so a deployment never
	// looks like it shipped someone else's account.
	defaultBootstrapEmail = "admin@localhost"
	// bootstrapMarker is the placeholder written by 009_bootstrap_admin.sql. It
	// is structurally invalid as a PBKDF2 hash, so it can never authenticate;
	// its presence only tells the server "this account still needs a password".
	bootstrapMarker = "bootstrap-pending"
)

// EnsureBootstrapAdmin creates the first administrator when the org has no
// usable identities yet.
//
// Three failure modes this deliberately avoids:
//
//   - A fresh `docker compose up` with no console account would be unusable:
//     every route requires a principal and there is no sign-up form. So the
//     account is created, and its password is logged exactly once.
//   - An existing deployment must never have a password reset behind its back.
//     The function only acts when the users table holds no *usable* identity, so
//     rotating an admin password and restarting is safe.
//   - 009_bootstrap_admin.sql always inserts an `admin@localhost` row carrying
//     the bootstrap marker. Counting that row as a user made every install look
//     "past bootstrap", so setting STATETRACK_ADMIN_EMAIL created nothing and
//     left a database that could not be logged into at all. Marker rows are
//     never identities: they cannot authenticate, and completing or replacing
//     one is always safe.
//
// STATETRACK_ADMIN_EMAIL / STATETRACK_ADMIN_PASSWORD let an operator (or an
// orchestrator injecting secrets) choose the credentials instead of reading them
// from the log. A password supplied that way is not printed.
func EnsureBootstrapAdmin(
	ctx context.Context,
	store *storage.Store,
	orgID string,
	logger *slog.Logger,
) (*BootstrapCredentials, error) {
	if store == nil {
		return nil, errors.New("bootstrap: no store")
	}
	if logger == nil {
		logger = slog.Default()
	}

	email := strings.TrimSpace(strings.ToLower(envOr("STATETRACK_ADMIN_EMAIL", defaultBootstrapEmail)))
	if email == "" {
		email = defaultBootstrapEmail
	}
	supplied := strings.TrimSpace(os.Getenv("STATETRACK_ADMIN_PASSWORD"))

	// Usable identities only: a leftover marker row is not one.
	count, err := store.CountUsers(ctx, orgID)
	if err != nil {
		return nil, err
	}

	existing, getErr := store.GetUserByEmail(ctx, orgID, email)
	if getErr != nil && !errors.Is(getErr, storage.ErrNotFound) {
		return nil, getErr
	}
	needsPassword := getErr == nil &&
		(existing.PasswordHash == bootstrapMarker || strings.TrimSpace(existing.PasswordHash) == "")
	if getErr == nil && !needsPassword {
		// The requested account already works; nothing to do on this restart.
		return nil, nil
	}
	if count > 0 && getErr != nil {
		// Other usable accounts exist and this address is not one of them: the
		// deployment is past bootstrap, so leave it alone.
		return nil, nil
	}

	password := supplied
	generated := false
	if password == "" {
		password, err = generateBootstrapPassword()
		if err != nil {
			return nil, err
		}
		generated = true
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return nil, err
	}

	if getErr == nil {
		if err := store.SetUserPassword(ctx, orgID, existing.ID, hash); err != nil {
			return nil, err
		}
		// The row kept the migration's localhost address while this install was
		// told to use another one: rename it so the operator's credentials work
		// and no dead `admin@localhost` row is left behind.
		if !strings.EqualFold(existing.Email, email) {
			if err := store.SetUserEmail(ctx, orgID, existing.ID, email); err != nil {
				return nil, err
			}
			existing.Email = email
		}
		logger.Info("bootstrap administrator password initialized", "email", existing.Email)
		return &BootstrapCredentials{Email: existing.Email, Password: password, Generated: generated}, nil
	}

	user, err := store.CreateUser(ctx, orgID, storage.User{
		Email: email,
		Name:  "Administrator",
		Role:  storage.RoleAdmin,
	}, hash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Lost a race with another replica; the other one created it.
			return nil, nil
		}
		return nil, err
	}
	// The migration's unused placeholder would otherwise linger as a row nobody
	// can sign in with, and a later restart with no env override would quietly
	// complete it into a second administrator.
	if _, err := store.DeleteBootstrapPlaceholders(ctx, orgID); err != nil {
		logger.Warn("remove the unused bootstrap placeholder", "err", err)
	}
	logger.Info("bootstrap administrator created", "email", user.Email)
	return &BootstrapCredentials{Email: user.Email, Password: password, Generated: generated}, nil
}

// generateBootstrapPassword returns a 24-character URL-safe random password
// (~144 bits). It is long enough that the console's login form is the only
// practical way in, and it is only ever printed once.
func generateBootstrapPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
