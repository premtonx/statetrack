package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/statetrack/statetrack/server/internal/security"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// bootstrapTestStore returns a store plus a throwaway organization.
//
// The tests must start from the exact state a fresh install is in — no usable
// identities, but the 009 placeholder present — and the only honest way to get
// that in a shared development database is a new org per test. Deleting the
// default org's users would work and would also wipe the fleet a developer is
// looking at in the console, which is unacceptable for a test they run locally.
func bootstrapTestStore(t *testing.T) (*storage.Store, string) {
	t.Helper()
	srv, store, _ := securityTestServer(t)
	_ = srv

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// `users.email` is UNIQUE across the whole database, not per organization,
	// while these tests need a brand-new org that also contains the
	// `admin@localhost` row migration 009 writes. On a fresh database that
	// address already belongs to the default org, so the insert below would hit
	// ON CONFLICT DO NOTHING and the test would fail with "not found".
	//
	// Removing the leftover marker is safe by definition: it carries no usable
	// hash and cannot authenticate (see bootstrapMarker). Only rows still
	// carrying the marker are touched, so a developer's real administrator and
	// its fleet are unaffected.
	if _, err := store.Pool().Exec(ctx,
		`DELETE FROM users WHERE password_hash = $1`, bootstrapMarker); err != nil {
		t.Fatalf("clear bootstrap markers: %v", err)
	}

	name := "bootstrap-test-" + time.Now().UTC().Format("20060102T150405.000000000")
	var org string
	if err := store.Pool().QueryRow(ctx,
		`INSERT INTO organizations (name) VALUES ($1) RETURNING id::text`, name).Scan(&org); err != nil {
		t.Fatalf("create test org: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Every table that references organizations declares ON DELETE CASCADE,
		// so this removes the users, keys and audit rows created here with it.
		if _, err := store.Pool().Exec(ctx, `DELETE FROM organizations WHERE id = $1::uuid`, org); err != nil {
			t.Logf("cleanup org %s: %v", org, err)
		}
	})
	return store, org
}

// seedPlaceholder recreates the row 009_bootstrap_admin.sql inserts into every
// fresh database, so the tests run against the state a real install has.
func seedPlaceholder(t *testing.T, store *storage.Store, org string) storage.User {
	t.Helper()
	u, err := store.CreateUser(context.Background(), org, storage.User{
		Email: "admin@localhost", Name: "Administrator", Role: storage.RoleAdmin,
	}, bootstrapMarker)
	if err != nil {
		t.Fatalf("seed placeholder: %v", err)
	}
	return u
}

// CountUsers must not count a row that still carries the migration marker.
//
// The regression this guards: 009_bootstrap_admin.sql inserts a placeholder into
// every fresh database, so `COUNT(*) > 0` was always true and the guard meant to
// protect existing deployments skipped bootstrap on every install. A server with
// STATETRACK_ADMIN_EMAIL set then created no account at all and could not be
// logged into.
func TestCountUsersIgnoresBootstrapPlaceholder(t *testing.T) {
	store, org := bootstrapTestStore(t)
	ctx := context.Background()

	if n, err := store.CountUsers(ctx, org); err != nil {
		t.Fatalf("CountUsers: %v", err)
	} else if n != 0 {
		t.Fatalf("empty org counted %d users, want 0", n)
	}

	placeholder := seedPlaceholder(t, store, org)

	if n, err := store.CountUsers(ctx, org); err != nil {
		t.Fatalf("CountUsers: %v", err)
	} else if n != 0 {
		t.Fatalf("placeholder counted as %d usable users, want 0", n)
	}

	// A real hash must count.
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := store.SetUserPassword(ctx, org, placeholder.ID, hash); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if n, err := store.CountUsers(ctx, org); err != nil {
		t.Fatalf("CountUsers: %v", err)
	} else if n != 1 {
		t.Fatalf("usable user counted as %d, want 1", n)
	}
}

// A configured STATETRACK_ADMIN_EMAIL on a fresh install must produce a working
// account under exactly that address, with no lingering placeholder.
func TestBootstrapHonoursConfiguredEmail(t *testing.T) {
	store, org := bootstrapTestStore(t)
	ctx := context.Background()
	seedPlaceholder(t, store, org)

	t.Setenv("STATETRACK_ADMIN_EMAIL", "ReleaseTest@Example.com")
	t.Setenv("STATETRACK_ADMIN_PASSWORD", "ReleaseTest12345!")

	creds, err := EnsureBootstrapAdmin(ctx, store, org, nil)
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin: %v", err)
	}
	if creds == nil {
		t.Fatal("EnsureBootstrapAdmin did nothing; the install would have no usable login")
	}
	if creds.Generated {
		t.Error("password was generated even though STATETRACK_ADMIN_PASSWORD was set")
	}
	if !strings.EqualFold(creds.Email, "releasetest@example.com") {
		t.Errorf("email = %q, want releasetest@example.com", creds.Email)
	}

	// The credentials must actually authenticate. This is the end-to-end check
	// that the login path reads what bootstrap wrote: the previous bug was a
	// column list that never selected password_hash, so every login failed no
	// matter what was stored.
	user, err := store.GetUserByEmail(ctx, org, "releasetest@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if user.PasswordHash == "" {
		t.Fatal("GetUserByEmail returned no password hash; login cannot ever succeed")
	}
	if !security.VerifyPassword(user.PasswordHash, "ReleaseTest12345!") {
		t.Fatal("stored hash does not verify the configured password")
	}

	// The old placeholder address must be gone, or a later restart without the
	// env override would quietly complete it into a second administrator.
	if _, err := store.GetUserByEmail(ctx, org, "admin@localhost"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("the admin@localhost placeholder survived bootstrap (err = %v)", err)
	}

	// Idempotent: a restart must not rewrite the password.
	t.Setenv("STATETRACK_ADMIN_PASSWORD", "some-other-password")
	again, err := EnsureBootstrapAdmin(ctx, store, org, nil)
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin (restart): %v", err)
	}
	if again != nil {
		t.Fatalf("bootstrap re-ran on restart: %+v", again)
	}
	if user, err := store.GetUserByEmail(ctx, org, "releasetest@example.com"); err != nil {
		t.Fatal(err)
	} else if !security.VerifyPassword(user.PasswordHash, "ReleaseTest12345!") {
		t.Fatal("a restart replaced the administrator's working password")
	}
}

// With no configuration at all, a fresh install must still be usable: a
// generated password under the documented default address.
func TestBootstrapGeneratesDefaultAdmin(t *testing.T) {
	store, org := bootstrapTestStore(t)
	ctx := context.Background()
	seedPlaceholder(t, store, org)

	t.Setenv("STATETRACK_ADMIN_EMAIL", "")
	t.Setenv("STATETRACK_ADMIN_PASSWORD", "")

	creds, err := EnsureBootstrapAdmin(ctx, store, org, nil)
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin: %v", err)
	}
	if creds == nil {
		t.Fatal("no administrator was created on a fresh install")
	}
	if !creds.Generated {
		t.Error("Generated = false, want true when no password is supplied")
	}
	if len(creds.Password) < 16 {
		t.Errorf("generated password is %d chars, want a long one", len(creds.Password))
	}
	if creds.Email != "admin@localhost" {
		t.Errorf("email = %q, want admin@localhost", creds.Email)
	}
	if !security.VerifyPassword(mustHashOf(t, store, org, creds.Email), creds.Password) {
		t.Fatal("the generated password does not verify against the stored hash")
	}
}

// mustHashOf reads the stored hash for an address, failing the test if it is
// absent — which is itself the login-blocking bug.
func mustHashOf(t *testing.T, store *storage.Store, org, email string) string {
	t.Helper()
	u, err := store.GetUserByEmail(context.Background(), org, email)
	if err != nil {
		t.Fatalf("GetUserByEmail(%s): %v", email, err)
	}
	if u.PasswordHash == "" {
		t.Fatalf("%s has no password hash stored", email)
	}
	return u.PasswordHash
}

// An operator who deletes every account has made a deliberate choice; a restart
// must not resurrect one. This is the behaviour the original guard existed for,
// and it must survive the fix.
func TestBootstrapDoesNotResurrectDeletedAccounts(t *testing.T) {
	store, org := bootstrapTestStore(t)
	ctx := context.Background()

	t.Setenv("STATETRACK_ADMIN_EMAIL", "")
	t.Setenv("STATETRACK_ADMIN_PASSWORD", "")

	// A real, working identity that is not the bootstrap address.
	hash, err := security.HashPassword("an-existing-operator-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := store.CreateUser(ctx, org, storage.User{
		Email: "sre@example.com", Name: "SRE", Role: storage.RoleOperator,
	}, hash); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	creds, err := EnsureBootstrapAdmin(ctx, store, org, nil)
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin: %v", err)
	}
	if creds != nil {
		t.Fatalf("bootstrap created a second admin on a populated org: %+v", creds)
	}
	if _, err := store.GetUserByEmail(ctx, org, "admin@localhost"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("a placeholder was completed on an org that is past bootstrap")
	}
}
