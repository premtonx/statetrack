package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/statetrack/statetrack/server/internal/storage"
)

// TestCreateWatchRuleEndpointRoundTrip exercises POST /api/v1/rules against a
// real database: the rule must be stored, decorated for the list view, and leave
// a control-plane audit row naming the watched path.
//
// This is the endpoint the console's "+ Add Watched Target" modal calls, so the
// assertions are the ones an operator depends on: the row exists afterwards, the
// audit trail answers "who started watching this?", and a failure leaves neither
// behind.
func TestCreateWatchRuleEndpointRoundTrip(t *testing.T) {
	srv, store, org := securityTestServer(t)
	t.Setenv("STATETRACK_AUTH_DISABLED", "0")

	ctx := context.Background()
	admin := &Principal{
		UserID: "00000000-0000-4000-8000-0000000000cc",
		Email:  "pk@statetrack.io", Name: "P. K",
		Role: storage.RoleAdmin, RealRole: storage.RoleAdmin,
		AuthMethod: "session",
	}

	// A unique name keeps the assertion independent of the shared development
	// database's seeded rules.
	name := "endpoint-test-" + time.Now().UTC().Format("20060102T150405.000000000")
	pattern := "iis://apppool/" + name
	body := fmt.Sprintf(
		`{"host_scope":"*","target_type":"iis_apppool","pattern":%q,"level":1,"diff":true,"name":%q}`,
		pattern, name)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, admin))
	rec := httptest.NewRecorder()

	handler := srv.mutation(storage.ActionWatchRuleCreated,
		bodyTarget("pattern"), srv.createWatchRule)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/rules = %d: %s", rec.Code, rec.Body.String())
	}

	var created watchRuleView
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" || created.Pattern != pattern {
		t.Fatalf("created view = %+v", created)
	}
	if created.HostScope != storage.FleetScope {
		t.Errorf("host scope = %q, want the fleet scope back", created.HostScope)
	}
	if created.TargetLabel != "IIS App Pool" || created.ImpactLabel != "Level 1 Critical" {
		t.Errorf("decorations = %q / %q, want the catalog labels",
			created.TargetLabel, created.ImpactLabel)
	}
	t.Cleanup(func() {
		_, _ = store.DeleteWatchRule(context.Background(), org, created.ID)
	})

	// The row must be readable through the same listing the console renders.
	rules, err := store.ListWatchRules(ctx, org, "iis_apppool", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		if r.ID == created.ID {
			found = true
			if r.Level != storage.ImpactLevelCritical || !r.Diff {
				t.Errorf("stored rule = level %d, diff %v; want critical with a diff",
					r.Level, r.Diff)
			}
			if r.CreatedBy != admin.Email {
				t.Errorf("created_by = %q, want the authoring identity", r.CreatedBy)
			}
		}
	}
	if !found {
		t.Fatal("the created watched target is missing from the list endpoint's source")
	}

	logs, err := store.ListAuditLogs(ctx, storage.ActionWatchRuleCreated, admin.Email, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("no audit row was written for a watched target")
	}
	if logs[0].Target != pattern {
		t.Errorf("audit target = %q, want the watched path %q", logs[0].Target, pattern)
	}
	if got, _ := logs[0].Details["target_type"].(string); got != "iis_apppool" {
		t.Errorf("audit details.target_type = %q, want iis_apppool", got)
	}
}

// TestDeleteWatchRuleAuditsThePattern proves a removal is audited as
// "stopped watching <path>" rather than "deleted <uuid>". The route only knows
// the id, so this also pins the handler→wrapper target hand-off.
func TestDeleteWatchRuleAuditsThePattern(t *testing.T) {
	srv, store, org := securityTestServer(t)
	t.Setenv("STATETRACK_AUTH_DISABLED", "0")

	ctx := context.Background()
	admin := &Principal{
		UserID: "00000000-0000-4000-8000-0000000000cd",
		Email:  "pk@statetrack.io", Name: "P. K",
		Role: storage.RoleAdmin, RealRole: storage.RoleAdmin,
		AuthMethod: "session",
	}

	name := "endpoint-delete-" + time.Now().UTC().Format("20060102T150405.000000000")
	pattern := "db://postgres/settings_db/tables/public." + name
	withDiff := true
	rule, err := store.CreateWatchRule(ctx, org, admin.Email, storage.WatchRuleInput{
		HostScope:  storage.FleetScope,
		TargetType: "database_table",
		Pattern:    pattern,
		Level:      storage.ImpactLevelCritical,
		Diff:       &withDiff,
		Name:       name,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/"+rule.ID, nil)
	req.SetPathValue("id", rule.ID)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, admin))
	rec := httptest.NewRecorder()

	handler := srv.mutation(storage.ActionWatchRuleDeleted,
		pathTarget("id"), srv.deleteWatchRule)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/rules/{id} = %d: %s", rec.Code, rec.Body.String())
	}

	logs, err := store.ListAuditLogs(ctx, storage.ActionWatchRuleDeleted, admin.Email, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("no audit row was written for a removed watched target")
	}
	if logs[0].Target != pattern {
		t.Errorf("audit target = %q, want the watched path %q", logs[0].Target, pattern)
	}
	if got, _ := logs[0].Details["rule_id"].(string); got != rule.ID {
		t.Errorf("audit details.rule_id = %q, want %q", got, rule.ID)
	}
}

// TestCreateWatchRuleRejectsUnknownHost proves a bad host scope is a 400 with a
// message the modal can show, not a 500 and not a silently fleet-wide rule.
func TestCreateWatchRuleRejectsUnknownHost(t *testing.T) {
	srv, _, _ := securityTestServer(t)
	t.Setenv("STATETRACK_AUTH_DISABLED", "0")

	admin := &Principal{Role: storage.RoleAdmin, RealRole: storage.RoleAdmin,
		Email: "pk@statetrack.io", AuthMethod: "session"}
	body := `{"host_scope":"no-such-host","target_type":"file","pattern":"/etc/app.conf","level":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, admin))
	rec := httptest.NewRecorder()

	srv.createWatchRule(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("body = %q, want it to name the missing host", rec.Body.String())
	}
}
