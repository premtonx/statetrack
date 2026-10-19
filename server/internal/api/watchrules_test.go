package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/statetrack/statetrack/server/internal/storage"
)

// The Target Type catalog is served to the browser, so its own consistency is a
// contract: every entry must be something the store will accept, and every
// target type the store knows must be offered. A type the store accepts but the
// modal omits is a feature nobody can reach; a type the modal offers but the
// store rejects is a form that always fails on submit.
func TestWatchTargetCatalogMatchesStorage(t *testing.T) {
	offered := map[string]bool{}
	for _, tt := range watchTargetCatalog {
		if tt.Value == "" || tt.Label == "" || tt.Placeholder == "" {
			t.Errorf("catalog entry %+v is missing a value, label or placeholder", tt)
		}
		if tt.Help == "" {
			t.Errorf("%s has no help text; the operator cannot tell what it watches", tt.Value)
		}
		if offered[tt.Value] {
			t.Errorf("%s is offered twice", tt.Value)
		}
		offered[tt.Value] = true

		// The placeholder is the example an operator copies. It must survive the
		// server's own validation, otherwise the modal teaches a bad rule.
		in := storage.WatchRuleInput{TargetType: tt.Value, Pattern: tt.Placeholder, Level: 1}
		if err := in.Validate(); err != nil {
			t.Errorf("%s placeholder %q fails validation: %v", tt.Value, tt.Placeholder, err)
		}
	}

	for _, want := range []string{
		storage.WatchTypeFile, storage.WatchTypeDirectory, storage.WatchTypeIISPool,
		storage.WatchTypeIISSite, storage.WatchTypeDBTable, storage.WatchTypeDBSchema,
		storage.WatchTypeDBParams, storage.WatchTypeRegistry, storage.WatchTypeService,
		storage.WatchTypeK8sObject,
	} {
		if !offered[want] {
			t.Errorf("target type %q is supported by the server but not offered in the builder", want)
		}
	}
}

// Platform scoping keeps the modal from suggesting an IIS pool on a Linux host.
func TestWatchTargetCatalogPlatforms(t *testing.T) {
	byValue := map[string]watchTargetType{}
	for _, tt := range watchTargetCatalog {
		byValue[tt.Value] = tt
	}
	for _, windowsOnly := range []string{
		storage.WatchTypeIISPool, storage.WatchTypeIISSite, storage.WatchTypeRegistry,
	} {
		tt := byValue[windowsOnly]
		if len(tt.Platforms) != 1 || tt.Platforms[0] != "windows" {
			t.Errorf("%s platforms = %v, want [windows]", windowsOnly, tt.Platforms)
		}
	}
	// Files, databases and Kubernetes objects are cross-platform; restricting
	// them would hide a valid option on the other OS.
	for _, crossPlatform := range []string{
		storage.WatchTypeFile, storage.WatchTypeDirectory,
		storage.WatchTypeDBTable, storage.WatchTypeK8sObject,
	} {
		if p := byValue[crossPlatform].Platforms; len(p) != 0 {
			t.Errorf("%s is restricted to %v, but it is not Windows-only", crossPlatform, p)
		}
	}
}

func TestWatchImpactLevels(t *testing.T) {
	levels := watchImpactLevels()
	if len(levels) != 2 {
		t.Fatalf("builder offers %d levels, want 2 (critical and drift)", len(levels))
	}
	if levels[0]["value"] != storage.ImpactLevelCritical {
		t.Errorf("first level = %v, want critical", levels[0]["value"])
	}
	if levels[0]["diff"] != true || levels[1]["diff"] != false {
		t.Errorf("capture modes = %v/%v, want full diff then hash only",
			levels[0]["diff"], levels[1]["diff"])
	}
	if watchTargetCatalog == nil {
		t.Fatal("catalog is nil")
	}
	if defaultWatchLevel != storage.ImpactLevelCritical {
		t.Errorf("default level = %d, want critical", defaultWatchLevel)
	}
}

func TestViewOfDecorations(t *testing.T) {
	critical := viewOf(storage.WatchRule{TargetType: storage.WatchTypeIISPool, Level: 1})
	if critical.TargetLabel != "IIS App Pool" {
		t.Errorf("label = %q, want the human name, not the wire value", critical.TargetLabel)
	}
	if critical.ImpactLabel != "Level 1 Critical" || critical.DiffMode != "Full diff" {
		t.Errorf("critical view = %q / %q", critical.ImpactLabel, critical.DiffMode)
	}

	drift := viewOf(storage.WatchRule{TargetType: storage.WatchTypeDirectory, Level: 3})
	if drift.ImpactLabel != "Level 3 Drift" || drift.DiffMode != "Hash only" {
		t.Errorf("drift view = %q / %q", drift.ImpactLabel, drift.DiffMode)
	}

	// A rule with no host id is fleet-wide; the UI expects the "*" selector back
	// so its dropdown round-trips.
	fleet := viewOf(storage.WatchRule{TargetType: storage.WatchTypeFile, Level: 1})
	if fleet.HostScope != storage.FleetScope {
		t.Errorf("fleet scope = %q, want %q", fleet.HostScope, storage.FleetScope)
	}

	// An unknown type must not render as an empty cell.
	unknown := viewOf(storage.WatchRule{TargetType: "future_type", Level: 1})
	if unknown.TargetLabel != "future_type" {
		t.Errorf("unknown label = %q, want the raw type", unknown.TargetLabel)
	}
}

// TestViewOfKeepsHostScopeForHostRules proves the host selector is echoed for a
// per-host rule rather than being overwritten by the fleet default.
func TestViewOfKeepsHostScopeForHostRules(t *testing.T) {
	v := viewOf(storage.WatchRule{HostID: "11111111-1111-4111-8111-111111111111",
		Hostname: "win-app-02", HostScope: "win-app-02", Level: 1})
	if v.HostScope != "win-app-02" {
		t.Errorf("host scope = %q", v.HostScope)
	}
}

func TestCreateWatchRuleRejectsBadJSONWithoutTouchingStore(t *testing.T) {
	// No Store: a decode failure must be reported before anything else runs, so
	// a malformed payload can never reach the database.
	s := &Server{OrgID: "org"}
	for _, body := range []string{`{"pattern":`, ``, `[]`} {
		rec := httptest.NewRecorder()
		s.createWatchRule(rec, httptest.NewRequest(http.MethodPost, "/api/v1/rules", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q = %d, want 400", body, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "error") {
			t.Fatalf("body %q produced no error message: %s", body, rec.Body.String())
		}
	}
}

func TestIsValidationError(t *testing.T) {
	yes := []string{
		`unsupported target type "printer"`,
		"pattern is required",
		"impact level must be 1-4, got 0",
		"a database table target must be a db:// path",
		"a database table target must name /tables/<schema>.<table>",
		`a registry target must start with a hive, e.g. HKLM\Software`,
		"a Kubernetes target must be an absolute object path",
		`host "ghost" not found`,
	}
	for _, msg := range yes {
		if !isValidationError(errors.New(msg)) {
			t.Errorf("%q was treated as an infrastructure failure", msg)
		}
	}

	no := []string{
		"connection refused",
		"list watch rules: pq: relation does not exist",
		"context deadline exceeded",
	}
	for _, msg := range no {
		if isValidationError(errors.New(msg)) {
			t.Errorf("%q was treated as an input problem and would return 400", msg)
		}
	}
}

// TestDeleteWatchRuleRejectsMalformedID checks that a hand-typed id is a 404
// rather than a 500 from the uuid cast.
func TestDeleteWatchRuleRejectsMalformedID(t *testing.T) {
	s := &Server{OrgID: "org"}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/not-a-uuid", nil)
	req.SetPathValue("id", "not-a-uuid")
	rec := httptest.NewRecorder()
	s.deleteWatchRule(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["id"] != "not-a-uuid" {
		t.Errorf("response does not echo the id: %v", body)
	}
}
