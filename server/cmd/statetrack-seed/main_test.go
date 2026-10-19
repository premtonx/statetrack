package main

import (
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// TestTimelineIsRelativeToNowAndInsideDashboardWindow guards the bug that made
// every Grafana rate/increase panel read zero: the seeder anchored its events to
// a fixed wall-clock hour (09:02 local). Run before 09:00 — which is exactly
// when a demo is often recorded — that put the whole timeline in the future, so
// it fell outside Grafana's window and nothing showed.
//
// The second invariant is the dashboard's one-hour window. The provisioned
// dashboard opens on `now-1h..now`, so an anchor older than an hour leaves dead
// space at the left of every chart — the panels are drawn, but with nothing in
// them. Every anchor is therefore both in the past and no more than an hour
// old.
func TestTimelineIsRelativeToNowAndInsideDashboardWindow(t *testing.T) {
	now := time.Date(2026, 10, 17, 2, 15, 0, 0, time.Local)
	tl := newTimeline(now)

	anchors := map[string]time.Time{
		"nginxAt":      tl.nginxAt,
		"aptAt":        tl.aptAt,
		"restartAt":    tl.restartAt,
		"indexAt":      tl.indexAt,
		"regAt":        tl.regAt,
		"peerAptAt":    tl.peerAptAt,
		"dbAt":         tl.dbAt,
		"iisAt":        tl.iisAt,
		"k8sCMAt":      tl.k8sCMAt,
		"k8sSecretAt":  tl.k8sSecretAt,
		"k8sDeployAt":  tl.k8sDeployAt,
		"k8sIngressAt": tl.k8sIngressAt,
	}

	for name, at := range anchors {
		if !at.Before(now) {
			t.Errorf("%s = %s is not before now (%s); a future event is invisible to rate()/increase()",
				name, at.Format(time.RFC3339), now.Format(time.RFC3339))
		}
		// The dashboard's default range is now-1h..now.
		if now.Sub(at) > time.Hour {
			t.Errorf("%s = %s is %s before now, outside the dashboard's default now-1h window",
				name, at.Format(time.RFC3339), now.Sub(at).Round(time.Minute))
		}
	}

	// The interleaving the dashboard and post-mortem rely on: the cluster's
	// ConfigMap lands before the nginx edit, the restart after it, and the IIS
	// pool stop is the newest critical change on win-app-02.
	if !tl.k8sCMAt.Before(tl.nginxAt) {
		t.Error("k8s ConfigMap should precede the nginx edit")
	}
	if !tl.restartAt.After(tl.nginxAt) {
		t.Error("the nginx restart should follow the nginx edit (be later)")
	}
	if !tl.regAt.After(tl.indexAt) {
		t.Error("the registry change should be newer than the index.html drift")
	}
	// The surgical-watcher scenarios are ordered so the IIS app-pool crash is
	// the newest critical change on win-app-02: Checkmk renders a host's latest
	// critical change, and that headline has to be the pool crash, not the
	// routine registry tweak seeded seven minutes ago.
	if !tl.iisAt.After(tl.dbAt) {
		t.Error("the IIS pool stop should follow the settings_db edit")
	}
	if !tl.iisAt.After(tl.regAt) {
		t.Error("the IIS pool stop must be newer than the registry change so it is the host's latest critical")
	}
}

// TestSurgicalWatcherDocumentsAreConsistent guards the two seeded canonical
// documents. They are JSON-free YAML literals in this file, so nothing else
// would catch a stray key: the diff drawer renders them verbatim, and a
// mismatch between the before/after pair would produce a diff that does not show
// the change the event's summary claims.
func TestSurgicalWatcherDocumentsAreConsistent(t *testing.T) {
	var before, after map[string]any
	if err := yaml.Unmarshal([]byte(checkoutPoolBefore), &before); err != nil {
		t.Fatalf("checkoutPoolBefore is not valid YAML: %v", err)
	}
	if err := yaml.Unmarshal([]byte(checkoutPoolAfter), &after); err != nil {
		t.Fatalf("checkoutPoolAfter is not valid YAML: %v", err)
	}
	if before["state"] != "Started" || after["state"] != "Stopped" {
		t.Errorf("pool state transition = %v -> %v, want Started -> Stopped", before["state"], after["state"])
	}
	if before["kind"] != "iis_apppool" || after["kind"] != "iis_apppool" {
		t.Errorf("pool kind = %v / %v", before["kind"], after["kind"])
	}
	// The key set must be identical, or the diff shows a removed and an added
	// field rather than a changed value — which would make the demo's diff look
	// like a different document.
	if len(before) != len(after) {
		t.Errorf("before has %d keys, after has %d; the pair must have the same shape",
			len(before), len(after))
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			t.Errorf("key %q exists only in the before document", k)
		}
	}
	// The cleartext credential must never appear; only the edge stub does.
	if strings.Contains(checkoutPoolAfter, "svc_checkout\"") && strings.Contains(checkoutPoolAfter, "password: C") {
		t.Error("the seeded pool document carries a cleartext password")
	}
	if !strings.Contains(checkoutPoolAfter, "[REDACTED:sha256:7c4e91a2]") {
		t.Error("the rotated pool identity lost its redaction stub")
	}

	var tBefore, tAfter map[string]any
	if err := yaml.Unmarshal([]byte(appSettingsBefore), &tBefore); err != nil {
		t.Fatalf("appSettingsBefore is not valid YAML: %v", err)
	}
	if err := yaml.Unmarshal([]byte(appSettingsAfter), &tAfter); err != nil {
		t.Fatalf("appSettingsAfter is not valid YAML: %v", err)
	}
	if tBefore["database"] != "settings_db" || tAfter["database"] != "settings_db" {
		t.Errorf("settings_db document names %v / %v", tBefore["database"], tAfter["database"])
	}
	if strings.Contains(appSettingsAfter, "verify_tls\n      value: \"true\"") {
		t.Error("verify_tls was not flipped to false in the after document")
	}
	// Both rotations must be stubs, and they must differ — a rotation that
	// rendered the same stub would be the one change the scrubber must not hide.
	if !strings.Contains(appSettingsBefore, "[REDACTED:sha256:9f3a1c8e]") ||
		!strings.Contains(appSettingsAfter, "[REDACTED:sha256:4b7d2e10]") {
		t.Error("the rotated webhook secret is missing one of its stubs")
	}
}

// TestAnnotatedAnchorsAreEvenlySpread guards the hero panel's readability.
//
// The four flags are the panel's whole point — each is a vertical line a viewer
// is meant to align with a spike — so they must be distributed across the hour
// rather than bunched at one end. This asserts both the ordering the recording
// script specifies and a minimum gap between neighbours, which is what a later
// "just move it a bit" edit would quietly break.
func TestAnnotatedAnchorsAreEvenlySpread(t *testing.T) {
	now := time.Date(2026, 10, 17, 2, 15, 0, 0, time.Local)
	tl := newTimeline(now)

	// Oldest to newest: nginx edit, ArgoCD rollout, settings_db, IIS pool.
	got := []struct {
		name string
		at   time.Time
	}{
		{"nginxAt (L1)", tl.nginxAt},
		{"k8sDeployAt (L1)", tl.k8sDeployAt},
		{"dbAt (L1)", tl.dbAt},
		{"iisAt (L1)", tl.iisAt},
	}
	for i := 1; i < len(got); i++ {
		gap := got[i].at.Sub(got[i-1].at)
		if gap <= 0 {
			t.Fatalf("%s does not follow %s", got[i].name, got[i-1].name)
		}
		if gap < 10*time.Minute {
			t.Errorf("flags %s and %s are only %s apart; on a one-hour panel they overlap",
				got[i-1].name, got[i].name, gap.Round(time.Minute))
		}
	}

	// The oldest flag must leave a readable stretch of chart to its left, and
	// the newest must not sit on the right edge where its tooltip is clipped.
	if oldest := now.Sub(got[0].at); oldest > 55*time.Minute || oldest < 45*time.Minute {
		t.Errorf("oldest flag is %s before now; want 45-55m so the panel has a left margin", oldest.Round(time.Minute))
	}
	if newest := now.Sub(got[len(got)-1].at); newest > 10*time.Minute || newest < 2*time.Minute {
		t.Errorf("newest flag is %s before now; want 2-10m so it is on-panel but settled", newest.Round(time.Minute))
	}
}

// TestTimelineIsStableAcrossRuns ensures the anchors track `now` rather than
// being pinned to a fixed date, so two runs at different times produce two
// different (but internally consistent) timelines.
func TestTimelineIsStableAcrossRuns(t *testing.T) {
	first := newTimeline(time.Date(2026, 10, 17, 2, 15, 0, 0, time.Local))
	second := newTimeline(time.Date(2026, 10, 18, 14, 30, 0, 0, time.Local))

	if first.nginxAt.Equal(second.nginxAt) {
		t.Fatal("timeline anchors are pinned; they must be relative to the run")
	}
	// The *offsets* between anchors are what must stay stable.
	if got, want := first.nginxAt.Sub(first.regAt), second.nginxAt.Sub(second.regAt); got != want {
		t.Fatalf("anchor spacing changed between runs: %s vs %s", got, want)
	}
}

// TestMarkSeededTagsEveryEvent guards the cleanup contract: clearSeededTimeline
// finds rows by the seed_source metadata, so an event inserted without it would
// survive the next run and accumulate as a duplicate.
func TestMarkSeededTagsEveryEvent(t *testing.T) {
	events := markSeeded([]*pb.MutationEvent{
		{EventId: "a", Metadata: map[string]string{"content": "text"}},
		{EventId: "b"}, // nil metadata must be initialised, not panic
	})
	for _, ev := range events {
		if got := ev.GetMetadata()["seed_source"]; got != seedSourceTag {
			t.Errorf("event %s seed_source = %q, want %q", ev.GetEventId(), got, seedSourceTag)
		}
	}
	if got := events[0].GetMetadata()["content"]; got != "text" {
		t.Errorf("markSeeded dropped existing metadata: content = %q", got)
	}
}

// TestSeededEventIDsAreDeterministic pins the ids clearSeededTimeline deletes by.
// They must be the same ids seedID produces for the event literals, or cleanup
// would miss rows written by an older binary and the timeline would double up.
func TestSeededEventIDsAreDeterministic(t *testing.T) {
	ids := seededEventIDs()
	if len(ids) == 0 {
		t.Fatal("seededEventIDs returned nothing; cleanup would delete no legacy rows")
	}

	// The ids must be stable across calls (they are SHA-1 over a fixed name).
	again := seededEventIDs()
	for i := range ids {
		if ids[i] != again[i] {
			t.Fatalf("seededEventIDs is not deterministic at %d: %s vs %s", i, ids[i], again[i])
		}
	}

	// Every parent id must match what the event literals compute, so a rename in
	// one place without the other is caught here rather than in production.
	for _, want := range []string{
		"prod-web-01/nginx.conf",
		"prod-web-01/nginx.service",
		"prod-web-01/index.html",
		"prod-web-01/settings_db/app_settings",
		"win-app-02/registry-loglevel",
		"win-app-02/iis/checkout-apppool",
		"prod-web-02/apt-openssl",
		"prod-k8s-01/payments/configmap/checkout-config",
		"prod-k8s-01/payments/secret/api-keys",
		"prod-k8s-01/payments/secret/db-credentials", // legacy id, still cleaned by name
		"prod-k8s-01/messaging/deployment/rabbitmq",
		"prod-k8s-01/staging/ingress/checkout-preview",
	} {
		if !contains(ids, seedID(want)) {
			t.Errorf("seededEventIDs is missing the id for %q", want)
		}
	}

	// Ambient events must be covered too, or a run that only tagged them (no
	// tag-based cleanup match) would leave its background volume behind and the
	// next run would stack a second copy.
	for _, sp := range ambientSpecs() {
		if !contains(ids, seedID(sp.name)) {
			t.Errorf("seededEventIDs is missing the ambient id %q", sp.name)
		}
	}
}

// TestAmbientSpecsAreWellFormed pins the shape the dashboard assumes of the
// background volume, which is easy to break with an innocent-looking edit:
//
//   - every spec is inside the one-hour window (an older one leaves dead space
//     at the left of every chart),
//   - no spec collides with a narrative path (a collision would let the last
//     ambient write overwrite the drift state the narrative seeder sets up),
//   - no ambient event is Level 1 (red is reserved for the story, or the
//     stacked chart's critical band stops being a signal),
//   - ids are unique (a duplicate would make two specs share a row).
func TestAmbientSpecsAreWellFormed(t *testing.T) {
	specs := ambientSpecs()
	if len(specs) == 0 {
		t.Fatal("ambientSpecs produced nothing; the dashboard's charts would render as single bars")
	}

	narrative := map[string]bool{
		"/etc/nginx/nginx.conf":                                true,
		"/var/www/html/index.html":                             true,
		"/usr/sbin/nginx":                                      true,
		"/lib/systemd/system/nginx.service":                    true,
		`HKLM\Software\Company\App\LogLevel`:                   true,
		"/k8s/prod-k8s-01/payments/configmaps/checkout-config": true,
		"/k8s/prod-k8s-01/payments/secrets/api-keys":           true,
		"/k8s/prod-k8s-01/messaging/deployments/rabbitmq":      true,
		"/k8s/prod-k8s-01/staging/ingresses/checkout-preview":  true,
	}

	seen := map[string]bool{}
	hosts := map[string]int{}
	for _, sp := range specs {
		if sp.minutesAgo <= 0 || sp.minutesAgo >= 60 {
			t.Errorf("ambient %s is %dm ago; want inside the 0-60m dashboard window", sp.name, sp.minutesAgo)
		}
		if sp.level == pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
			t.Errorf("ambient %s is Level 1; critical is reserved for the annotated flags", sp.name)
		}
		if narrative[sp.path] {
			t.Errorf("ambient %s targets the narrative path %q", sp.name, sp.path)
		}
		if seen[sp.name] {
			t.Errorf("duplicate ambient spec name %q", sp.name)
		}
		seen[sp.name] = true
		if sp.summary == "" || sp.actor.username == "" {
			t.Errorf("ambient %s has no summary or actor", sp.name)
		}
		hosts[sp.hostName]++
	}

	// Every host on the fleet must have background volume, or the "Top affected
	// hosts" table ranks a busy host against an empty one.
	for _, host := range []string{"prod-web-01", "prod-web-02", "win-app-02", "prod-k8s-01"} {
		if hosts[host] == 0 {
			t.Errorf("no ambient events for %s", host)
		}
	}
}

// TestAnnotatedIDsMatchTimelineAnchors guards the contract between the seeder
// and the Grafana annotation tool: the flagged events are looked up by id, so
// an id that does not correspond to an inserted event pushes no flag at all
// (silently — the hero panel just draws three lines instead of four).
func TestAnnotatedIDsMatchTimelineAnchors(t *testing.T) {
	ids := annotatedIDs()
	if len(ids) != 4 {
		t.Fatalf("annotatedIDs returned %d ids, want the 4 the hero panel is designed around", len(ids))
	}
	tagged := map[string]bool{}
	for _, id := range ids {
		if tagged[id] {
			t.Fatalf("duplicate annotated id %s", id)
		}
		tagged[id] = true
	}

	// The four named scenarios the recording script asks for: one Linux config
	// edit, one ArgoCD rollout, one database mutation and one IIS pool crash.
	for name, want := range map[string]string{
		"nginx.conf (L1)":   "prod-web-01/nginx.conf",
		"argo rollout (L1)": "prod-k8s-01/messaging/deployment/rabbitmq",
		"settings_db (L1)":  "prod-web-01/settings_db/app_settings",
		"iis pool (L1)":     "win-app-02/iis/checkout-apppool",
	} {
		if !tagged[seedID(want)] {
			t.Errorf("annotatedIDs is missing the %s anchor (%q)", name, want)
		}
	}

	// markAnnotated must set the flag on exactly those ids and nothing else.
	events := []*pb.MutationEvent{
		{EventId: seedID("prod-web-01/nginx.conf")},
		{EventId: seedID("prod-k8s-01/messaging/deployment/rabbitmq"), Metadata: map[string]string{"x": "y"}},
		{EventId: seedID("prod-web-01/apt-nginx")}, // not annotated
	}
	marked := markAnnotated(events)
	if marked[0].Metadata[annotateTag] != "true" {
		t.Error("the nginx.conf edit was not flagged")
	}
	if marked[1].Metadata["x"] != "y" {
		t.Error("markAnnotated dropped existing metadata")
	}
	if marked[2].Metadata[annotateTag] == "true" {
		t.Error("an unlisted event was flagged; the hero panel would grow extra lines")
	}
}

// TestAptChildSeedNamesMatchInsertedChildren guards the one place the cleanup
// list and the insertion list could silently diverge: the apt transaction's
// children are referenced by name in both.
func TestAptChildSeedNamesMatchInsertedChildren(t *testing.T) {
	// Independently derived from the childSpec table in seed(); this literal is
	// the "expected" side of the guard.
	want := []string{
		"mime.types", "fastcgi_params", "conf.d/default.conf",
		"html/index.html", "nginx", "nginx.service",
	}
	got := aptChildSeedNames()
	if len(got) != len(want) {
		t.Fatalf("aptChildSeedNames returned %d names, want %d", len(got), len(want))
	}
	for i := range want {
		full := "prod-web-01/apt-nginx/" + want[i]
		if got[i] != full {
			t.Errorf("aptChildSeedNames[%d] = %q, want %q", i, got[i], full)
		}
	}
}

// TestAptChildHashesKeepTheirLabels pins the post-upgrade hash inputs. They are
// part of the seeded drift state (the matrix compares them), so a refactor that
// changes a label — e.g. "default.conf" to "conf.d/default.conf" — would
// silently change every hash the drift view reports.
func TestAptChildHashesKeepTheirLabels(t *testing.T) {
	for _, c := range aptChildren {
		if c.hashKey == "" {
			t.Errorf("apt child %q has no hashKey; its hash would be unstable", c.name)
		}
		if c.name == "conf.d/default.conf" && c.hashKey != "default.conf" {
			t.Errorf("conf.d/default.conf hashKey = %q, want the historical %q", c.hashKey, "default.conf")
		}
	}
	// The derived hash must actually depend on the version, or an upgrade would
	// not show as a change.
	if aptChildHashAfter(aptChildren[0]) == sha256hex(aptChildren[0].hashKey+"@"+aptNginxBeforeVer) {
		t.Error("apt child hash does not depend on the version")
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
