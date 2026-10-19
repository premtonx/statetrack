package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/metrics"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// metricValue reads one series out of a registry by name and label set, using
// the exposition text so the test asserts on what a scraper would actually see.
func metricValue(t *testing.T, reg *metrics.Registry, name, labels string) float64 {
	t.Helper()
	families, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, m := range family.GetMetric() {
			var parts []string
			for _, lp := range m.GetLabel() {
				parts = append(parts, lp.GetName()+`="`+lp.GetValue()+`"`)
			}
			if strings.Join(parts, ",") == labels {
				if m.GetCounter() != nil {
					return m.GetCounter().GetValue()
				}
				return 0
			}
		}
	}
	return 0
}

var _ = testutil.ToFloat64 // keep the import honest if helpers change

func testEvent() Event {
	return Event{
		ID:         "00002798-0000-4000-8000-0004f26c0000",
		Hostname:   "prod-web-01",
		OccurredAt: time.Date(2026, 10, 15, 19, 51, 0, 0, time.UTC),
		Level:      pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
		Category:   pb.Category_CATEGORY_CONFIG,
		Action:     pb.Action_ACTION_MODIFIED,
		Summary:    "Modified /etc/nginx/nginx.conf (+12 -3)",
		Actor:      "alice",
		Tool:       "vim",
		Target:     "/etc/nginx/nginx.conf",
		RuleName:   "Protect nginx config",
		DeepLink:   "http://localhost:5173/events/00002798-0000-4000-8000-0004f26c0000?tab=diff",
	}
}

/* -------------------------------------------------------------------------- */
/* HMAC signature                                                             */
/* -------------------------------------------------------------------------- */

func TestSignPayloadMatchesIndependentHMAC(t *testing.T) {
	secret := "s3cr3t-shared-key"
	body := []byte(`{"event_id":"abc","summary":"Modified /etc/nginx/nginx.conf"}`)

	got := SignPayload(secret, body)

	// Recompute with the standard library directly, rather than calling
	// SignPayload again, so the test would catch a wrong algorithm or encoding
	// inside SignPayload itself.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, SignatureScheme) {
		t.Fatalf("signature %q is missing the %q scheme prefix", got, SignatureScheme)
	}
	if len(got) != len(SignatureScheme)+64 {
		t.Fatalf("signature length = %d, want scheme+64 hex chars", len(got))
	}
}

func TestSignPayloadIsDeterministicAndSecretDependent(t *testing.T) {
	body := []byte(`{"a":1}`)
	if SignPayload("k1", body) != SignPayload("k1", body) {
		t.Fatal("signature is not deterministic for the same secret and body")
	}
	if SignPayload("k1", body) == SignPayload("k2", body) {
		t.Fatal("signature does not depend on the secret")
	}
	if SignPayload("k1", body) == SignPayload("k1", []byte(`{"a":2}`)) {
		t.Fatal("signature does not depend on the body")
	}
}

func TestVerifySignature(t *testing.T) {
	secret := "k"
	body := []byte(`{"a":1}`)

	if !VerifySignature(secret, body, SignPayload(secret, body)) {
		t.Fatal("a genuine signature failed verification")
	}
	if VerifySignature(secret, body, "sha256="+strings.Repeat("0", 64)) {
		t.Fatal("a forged signature passed verification")
	}
	if VerifySignature("other", body, SignPayload(secret, body)) {
		t.Fatal("a signature verified under the wrong secret")
	}
	// A tampered body must break verification — that is the entire point.
	if VerifySignature(secret, []byte(`{"a":2}`), SignPayload(secret, body)) {
		t.Fatal("a tampered body verified")
	}
}

func TestRenderSignsGenericWebhookBody(t *testing.T) {
	ch := Channel{Provider: ProviderWebhook, Secret: "shared-secret"}
	body, contentType, headers, err := Render(ch, testEvent())
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "application/json" {
		t.Fatalf("content type = %q", contentType)
	}
	sig := headers[SignatureHeader]
	if sig == "" {
		t.Fatalf("generic webhook body is unsigned; headers = %v", headers)
	}
	if !VerifySignature("shared-secret", body, sig) {
		t.Fatal("the delivered signature does not verify against the delivered body")
	}
	if headers["X-StateTrack-Event"] != testEvent().ID {
		t.Fatalf("event header = %q", headers["X-StateTrack-Event"])
	}
}

func TestRenderOmitsSignatureWithoutSecret(t *testing.T) {
	body, _, headers, err := Render(Channel{Provider: ProviderWebhook}, testEvent())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := headers[SignatureHeader]; ok {
		t.Fatal("a signature was emitted with no secret configured")
	}
	// Without a secret the payload must still be valid JSON.
	if !json.Valid(body) {
		t.Fatal("payload is not valid JSON")
	}
}

func TestSigningSecretFromURL(t *testing.T) {
	url, secret := SigningSecretFromURL("https://siem.example.com/hook?secret=abc123&tag=prod")
	if secret != "abc123" {
		t.Fatalf("secret = %q", secret)
	}
	// The secret must be stripped so it never lands in the receiver's log.
	if strings.Contains(url, "abc123") {
		t.Fatalf("secret leaked into the delivered URL %q", url)
	}
	if url != "https://siem.example.com/hook?tag=prod" {
		t.Fatalf("url = %q", url)
	}

	// Other query parameters survive, and no query means no secret.
	url, secret = SigningSecretFromURL("https://siem.example.com/hook?tag=prod")
	if url != "https://siem.example.com/hook?tag=prod" || secret != "" {
		t.Fatalf("url=%q secret=%q", url, secret)
	}
	url, secret = SigningSecretFromURL("https://siem.example.com/hook")
	if url != "https://siem.example.com/hook" || secret != "" {
		t.Fatalf("url=%q secret=%q", url, secret)
	}
	// `signing_secret` is accepted as an alias.
	if _, secret = SigningSecretFromURL("https://x/h?signing_secret=zzz"); secret != "zzz" {
		t.Fatalf("alias not honoured: %q", secret)
	}
}

/* -------------------------------------------------------------------------- */
/* Slack Block Kit                                                            */
/* -------------------------------------------------------------------------- */

func TestFormatSlackBlockKit(t *testing.T) {
	raw, err := FormatSlack(testEvent())
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("slack payload is not valid JSON: %v", err)
	}

	// The fallback text is what Slack shows in the sidebar and in push
	// notifications, so it must summarise the change.
	if !strings.Contains(payload.Text, "Modified /etc/nginx/nginx.conf") ||
		!strings.Contains(payload.Text, "prod-web-01") {
		t.Fatalf("fallback text is uninformative: %q", payload.Text)
	}

	flat := string(raw)
	for _, want := range []string{
		"*L1: Modified /etc/nginx/nginx.conf (+12 -3)*", // headline
		"`prod-web-01`",           // server field
		"alice via vim",           // actor rendered with tool
		"`/etc/nginx/nginx.conf`", // path field
		"config",                  // impact/category field
		"Protect nginx config",    // matched rule
	} {
		if !strings.Contains(flat, want) {
			t.Fatalf("slack payload missing %q:\n%s", want, flat)
		}
	}

	// Exactly one action block, with a primary button carrying the deep link.
	var buttons int
	for _, block := range payload.Blocks {
		elements, _ := block["elements"].([]any)
		for _, rawEl := range elements {
			el, _ := rawEl.(map[string]any)
			if el["type"] != "button" {
				continue
			}
			buttons++
			if el["style"] != "primary" {
				t.Fatalf("button style = %v, want primary", el["style"])
			}
			if el["url"] != testEvent().DeepLink {
				t.Fatalf("button url = %v, want the diff drawer deep link", el["url"])
			}
			if !strings.Contains(el["text"].(map[string]any)["text"].(string), "Inspect Diff") {
				t.Fatalf("button label = %v", el["text"])
			}
		}
	}
	if buttons != 1 {
		t.Fatalf("button count = %d, want 1", buttons)
	}
}

func TestFormatSlackStormVariant(t *testing.T) {
	ev := testEvent()
	ev.IsStorm = true
	ev.SuppressedMutations = 512
	ev.Level = pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT
	ev.Summary = "Change storm: 512 mutations throttled"

	raw, err := FormatSlack(ev)
	if err != nil {
		t.Fatal(err)
	}
	flat := string(raw)
	if !strings.Contains(flat, "Change storm") {
		t.Fatalf("storm payload lacks a storm headline:\n%s", flat)
	}
	if !strings.Contains(flat, "512 mutations") {
		t.Fatalf("storm payload does not report the suppressed count:\n%s", flat)
	}
}

func TestFormatSlackDegradesWithoutActor(t *testing.T) {
	ev := testEvent()
	ev.Actor, ev.Tool, ev.Target, ev.RuleName, ev.DeepLink = "", "", "", "", ""

	raw, err := FormatSlack(ev)
	if err != nil {
		t.Fatal(err)
	}
	flat := string(raw)
	if !strings.Contains(flat, "unknown actor") {
		t.Fatalf("missing-actor slug not rendered:\n%s", flat)
	}
	// With no deep link there must be no action block (an empty url makes
	// Slack reject the whole message).
	if strings.Contains(flat, `"type":"actions"`) {
		t.Fatalf("action block emitted with no deep link:\n%s", flat)
	}
	if strings.Contains(flat, " via unknown") {
		t.Fatalf("dangling 'via' with no tool:\n%s", flat)
	}
}

/* -------------------------------------------------------------------------- */
/* PagerDuty Events API v2                                                    */
/* -------------------------------------------------------------------------- */

func TestFormatPagerDutyTrigger(t *testing.T) {
	raw, err := FormatPagerDuty("routing-key-123", "", testEvent())
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		RoutingKey  string `json:"routing_key"`
		EventAction string `json:"event_action"`
		DedupKey    string `json:"dedup_key"`
		Payload     struct {
			Summary       string         `json:"summary"`
			Source        string         `json:"source"`
			Severity      string         `json:"severity"`
			Timestamp     string         `json:"timestamp"`
			Class         string         `json:"class"`
			CustomDetails map[string]any `json:"custom_details"`
		} `json:"payload"`
		Links []map[string]any `json:"links"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("pagerduty payload is not valid JSON: %v", err)
	}

	if payload.RoutingKey != "routing-key-123" {
		t.Fatalf("routing_key = %q", payload.RoutingKey)
	}
	if payload.EventAction != "trigger" {
		t.Fatalf("event_action = %q, want trigger", payload.EventAction)
	}
	// dedup_key must be the event id so a retry collapses instead of paging twice.
	if payload.DedupKey != testEvent().ID {
		t.Fatalf("dedup_key = %q, want the event id", payload.DedupKey)
	}
	if payload.Payload.Severity != "critical" {
		t.Fatalf("severity = %q, want critical for L1", payload.Payload.Severity)
	}
	if payload.Payload.Source != "prod-web-01" {
		t.Fatalf("source = %q, want the host", payload.Payload.Source)
	}
	if payload.Payload.Summary != testEvent().Summary {
		t.Fatalf("summary = %q", payload.Payload.Summary)
	}
	if payload.Payload.Class != "CRITICAL_MUTATION" {
		t.Fatalf("class = %q", payload.Payload.Class)
	}

	details := payload.Payload.CustomDetails
	for key, want := range map[string]string{
		"host":         "prod-web-01",
		"impact_level": "L1",
		"category":     "config",
		"action":       "modified",
		"actor":        "alice via vim",
		"target_path":  "/etc/nginx/nginx.conf",
		"rule_name":    "Protect nginx config",
		"inspect_diff": testEvent().DeepLink,
	} {
		if details[key] != want {
			t.Fatalf("custom_details[%q] = %v, want %q", key, details[key], want)
		}
	}

	if len(payload.Links) != 1 || payload.Links[0]["href"] != testEvent().DeepLink {
		t.Fatalf("links = %v, want one link to the deep link", payload.Links)
	}
}

func TestFormatPagerDutySeverityMapping(t *testing.T) {
	cases := []struct {
		level pb.ImpactLevel
		want  string
	}{
		{pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, "critical"},
		{pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED, "warning"},
		{pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, "info"},
		{pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC, "info"},
	}
	for _, tc := range cases {
		ev := testEvent()
		ev.Level = tc.level
		raw, err := FormatPagerDuty("k", "", ev)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Payload struct {
				Severity string `json:"severity"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Payload.Severity != tc.want {
			t.Fatalf("level %v severity = %q, want %q", tc.level, payload.Payload.Severity, tc.want)
		}
	}
}

func TestFormatPagerDutyStormAndTruncation(t *testing.T) {
	ev := testEvent()
	ev.IsStorm = true
	ev.SuppressedMutations = 300
	ev.Summary = strings.Repeat("s", 4000)

	raw, err := FormatPagerDuty("k", "", ev)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Payload struct {
			Summary       string         `json:"summary"`
			Severity      string         `json:"severity"`
			CustomDetails map[string]any `json:"custom_details"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	// PagerDuty hard-rejects summaries over 1024 characters.
	if len(payload.Payload.Summary) > 1024 {
		t.Fatalf("summary length = %d, want <= 1024", len(payload.Payload.Summary))
	}
	if payload.Payload.Severity != "warning" {
		t.Fatalf("storm severity = %q, want warning", payload.Payload.Severity)
	}
	if payload.Payload.CustomDetails["event_type"] != "CHANGE_STORM" {
		t.Fatalf("storm event_type = %v", payload.Payload.CustomDetails["event_type"])
	}
	if payload.Payload.CustomDetails["suppressed_mutations"] != float64(300) {
		t.Fatalf("suppressed_mutations = %v", payload.Payload.CustomDetails["suppressed_mutations"])
	}
}

/* -------------------------------------------------------------------------- */
/* Microsoft Teams MessageCard                                                */
/* -------------------------------------------------------------------------- */

func TestFormatTeamsMessageCard(t *testing.T) {
	raw, err := FormatTeams(testEvent())
	if err != nil {
		t.Fatal(err)
	}
	var card struct {
		Type       string `json:"@type"`
		Context    string `json:"@context"`
		ThemeColor string `json:"themeColor"`
		Summary    string `json:"summary"`
		Title      string `json:"title"`
		Sections   []struct {
			ActivityTitle    string              `json:"activityTitle"`
			ActivitySubtitle string              `json:"activitySubtitle"`
			Facts            []map[string]string `json:"facts"`
			PotentialAction  []map[string]any    `json:"potentialAction"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(raw, &card); err != nil {
		t.Fatalf("teams payload is not valid JSON: %v", err)
	}

	if card.Type != "MessageCard" || card.Context != "http://schema.org/extensions" {
		t.Fatalf("card envelope = %q / %q", card.Type, card.Context)
	}
	// L1 must use Google Red, per the design system's severity mapping.
	if card.ThemeColor != "d93025" {
		t.Fatalf("themeColor = %q, want d93025 for L1", card.ThemeColor)
	}
	if len(card.Sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(card.Sections))
	}
	section := card.Sections[0]
	if section.ActivityTitle != testEvent().Summary {
		t.Fatalf("activityTitle = %q", section.ActivityTitle)
	}

	facts := map[string]string{}
	for _, f := range section.Facts {
		facts[f["name"]] = f["value"]
	}
	for name, want := range map[string]string{
		"Server":   "prod-web-01",
		"Actor":    "alice via vim",
		"Path":     "/etc/nginx/nginx.conf",
		"Rule":     "Protect nginx config",
		"Category": "config",
	} {
		if facts[name] != want {
			t.Fatalf("fact %q = %q, want %q", name, facts[name], want)
		}
	}
	if !strings.Contains(facts["Impact"], "L1") {
		t.Fatalf("impact fact = %q", facts["Impact"])
	}

	if len(section.PotentialAction) != 1 {
		t.Fatalf("potentialAction = %d, want 1", len(section.PotentialAction))
	}
	action := section.PotentialAction[0]
	if action["@type"] != "OpenUri" || action["name"] != "Inspect Diff & Actor" {
		t.Fatalf("action = %v", action)
	}
	targets, _ := action["targets"].([]any)
	if len(targets) != 1 || targets[0].(map[string]any)["uri"] != testEvent().DeepLink {
		t.Fatalf("action targets = %v", targets)
	}
}

func TestFormatTeamsThemeColorByLevel(t *testing.T) {
	cases := map[pb.ImpactLevel]string{
		pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL: "d93025",
		pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED:  "7c3aed",
		pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT:    "f9ab00",
	}
	for level, want := range cases {
		ev := testEvent()
		ev.Level = level
		raw, err := FormatTeams(ev)
		if err != nil {
			t.Fatal(err)
		}
		var card struct {
			ThemeColor string `json:"themeColor"`
		}
		if err := json.Unmarshal(raw, &card); err != nil {
			t.Fatal(err)
		}
		if card.ThemeColor != want {
			t.Fatalf("level %v themeColor = %q, want %q", level, card.ThemeColor, want)
		}
	}
}

/* -------------------------------------------------------------------------- */
/* Generic / SIEM payload                                                     */
/* -------------------------------------------------------------------------- */

func TestFormatGenericPayload(t *testing.T) {
	raw, err := FormatGeneric(testEvent())
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}

	for key, want := range map[string]any{
		"provider":      "statetrack",
		"event_type":    "CRITICAL_MUTATION",
		"event_id":      testEvent().ID,
		"host":          "prod-web-01",
		"impact_level":  "L1",
		"impact_number": float64(1),
		"category":      "config",
		"action":        "modified",
		"summary":       testEvent().Summary,
		"actor":         "alice",
		"tool":          "vim",
		"target_path":   "/etc/nginx/nginx.conf",
		"rule_name":     "Protect nginx config",
		"status":        "critical",
		"inspect":       testEvent().DeepLink,
		"deep_link":     testEvent().DeepLink,
		"occurred_at":   float64(testEvent().OccurredAt.UnixMilli()),
	} {
		if payload[key] != want {
			t.Fatalf("payload[%q] = %v, want %v", key, payload[key], want)
		}
	}
}

func TestFormatGenericEventTypeAndStatus(t *testing.T) {
	cases := []struct {
		level    pb.ImpactLevel
		storm    bool
		wantType string
		wantStat string
	}{
		{pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, false, "CRITICAL_MUTATION", "critical"},
		{pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED, false, "MUTATION", "warning"},
		{pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, false, "MUTATION", "info"},
		{pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, true, "CHANGE_STORM", "storm"},
	}
	for _, tc := range cases {
		ev := testEvent()
		ev.Level = tc.level
		ev.IsStorm = tc.storm
		raw, err := FormatGeneric(ev)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			EventType string `json:"event_type"`
			Status    string `json:"status"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.EventType != tc.wantType || payload.Status != tc.wantStat {
			t.Fatalf("level=%v storm=%v → type=%q status=%q, want %q/%q",
				tc.level, tc.storm, payload.EventType, payload.Status, tc.wantType, tc.wantStat)
		}
	}
}

/* -------------------------------------------------------------------------- */
/* Channel filtering                                                          */
/* -------------------------------------------------------------------------- */

func TestChannelWants(t *testing.T) {
	l1 := testEvent()
	l3 := testEvent()
	l3.Level = pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT
	l3.IsStorm = false

	storm := testEvent()
	storm.IsStorm = true

	cases := []struct {
		name    string
		channel Channel
		event   Event
		want    bool
	}{
		{"L1-only receives L1", Channel{MinImpactLevel: 1}, l1, true},
		{"L1-only rejects L3", Channel{MinImpactLevel: 1}, l3, false},
		{"L3 channel receives L1", Channel{MinImpactLevel: 3}, l1, true},
		{"L3 channel receives L3", Channel{MinImpactLevel: 3}, l3, true},
		{"storm rejected when storms off", Channel{MinImpactLevel: 3}, storm, false},
		{"storm accepted when storms on", Channel{MinImpactLevel: 3, NotifyStorms: true}, storm, true},
		{"storm accepted by L1 channel if opted in", Channel{MinImpactLevel: 1, NotifyStorms: true}, storm, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.channel.Wants(tc.event); got != tc.want {
				t.Fatalf("Wants() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEventFromNotification(t *testing.T) {
	n := storage.Notification{
		ID:          "evt-1",
		Hostname:    "prod-web-01",
		OccurredAt:  time.Now().UTC(),
		ImpactLevel: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
		Category:    pb.Category_CATEGORY_CONFIG,
		Action:      pb.Action_ACTION_MODIFIED,
		Summary:     "Modified /etc/nginx/nginx.conf",
		ActorName:   "alice",
		PathOrKey:   "/etc/nginx/nginx.conf",
		Metadata: map[string]string{
			"rule_name":      "Protect nginx config",
			"mutation_count": "128",
			"process_name":   "vim",
		},
	}
	ev := EventFromNotification("http://localhost:5173/", n)

	if ev.DeepLink != "http://localhost:5173/events/evt-1?tab=diff" {
		t.Fatalf("deep link = %q", ev.DeepLink)
	}
	if ev.RuleName != "Protect nginx config" {
		t.Fatalf("rule name = %q", ev.RuleName)
	}
	if ev.Tool != "vim" {
		t.Fatalf("tool = %q", ev.Tool)
	}
	if ev.IsStorm {
		t.Fatal("a plain modification was classified as a storm")
	}
	// The mutation_count metadata only means something for a storm.
	if ev.SuppressedMutations != 128 {
		t.Fatalf("suppressed = %d", ev.SuppressedMutations)
	}

	n.Action = pb.Action_ACTION_THROTTLED
	n.Metadata["event_type"] = "CHANGE_STORM_THROTTLED"
	if ev := EventFromNotification("", n); !ev.IsStorm {
		t.Fatal("a throttled action was not classified as a storm")
	}
}

/* -------------------------------------------------------------------------- */
/* Dispatch (transport, retries, metrics)                                     */
/* -------------------------------------------------------------------------- */

func TestDispatchDeliversAndRecordsMetrics(t *testing.T) {
	var gotBody []byte
	var gotSig, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = readAll(r)
		gotSig = r.Header.Get(SignatureHeader)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reg := metrics.New()
	d := NewDispatcher(DispatcherOptions{Metrics: reg})
	result := d.Dispatch(context.Background(), Channel{
		Provider: ProviderWebhook, URL: srv.URL, Secret: "k",
	}, testEvent())

	if !result.OK() {
		t.Fatalf("dispatch failed: %v (status %d)", result.Err, result.Status)
	}
	if result.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", result.Attempts)
	}
	if gotCT != "application/json" {
		t.Fatalf("content type = %q", gotCT)
	}
	if !VerifySignature("k", gotBody, gotSig) {
		t.Fatal("the delivered signature does not verify against the delivered body")
	}
	// The metric must be bucketed, not keyed by URL or status code.
	if got := metricValue(t, reg, "statetrack_webhook_deliveries_total",
		`provider="webhook",status="success"`); got != 1 {
		t.Fatalf("success counter = %v, want 1", got)
	}
}

// TestSignatureHeaderKeepsDocumentedCasing pins the exact spelling of the
// signature header on the wire.
//
// net/http canonicalizes header keys, and its server canonicalizes again when
// parsing, so a test that asserts through r.Header.Get would pass even if we
// emitted "X-Statetrack-Signature". A raw listener is the only place the true
// bytes are observable, and it matters: our docs, the console hint and SIEM
// receiver configs all name the header "X-StateTrack-Signature", and a strict
// matcher keying off a literal string would silently stop verifying.
func TestSignatureHeaderKeepsDocumentedCasing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	raw := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read only the header block; the body length is irrelevant here.
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		raw <- string(buf[:n])
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	d := NewDispatcher(DispatcherOptions{})
	result := d.Dispatch(context.Background(),
		Channel{Provider: ProviderWebhook, URL: "http://" + ln.Addr().String(), Secret: "k"},
		testEvent())
	if !result.OK() {
		t.Fatalf("dispatch failed: %v", result.Err)
	}

	select {
	case head := <-raw:
		if !strings.Contains(head, SignatureHeader+":") {
			t.Fatalf("wire request lacks %q with its documented casing:\n%s", SignatureHeader, head)
		}
		if strings.Contains(head, "X-Statetrack-Signature:") {
			t.Fatalf("signature header reached the wire with canonicalized casing:\n%s", head)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the raw request")
	}
}

func TestDispatchRetriesServerErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reg := metrics.New()
	d := NewDispatcher(DispatcherOptions{Metrics: reg, Retries: 2})
	d.sleep = func(time.Duration) {} // keep the test fast

	result := d.Dispatch(context.Background(), Channel{Provider: ProviderWebhook, URL: srv.URL}, testEvent())
	if !result.OK() {
		t.Fatalf("dispatch should have succeeded on the third attempt: %v", result.Err)
	}
	if result.Attempts != 3 || calls != 3 {
		t.Fatalf("attempts = %d (server saw %d), want 3", result.Attempts, calls)
	}
	if got := metricValue(t, reg, "statetrack_webhook_deliveries_total",
		`provider="webhook",status="success"`); got != 1 {
		t.Fatalf("success counter = %v, want 1", got)
	}
}

func TestDispatchDoesNotRetryClientErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer srv.Close()

	reg := metrics.New()
	d := NewDispatcher(DispatcherOptions{Metrics: reg, Retries: 3})
	d.sleep = func(time.Duration) {}

	result := d.Dispatch(context.Background(), Channel{Provider: ProviderSlack, URL: srv.URL}, testEvent())
	if result.OK() {
		t.Fatal("a 401 must not be reported as delivered")
	}
	// Retrying a rejected credential would only spam the provider.
	if calls != 1 {
		t.Fatalf("server saw %d requests, want 1 (4xx must not be retried)", calls)
	}
	if result.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d", result.Status)
	}
	if !strings.Contains(result.Err.Error(), "invalid_token") {
		t.Fatalf("error does not carry the provider's message: %v", result.Err)
	}
	if got := metricValue(t, reg, "statetrack_webhook_deliveries_total",
		`provider="slack",status="client_error"`); got != 1 {
		t.Fatalf("client_error counter = %v, want 1", got)
	}
}

func TestDispatchReportsTransportFailure(t *testing.T) {
	// A closed server: the connection is refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	reg := metrics.New()
	d := NewDispatcher(DispatcherOptions{Metrics: reg, Retries: 0})
	d.retries = 0
	d.sleep = func(time.Duration) {}

	result := d.Dispatch(context.Background(), Channel{Provider: ProviderPagerDuty, URL: url}, testEvent())
	if result.OK() {
		t.Fatal("an unreachable provider must not be reported as delivered")
	}
	if result.Err == nil {
		t.Fatal("no error reported for a refused connection")
	}
	if got := metricValue(t, reg, "statetrack_webhook_deliveries_total",
		`provider="pagerduty",status="error"`); got != 1 {
		t.Fatalf("error counter = %v, want 1", got)
	}
}

func TestDispatchRejectsUnknownProvider(t *testing.T) {
	d := NewDispatcher(DispatcherOptions{})
	result := d.Dispatch(context.Background(), Channel{Provider: "carrier-pigeon", URL: "http://x"}, testEvent())
	if result.OK() {
		t.Fatal("an unknown provider must fail loudly, not silently succeed")
	}
	if !strings.Contains(result.Err.Error(), "unknown provider") {
		t.Fatalf("error = %v", result.Err)
	}
}

func TestRenderContentTypesPerProvider(t *testing.T) {
	for _, provider := range []string{
		ProviderWebhook, ProviderSlack, ProviderPagerDuty, ProviderTeams,
	} {
		body, contentType, _, err := Render(Channel{Provider: provider}, testEvent())
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		if contentType != "application/json" {
			t.Fatalf("%s content type = %q", provider, contentType)
		}
		if !json.Valid(body) {
			t.Fatalf("%s produced invalid JSON: %s", provider, body)
		}
	}
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

func readAll(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}
