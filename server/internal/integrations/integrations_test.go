package integrations

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// repoFile resolves a path relative to the repository root. Go runs a package's
// tests with the working directory set to the package directory, which is three
// levels below the root for this package.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", rel)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("resolve %s: %v", rel, err)
	}
	return path
}

func loadYAML(t *testing.T, rel string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(repoFile(t, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return doc
}

// TestPrometheusAlertRulesAreValid loads the shipped Alertmanager rules file.
// Prometheus refuses to start on a malformed rule file, so a typo here would
// only be discovered at deploy time; this catches it at test time instead.
func TestPrometheusAlertRulesAreValid(t *testing.T) {
	doc := loadYAML(t, "integrations/prometheus/prometheus_alerts.yml")

	groups, ok := doc["groups"].([]any)
	if !ok || len(groups) == 0 {
		t.Fatalf("prometheus_alerts.yml has no rule groups")
	}

	names := map[string]bool{}
	var alerts []map[string]any
	for _, g := range groups {
		group, ok := g.(map[string]any)
		if !ok {
			t.Fatalf("rule group is not a mapping")
		}
		if name, _ := group["name"].(string); name == "" {
			t.Fatalf("rule group has no name")
		}
		rules, ok := group["rules"].([]any)
		if !ok || len(rules) == 0 {
			t.Fatalf("group %v has no rules", group["name"])
		}
		for _, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				t.Fatalf("rule is not a mapping")
			}
			name, _ := rule["alert"].(string)
			if name == "" {
				continue
			}
			if names[name] {
				t.Fatalf("duplicate alert name %q", name)
			}
			names[name] = true
			alerts = append(alerts, rule)
		}
	}

	// The four rules the integrations spec requires, verbatim.
	for _, want := range []string{
		"StateTrackCriticalConfigMutation",
		"StateTrackChangeStormDetected",
		"StateTrackAgentOffline",
		"StateTrackFleetDriftDetected",
	} {
		if !names[want] {
			t.Fatalf("required alert %q is missing", want)
		}
	}

	// Every alert must be evaluable and carry a severity: an alert with no
	// expression never fires, and one with no severity rows into a routing gap.
	for _, a := range alerts {
		if expr, _ := a["expr"].(string); strings.TrimSpace(expr) == "" {
			t.Fatalf("alert %v has an empty expr", a["alert"])
		}
		labels, _ := a["labels"].(map[string]any)
		if labels == nil || labels["severity"] == nil {
			t.Fatalf("alert %v has no severity label", a["alert"])
		}
		ann, _ := a["annotations"].(map[string]any)
		if ann == nil || ann["summary"] == nil {
			t.Fatalf("alert %v has no summary annotation", a["alert"])
		}
	}
}

// metricRef matches a PromQL metric selector: an identifier followed by an
// optional label matcher and then an operator or bracket. Restricting the match
// to selectors keeps label names out of the results.
var metricRef = regexp.MustCompile(`([a-z][a-z0-9_]*)\s*(\{[^}]*\})?\s*(\)|\[|$)`)

// TestPrometheusRulesOnlyReferenceExportedMetrics catches a rule that queries a
// metric the exporter does not publish, which would fail silently in production
// (an empty vector is indistinguishable from "everything is healthy").
func TestPrometheusRulesOnlyReferenceExportedMetrics(t *testing.T) {
	raw, err := os.ReadFile(repoFile(t, "integrations/prometheus/prometheus_alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}

	exported := map[string]bool{
		"statetrack_mutations_total":               true,
		"statetrack_drift_targets":                 true,
		"statetrack_active_agents":                 true,
		"statetrack_storm_throttles_total":         true,
		"statetrack_ingest_batch_duration_seconds": true,
		"statetrack_ingest_events_received_total":  true,
		"statetrack_webhook_deliveries_total":      true,
		// Derived series Prometheus synthesises for a histogram.
		"statetrack_ingest_batch_duration_seconds_bucket": true,
		"statetrack_ingest_batch_duration_seconds_sum":    true,
		"statetrack_ingest_batch_duration_seconds_count":  true,
	}

	found := map[string]bool{}
	for _, m := range metricRef.FindAllStringSubmatch(string(raw), -1) {
		name := m[1]
		if !strings.HasPrefix(name, "statetrack_") {
			continue
		}
		found[name] = true
		if !exported[name] {
			t.Fatalf("alerting rules reference unknown metric %q", name)
		}
	}
	if len(found) < 4 {
		t.Fatalf("only %d distinct statetrack metrics referenced; expected the fleet and SLI families", len(found))
	}
}

// TestZabbixTemplateShape validates the shipped template's architecture: one
// HTTP Agent master item and everything else dependent on it. That invariant is
// what keeps a large fleet to one API call per host per minute.
func TestZabbixTemplateShape(t *testing.T) {
	doc := loadYAML(t, "integrations/zabbix/zabbix_template_statetrack.yaml")

	root, ok := doc["zabbix_export"].(map[string]any)
	if !ok {
		t.Fatal("zabbix_template_statetrack.yaml is missing zabbix_export")
	}
	version, _ := root["version"].(string)
	if version != "6.4" && version != "7.0" {
		t.Fatalf("unexpected template version %q", version)
	}

	templates, ok := root["templates"].([]any)
	if !ok || len(templates) != 1 {
		t.Fatalf("expected exactly one template, got %d", len(templates))
	}
	tmpl := templates[0].(map[string]any)

	items, ok := tmpl["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatal("template has no items")
	}

	keys := map[string]map[string]any{}
	for i, rawItem := range items {
		item := rawItem.(map[string]any)
		key, _ := item["key"].(string)
		if key == "" {
			t.Fatalf("item %d has no key", i)
		}
		if _, dup := keys[key]; dup {
			t.Fatalf("duplicate item key %q", key)
		}
		keys[key] = item
	}

	master, ok := keys["statetrack.host.summary"]
	if !ok {
		t.Fatal("master item statetrack.host.summary is missing")
	}
	if master["type"] != "HTTP_AGENT" {
		t.Fatalf("master item type = %v, want HTTP_AGENT", master["type"])
	}
	if master["delay"] != "1m" {
		t.Fatalf("master item delay = %v, want 1m", master["delay"])
	}
	url, _ := master["url"].(string)
	for _, want := range []string{
		"{$STATETRACK.URL}",
		"/api/v1/hosts/{HOST.HOST}/summary",
		"window={$STATETRACK.WINDOW}",
	} {
		if !strings.Contains(url, want) {
			t.Fatalf("master item url %q missing %q", url, want)
		}
	}
	headers, _ := master["headers"].(map[string]any)
	if auth, _ := headers["Authorization"].(string); !strings.Contains(auth, "{$STATETRACK.TOKEN}") {
		t.Fatalf("master item Authorization header does not use the token macro: %v", auth)
	}

	// The spec's required dependent items, and the JSONPath each must run.
	wantDependents := map[string]string{
		"statetrack.agent.online":     "$.online",
		"statetrack.changes.critical": "$.counts.l1_critical",
		"statetrack.changes.grouped":  "$.counts.l2_grouped",
		"statetrack.changes.drift":    "$.counts.l3_drift",
		"statetrack.drift.targets":    "$.drift_targets_count",
		"statetrack.latest.summary":   "$.latest_critical.summary",
		"statetrack.latest.actor":     "$.latest_critical.actor",
		"statetrack.latest.link":      "$.latest_critical.deep_link",
	}
	for key, path := range wantDependents {
		item, ok := keys[key]
		if !ok {
			t.Fatalf("dependent item %q is missing", key)
		}
		if item["type"] != "DEPENDENT" {
			t.Fatalf("item %q type = %v, want DEPENDENT", key, item["type"])
		}
		if item["delay"] != 0 {
			t.Fatalf("dependent item %q delay = %v, want 0 (parsed from master)", key, item["delay"])
		}
		masterItem, _ := item["master_item"].(map[string]any)
		if masterItem["key"] != "statetrack.host.summary" {
			t.Fatalf("item %q is not attached to the master item", key)
		}
		if !jsonPathUsed(item, path) {
			t.Fatalf("item %q does not preprocess with JSONPath %q", key, path)
		}
	}

	// online must be coerced to a number so triggers can compare it.
	if !hasPreprocessing(keys["statetrack.agent.online"], "BOOLEAN_TO_DECIMAL") {
		t.Fatal("statetrack.agent.online must apply BOOLEAN_TO_DECIMAL")
	}

	// Triggers: the three severities the spec asks for, with the deep link
	// carried into the alert so it is actionable from the notification.
	triggers, ok := tmpl["triggers"].([]any)
	if !ok || len(triggers) < 3 {
		t.Fatalf("expected at least 3 triggers, got %d", len(triggers))
	}
	priorities := map[string]string{}
	for _, rawTrigger := range triggers {
		trig := rawTrigger.(map[string]any)
		name, _ := trig["name"].(string)
		priority, _ := trig["priority"].(string)
		if name == "" || priority == "" {
			t.Fatalf("trigger missing name or priority: %v", trig)
		}
		priorities[priority] = name
		if expr, _ := trig["expression"].(string); strings.TrimSpace(expr) == "" {
			t.Fatalf("trigger %q has an empty expression", name)
		}
	}
	for _, want := range []string{"HIGH", "AVERAGE", "WARNING"} {
		if priorities[want] == "" {
			t.Fatalf("no %s severity trigger", want)
		}
	}
	if !strings.Contains(priorities["HIGH"], "critical configuration mutation") {
		t.Fatalf("HIGH trigger does not describe a critical configuration mutation: %q", priorities["HIGH"])
	}
	if !strings.Contains(priorities["AVERAGE"], "offline") {
		t.Fatalf("AVERAGE trigger does not describe an offline agent: %q", priorities["AVERAGE"])
	}
	if !strings.Contains(strings.ToLower(priorities["WARNING"]), "drift") {
		t.Fatalf("WARNING trigger does not describe drift: %q", priorities["WARNING"])
	}

	// The High trigger's operational data must surface the deep link.
	for _, rawTrigger := range triggers {
		trig := rawTrigger.(map[string]any)
		if trig["priority"] != "HIGH" {
			continue
		}
		opdata, _ := trig["opdata"].(string)
		if !strings.Contains(opdata, "statetrack.latest.link") {
			t.Fatalf("HIGH trigger opdata does not expose the deep link: %q", opdata)
		}
	}
}

func jsonPathUsed(item map[string]any, path string) bool {
	steps, _ := item["preprocessing"].([]any)
	for _, raw := range steps {
		step, _ := raw.(map[string]any)
		if step["type"] != "JSONPATH" {
			continue
		}
		params, _ := step["parameters"].([]any)
		for _, p := range params {
			if s, _ := p.(string); strings.TrimSpace(s) == path {
				return true
			}
		}
	}
	return false
}

func hasPreprocessing(item map[string]any, kind string) bool {
	steps, _ := item["preprocessing"].([]any)
	for _, raw := range steps {
		if step, _ := raw.(map[string]any); step["type"] == kind {
			return true
		}
	}
	return false
}
