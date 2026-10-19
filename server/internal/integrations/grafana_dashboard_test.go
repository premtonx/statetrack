package integrations

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// statetrackMetric matches a metric name used in a PromQL expression.
var statetrackMetric = regexp.MustCompile(`\b(statetrack_[a-z0-9_]+)\b`)

// loadDashboard decodes the provisioned dashboard, which Grafana rejects
// outright on a malformed file.
func loadDashboard(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(repoFile(t, "integrations/grafana/statetrack-overview-dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var dash map[string]any
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	return dash
}

// panelByTitle finds a panel by its exact title, so the assertions below read as
// "what the viewer sees" rather than by array index.
func panelByTitle(t *testing.T, dash map[string]any, title string) map[string]any {
	t.Helper()
	panels, _ := dash["panels"].([]any)
	for _, rawPanel := range panels {
		panel, _ := rawPanel.(map[string]any)
		if got, _ := panel["title"].(string); got == title {
			return panel
		}
	}
	t.Fatalf("dashboard has no panel titled %q", title)
	return nil
}

// panelSQL joins every SQL target of a panel, so an assertion can look at the
// whole query rather than at one refId.
func panelSQL(panel map[string]any) string {
	targets, _ := panel["targets"].([]any)
	var out []string
	for _, rawTarget := range targets {
		target, _ := rawTarget.(map[string]any)
		if sql, _ := target["rawSql"].(string); sql != "" {
			out = append(out, sql)
		}
	}
	return strings.Join(out, "\n")
}

// panelExpr joins every PromQL target of a panel.
func panelExpr(panel map[string]any) string {
	targets, _ := panel["targets"].([]any)
	var out []string
	for _, rawTarget := range targets {
		target, _ := rawTarget.(map[string]any)
		if expr, _ := target["expr"].(string); expr != "" {
			out = append(out, expr)
		}
	}
	return strings.Join(out, "\n")
}

// TestGrafanaDashboardIsImportable validates the provisioned dashboard envelope:
// the fields Grafana rejects outright, and the identity that makes a re-import
// update rather than duplicate.
func TestGrafanaDashboardIsImportable(t *testing.T) {
	dash := loadDashboard(t)

	if title, _ := dash["title"].(string); title != "StateTrack – Change Impact" {
		t.Fatalf("dashboard title = %q, want the designed %q", title, "StateTrack – Change Impact")
	}
	// Grafana requires a stable uid so re-importing updates the existing
	// dashboard instead of creating a duplicate.
	if uid, _ := dash["uid"].(string); uid == "" {
		t.Fatal("dashboard has no uid; a re-import would duplicate it")
	}

	panels, ok := dash["panels"].([]any)
	if !ok || len(panels) == 0 {
		t.Fatal("dashboard has no panels")
	}

	// The default window is the design's: one hour. A wider default would leave
	// the seeded timeline squeezed into a fraction of the width; a narrower one
	// would put the oldest flag off the left edge.
	timeRange, _ := dash["time"].(map[string]any)
	if timeRange["from"] != "now-1h" {
		t.Fatalf("dashboard time.from = %v, want now-1h", timeRange["from"])
	}

	// The KPI grid must be at the very top. Grafana renders panels in y/x order,
	// so a gridPos that does not start at y=0 silently pushes the headline below
	// whatever is there instead.
	for _, title := range []string{"Critical changes", "Changes / minute", "Hosts affected", "Agents online"} {
		panel := panelByTitle(t, dash, title)
		gridPos, _ := panel["gridPos"].(map[string]any)
		if y, _ := gridPos["y"].(float64); y != 0 {
			t.Errorf("%q is at y=%v, want 0 (the top row)", title, gridPos["y"])
		}
		if panel["type"] != "stat" {
			t.Errorf("%q type = %v, want stat", title, panel["type"])
		}
	}
	for _, title := range []string{"Tracked targets", "Storm throttles", "Notification deliveries", "Change categories"} {
		panel := panelByTitle(t, dash, title)
		gridPos, _ := panel["gridPos"].(map[string]any)
		if y, _ := gridPos["y"].(float64); y != 3 {
			t.Errorf("%q is at y=%v, want 3 (the second KPI row)", title, gridPos["y"])
		}
	}

	// Every datasource reference must be one of the two provisioned ones. A
	// `${DS_POSTGRES}` that resolved to nothing is the "No data everywhere" bug.
	for _, rawPanel := range panels {
		panel, _ := rawPanel.(map[string]any)
		for _, rawTarget := range asSlice(panel["targets"]) {
			target, _ := rawTarget.(map[string]any)
			ds, _ := target["datasource"].(map[string]any)
			uid, _ := ds["uid"].(string)
			if uid != "${DS_PROMETHEUS}" && uid != "${DS_POSTGRES}" {
				t.Errorf("panel %v targets unexpected datasource %q", panel["title"], uid)
			}
		}
	}
}

// TestGrafanaDashboardLayoutMatchesDesign locks the five zones the dashboard is
// specified as: a two-row KPI grid, the hero panel, a three-column breakdown
// row, and a two-column detail row. Each assertion maps onto something a viewer
// would notice missing in a screenshot, which is the kind of regression a JSON
// diff hides.
func TestGrafanaDashboardLayoutMatchesDesign(t *testing.T) {
	dash := loadDashboard(t)

	gridOf := func(title string) (x, y, w, h float64) {
		gridPos, _ := panelByTitle(t, dash, title)["gridPos"].(map[string]any)
		num := func(key string) float64 { v, _ := gridPos[key].(float64); return v }
		return num("x"), num("y"), num("w"), num("h")
	}

	// Zone 2: the hero is full width, directly under the KPI grid, and tall
	// enough to read a spike against its annotation.
	if x, y, w, h := gridOf("Infrastructure signals + change events"); x != 0 || w != 24 || y != 6 || h != 9 {
		t.Errorf("hero gridPos = x%v y%v w%v h%v, want x0 y6 w24 h9", x, y, w, h)
	}

	// Zone 3: three equal columns.
	for i, title := range []string{"Changes by impact over time", "Top affected hosts", "Change distribution by category"} {
		x, y, w, h := gridOf(title)
		if x != float64(i*8) || y != 15 || w != 8 || h != 8 {
			t.Errorf("%q gridPos = x%v y%v w%v h%v, want x%d y15 w8 h8", title, x, y, w, h, i*8)
		}
	}

	// Zone 4: the change table takes two thirds, the health panel one third.
	if x, y, w, h := gridOf("Recent critical changes"); x != 0 || y != 23 || w != 16 || h != 8 {
		t.Errorf("recent changes gridPos = x%v y%v w%v h%v, want x0 y23 w16 h8", x, y, w, h)
	}
	if x, y, w, h := gridOf("Pipeline & system health"); x != 16 || y != 23 || w != 8 || h != 8 {
		t.Errorf("health gridPos = x%v y%v w%v h%v, want x16 y23 w8 h8", x, y, w, h)
	}

	// Panel types are part of the design: a stacked bar chart, two tables and a
	// donut are not interchangeable with a line chart.
	for title, want := range map[string]string{
		"Changes by impact over time":            "timeseries",
		"Top affected hosts":                     "table",
		"Change distribution by category":        "piechart",
		"Recent critical changes":                "table",
		"Pipeline & system health":               "table",
		"Infrastructure signals + change events": "timeseries",
	} {
		if got := panelByTitle(t, dash, title)["type"]; got != want {
			t.Errorf("%q type = %v, want %v", title, got, want)
		}
	}
}

// TestGrafanaHeroPanelSpikesAlignWithAnnotations is the core of the design: the
// error-rate line must spike at the exact timestamps a change was flagged, or
// the panel's whole premise ("this change caused this spike") is a lie.
//
// The invariant is structural rather than numeric: the hero query derives its
// spike from the *same* events rows the annotations are posted from, at the same
// one-minute truncation. Asserting on the SQL is what makes that checkable
// without a live database.
func TestGrafanaHeroPanelSpikesAlignWithAnnotations(t *testing.T) {
	dash := loadDashboard(t)
	hero := panelByTitle(t, dash, "Infrastructure signals + change events")
	sql := panelSQL(hero)

	// A full hour of buckets, generated rather than scraped: this is what makes
	// the panel populated the moment the stack boots instead of an hour later.
	// The series spans the panel's own time range; the dashboard defaults that to
	// now-1h..now, so the grid is 60 one-minute points on first paint.
	if !strings.Contains(sql, "generate_series") {
		t.Errorf("hero query does not generate its own timeline:\n%s", sql)
	}
	for _, want := range []string{"$__timeFrom()", "$__timeTo()", "interval '1 minute'"} {
		if !strings.Contains(sql, want) {
			t.Errorf("hero query does not build a one-minute grid over the panel range (%q missing):\n%s", want, sql)
		}
	}

	// The spike must be driven by the L1 events, truncated to the minute so it
	// lands on the same bucket as the annotation.
	if !strings.Contains(sql, "impact_level = 1") {
		t.Errorf("hero query does not derive its spike from Level 1 events:\n%s", sql)
	}
	if !strings.Contains(sql, "date_trunc('minute'") {
		t.Errorf("hero query does not truncate to the minute, so spikes would miss their flag:\n%s", sql)
	}

	// Three series, coloured as the design specifies.
	overrides, _ := hero["fieldConfig"].(map[string]any)
	props, _ := overrides["overrides"].([]any)
	colors := map[string]string{}
	for _, rawOverride := range props {
		override, _ := rawOverride.(map[string]any)
		matcher, _ := override["matcher"].(map[string]any)
		name, _ := matcher["options"].(string)
		for _, rawProp := range asSlice(override["properties"]) {
			prop, _ := rawProp.(map[string]any)
			if prop["id"] != "color" {
				continue
			}
			value, _ := prop["value"].(map[string]any)
			fixed, _ := value["fixedColor"].(string)
			colors[name] = fixed
		}
	}
	for name, want := range map[string]string{
		"CPU utilization": "#22c55e",
		"Latency (p95)":   "#3b82f6",
		"Error rate":      "#ef4444",
	} {
		if colors[name] != want {
			t.Errorf("hero series %q colour = %q, want %q", name, colors[name], want)
		}
		if !strings.Contains(sql, `AS "`+name+`"`) {
			t.Errorf("hero query has no %q column", name)
		}
	}
}

// TestGrafanaAnnotationsArePointsScopedToTheHero guards the two annotation bugs
// that made the dashboard unreadable: region curtains (a `timeEnd` spanning the
// window, drawn as a translucent block over the data) and flags leaking onto
// every panel.
func TestGrafanaAnnotationsArePointsScopedToTheHero(t *testing.T) {
	dash := loadDashboard(t)

	heroID := panelByTitle(t, dash, "Infrastructure signals + change events")["id"]

	annotations, _ := dash["annotations"].(map[string]any)
	layers, _ := annotations["list"].([]any)
	if len(layers) == 0 {
		t.Fatal("dashboard declares no annotation layers")
	}

	var statetrackLayers int
	var levelsSeen []string
	for _, rawLayer := range layers {
		layer, _ := rawLayer.(map[string]any)
		target, _ := layer["target"].(map[string]any)
		if target["type"] != "tags" {
			continue
		}
		tags := asStrings(target["tags"])
		if !containsString(tags, "statetrack") {
			continue
		}
		statetrackLayers++

		// A point annotation is created by posting `time` alone; a region is
		// created by posting `timeEnd`. Nothing in the payload may reintroduce
		// the region form.
		for _, region := range []string{"timeEnd", "isRegion"} {
			if _, bad := layer[region]; bad {
				t.Errorf("annotation layer %v sets %q; the flag would render as a curtain", layer["name"], region)
			}
		}

		// The tags must be ANDed. With matchAny:true Grafana treats `statetrack`
		// and `level:L1` as alternatives, so the L1 layer also matches every L2
		// annotation and each change is drawn twice — once red and once amber, at
		// the same x. That is the "duplicate flags in two colours" symptom.
		if matchAny, ok := target["matchAny"].(bool); !ok || matchAny {
			t.Errorf("annotation layer %v matches any tag rather than all of them; every change would be drawn once per layer", layer["name"])
		}

		// Scoping: the layer must name the hero panel, not be dashboard-wide.
		filter, _ := layer["filter"].(map[string]any)
		ids := filter["ids"]
		if filter == nil || ids == nil {
			t.Errorf("annotation layer %v has no panel filter; it would draw on every panel", layer["name"])
			continue
		}
		list, _ := ids.([]any)
		if len(list) != 1 || list[0] != heroID {
			t.Errorf("annotation layer %v is scoped to panels %v, want only the hero (%v)", layer["name"], list, heroID)
		}
		if exclude, _ := filter["exclude"].(bool); exclude {
			t.Errorf("annotation layer %v excludes the hero; it would draw everywhere else", layer["name"])
		}

		// Colour is the level, and the level is a tag: one layer per level is
		// the only way Grafana can draw L1 red and L2 amber.
		for _, tag := range tags {
			if strings.HasPrefix(tag, "level:") {
				levelsSeen = append(levelsSeen, tag)
			}
		}
		icon, _ := layer["iconColor"].(string)
		switch {
		case containsString(tags, "level:L1") && icon != "#ef4444":
			t.Errorf("L1 layer iconColor = %q, want #ef4444", icon)
		case containsString(tags, "level:L2") && icon != "#f59e0b":
			t.Errorf("L2 layer iconColor = %q, want #f59e0b", icon)
		case !containsString(tags, "level:L1") && !containsString(tags, "level:L2"):
			t.Errorf("annotation layer %v matches no impact level", layer["name"])
		}

		// The toggles in the toolbar are noise for a fixed part of the panel's
		// meaning, so the layers are hidden from the picker while staying on.
		if hidden, _ := layer["hide"].(bool); !hidden {
			t.Errorf("annotation layer %v is not hidden from the toolbar", layer["name"])
		}
		if enabled, _ := layer["enable"].(bool); !enabled {
			t.Errorf("annotation layer %v is disabled; its flags would never draw", layer["name"])
		}
	}

	if statetrackLayers != 2 {
		t.Fatalf("found %d statetrack annotation layers, want 2 (one per level, so each can have its own colour)", statetrackLayers)
	}
	for _, want := range []string{"level:L1", "level:L2"} {
		if !containsString(levelsSeen, want) {
			t.Errorf("no annotation layer draws %s flags", want)
		}
	}
}

// TestGrafanaDashboardUsesPostgresForExactFigures locks in why the dashboard has
// two datasources. Prometheus can only answer "how fast is this counter moving",
// so a count expressed through it is a fractional rate that has to be rounded
// somewhere; Postgres holds the rows, so a count is an integer and a table is a
// table.
func TestGrafanaDashboardUsesPostgresForExactFigures(t *testing.T) {
	dash := loadDashboard(t)

	// The panels that must be exact: integers, rows, distinct values.
	for _, title := range []string{
		"Critical changes",
		"Tracked targets",
		"Storm throttles",
		"Notification deliveries",
		"Change categories",
		"Top affected hosts",
		"Change distribution by category",
		"Recent critical changes",
		"Pipeline & system health",
		"Infrastructure signals + change events",
	} {
		panel := panelByTitle(t, dash, title)
		targets := asSlice(panel["targets"])
		if len(targets) == 0 {
			t.Errorf("%q has no targets", title)
			continue
		}
		target, _ := targets[0].(map[string]any)
		ds, _ := target["datasource"].(map[string]any)
		if ds["uid"] != "${DS_POSTGRES}" {
			t.Errorf("%q reads from %v, want the Postgres datasource (exact rows, not a scrape)", title, ds["uid"])
		}
		if sql := panelSQL(panel); !strings.Contains(sql, "events") && !strings.Contains(sql, "hosts") &&
			!strings.Contains(sql, "host_current_state") && !strings.Contains(sql, "webhook_deliveries") {
			t.Errorf("%q query reads none of the event tables:\n%s", title, sql)
		}
	}

	// The integer cards must not carry decimals. A count rendered as "11.1" is
	// the specific bug this dashboard was rebuilt to fix, and it comes from a
	// rate() being displayed without pinning the precision.
	for _, title := range []string{"Critical changes", "Hosts affected", "Tracked targets", "Storm throttles", "Change categories"} {
		panel := panelByTitle(t, dash, title)
		fc, _ := panel["fieldConfig"].(map[string]any)
		defaults, _ := fc["defaults"].(map[string]any)
		if unit, _ := defaults["unit"].(string); unit == "percent" || unit == "reqps" {
			t.Errorf("%q unit = %q, want a plain count", title, unit)
		}
		if decimals, ok := defaults["decimals"]; ok && decimals != nil {
			if n, _ := decimals.(float64); n != 0 {
				t.Errorf("%q renders %v decimals, want an integer", title, n)
			}
		}
	}

	// The recent-changes table links each row into the console's diff drawer,
	// carrying the row's own id. Without that, the table is read-only trivia.
	recent := panelByTitle(t, dash, "Recent critical changes")
	sql := panelSQL(recent)
	for _, want := range []string{"AS \"Time\"", "AS \"Impact\"", "AS \"Host\"", "AS \"Target\"", "AS \"Actor\"",
		"AS \"Change summary\"", "AS \"StateTrack\"", "e.id::text AS \"id\""} {
		if !strings.Contains(sql, want) {
			t.Errorf("recent-changes query is missing the %s column", want)
		}
	}

	fc, _ := recent["fieldConfig"].(map[string]any)
	overrides, _ := fc["overrides"].([]any)
	var linkURL, impactMapping string
	for _, rawOverride := range overrides {
		override, _ := rawOverride.(map[string]any)
		matcher, _ := override["matcher"].(map[string]any)
		name, _ := matcher["options"].(string)
		for _, rawProp := range asSlice(override["properties"]) {
			prop, _ := rawProp.(map[string]any)
			switch prop["id"] {
			case "links":
				raw, _ := json.Marshal(prop["value"])
				linkURL = string(raw)
			case "mappings":
				raw, _ := json.Marshal(prop["value"])
				if name == "Impact" {
					impactMapping = string(raw)
				}
			}
		}
	}
	if !strings.Contains(linkURL, "/events/${__data.fields.id}?tab=diff") {
		t.Errorf("recent-changes rows have no diff deep link; got %q", linkURL)
	}
	// The badge colours are the level semantics: red, purple, amber.
	for _, want := range []string{"#ef4444", "#8b5cf6", "#f59e0b"} {
		if !strings.Contains(impactMapping, want) {
			t.Errorf("impact badge mapping is missing %s: %s", want, impactMapping)
		}
	}
}

// TestGrafanaTemplateVariablesMatchDesign pins the four filters and hides the
// datasource plumbing. A dashboard whose variable bar is a row of datasource
// pickers is not something an operator can hand to a colleague.
func TestGrafanaTemplateVariablesMatchDesign(t *testing.T) {
	dash := loadDashboard(t)

	templating, _ := dash["templating"].(map[string]any)
	vars, _ := templating["list"].([]any)

	byName := map[string]map[string]any{}
	for _, rawVar := range vars {
		v, _ := rawVar.(map[string]any)
		name, _ := v["name"].(string)
		byName[name] = v
	}

	// Environment is a fixed single value today; it exists so a multi-tenant
	// deployment has one switch.
	env := byName["environment"]
	if env == nil {
		t.Fatal("dashboard has no $environment variable")
	}
	if current, _ := env["current"].(map[string]any); current["text"] != "Production" {
		t.Errorf("$environment defaults to %v, want Production", current["text"])
	}

	// Host, impact and category are multi-select and default to All: one board
	// serves the whole fleet until someone narrows it.
	for _, name := range []string{"host", "impact", "category"} {
		v := byName[name]
		if v == nil {
			t.Fatalf("dashboard has no $%s variable", name)
		}
		if v["multi"] != true {
			t.Errorf("$%s is not multi-select", name)
		}
		if v["includeAll"] != true {
			t.Errorf("$%s has no All option", name)
		}
		current, _ := v["current"].(map[string]any)
		if current["value"] == nil {
			t.Errorf("$%s has no default selection", name)
		}
	}

	// The host list comes from the hosts table, so it is the enrolled fleet
	// rather than whatever a scrape happened to publish.
	host := byName["host"]
	if q, _ := host["query"].(string); !strings.Contains(q, "FROM hosts") {
		t.Errorf("$host query does not read the hosts table: %v", host["query"])
	}

	// Both datasources exist and are hidden, and both must be datasource-type
	// variables so the importer can bind them by uid.
	for _, name := range []string{"DS_PROMETHEUS", "DS_POSTGRES"} {
		v := byName[name]
		if v == nil {
			t.Fatalf("dashboard has no %s variable", name)
		}
		if v["type"] != "datasource" {
			t.Errorf("%s type = %v, want datasource", name, v["type"])
		}
		if hide, _ := v["hide"].(float64); hide != 2 {
			t.Errorf("%s hide = %v, want 2 (hidden)", name, v["hide"])
		}
	}
}

// TestGrafanaPanelsFilterOnlyHostLabelledMetrics keeps the original guard
// against filtering a metric that does not carry the host label. The dashboard
// is Postgres-first now, so this only applies to any PromQL left in it - which
// is intentional: the check stays so re-adding a Prometheus panel cannot
// silently reintroduce the "No data" bug.
func TestGrafanaPanelsFilterOnlyHostLabelledMetrics(t *testing.T) {
	dash := loadDashboard(t)

	hostLabelled := map[string]bool{
		"statetrack_mutations_total":       true,
		"statetrack_drift_targets":         true,
		"statetrack_active_agents":         true,
		"statetrack_storm_throttles_total": true,
	}
	notHostLabelled := map[string]bool{
		"statetrack_ingest_batch_duration_seconds": true,
		"statetrack_ingest_events_received_total":  true,
		"statetrack_webhook_deliveries_total":      true,
	}

	panels, _ := dash["panels"].([]any)
	for _, rawPanel := range panels {
		panel, _ := rawPanel.(map[string]any)
		expr := panelExpr(panel)
		if expr == "" || !strings.Contains(expr, "host=~") {
			continue
		}
		for _, m := range statetrackMetric.FindAllString(expr, -1) {
			if notHostLabelled[m] {
				t.Fatalf("panel %q filters %s by host, but that metric has no host label:\n%s",
					panel["title"], m, expr)
			}
			if !hostLabelled[m] && strings.HasPrefix(m, "statetrack_") {
				t.Fatalf("panel %q filters %s by host; add it to hostLabelled if it carries the label:\n%s",
					panel["title"], m, expr)
			}
		}
	}
}

// TestGrafanaStatCardsRenderValuesInsteadOfNoData guards the "Agents online:
// No data" bug.
//
// Grafana's stat panel drops a frame whose reduced fields are all strings unless
// `reduceOptions.fields` names the fields it should look at. The Agents card is
// the only one built from such a frame (it renders "4 / 4" and "100% healthy"
// rather than a number), so it is exactly the card that silently went blank
// while the same SQL returned rows through /api/ds/query.
func TestGrafanaStatCardsRenderValuesInsteadOfNoData(t *testing.T) {
	dash := loadDashboard(t)

	agents := panelByTitle(t, dash, "Agents online")
	options, _ := agents["options"].(map[string]any)
	reduce, _ := options["reduceOptions"].(map[string]any)
	if values, _ := reduce["values"].(bool); !values {
		t.Error("Agents online does not reduce to raw values; it would try to compute a statistic over strings and show No data")
	}
	if fields, _ := reduce["fields"].(string); fields == "" {
		t.Error("Agents online selects no field; an all-string frame renders as No data without an explicit field selection")
	}

	// The two values ("4 / 4" and "100% healthy") must both be visible, side by
	// side. textMode "value" is what suppresses the redundant series names.
	if mode, _ := options["textMode"].(string); mode != "value" {
		t.Errorf("Agents online textMode = %q, want value so the count and the health caption both show", mode)
	}

	// Every stat panel must avoid a numeric unit on a string column: that is what
	// turns "4 / 4" into No data even when the field selection is right.
	fc, _ := agents["fieldConfig"].(map[string]any)
	defaults, _ := fc["defaults"].(map[string]any)
	if unit, _ := defaults["unit"].(string); unit == "short" || unit == "percent" {
		t.Errorf("Agents online carries the numeric unit %q on a text frame", unit)
	}
}

// TestGrafanaTablesHideHelperColumnsCorrectly pins the property that actually
// hides a table column. `custom.hideFrom` only applies to time-series panels, so
// using it on a table leaves the helper column (`id`, `ord`) on screen — visible
// clutter that also pushes the real columns out of view.
func TestGrafanaTablesHideHelperColumnsCorrectly(t *testing.T) {
	dash := loadDashboard(t)

	for _, tc := range []struct{ title, column string }{
		{"Recent critical changes", "id"},
		{"Pipeline & system health", "ord"},
	} {
		panel := panelByTitle(t, dash, tc.title)
		fc, _ := panel["fieldConfig"].(map[string]any)
		overrides, _ := fc["overrides"].([]any)

		var found bool
		for _, rawOverride := range overrides {
			override, _ := rawOverride.(map[string]any)
			matcher, _ := override["matcher"].(map[string]any)
			if matcher["options"] != tc.column {
				continue
			}
			for _, rawProp := range asSlice(override["properties"]) {
				prop, _ := rawProp.(map[string]any)
				switch prop["id"] {
				case "custom.hidden":
					found = prop["value"] == true
				case "custom.hideFrom":
					t.Errorf("%s hides %q with custom.hideFrom, which table panels ignore", tc.title, tc.column)
				}
			}
		}
		if !found {
			t.Errorf("%s does not hide its %q helper column", tc.title, tc.column)
		}
	}
}

// TestGrafanaHostGaugeIsNotClamped catches a hard-coded gauge ceiling. The
// seeded fleet already exceeds 60 events/hour, so a max of 60 rendered every host
// as a full bar and the ranking lost the relative volume the column exists for.
func TestGrafanaHostGaugeIsNotClamped(t *testing.T) {
	panel := panelByTitle(t, loadDashboard(t), "Top affected hosts")
	fc, _ := panel["fieldConfig"].(map[string]any)
	overrides, _ := fc["overrides"].([]any)

	for _, rawOverride := range overrides {
		override, _ := rawOverride.(map[string]any)
		matcher, _ := override["matcher"].(map[string]any)
		if matcher["options"] != "volume" {
			continue
		}
		for _, rawProp := range asSlice(override["properties"]) {
			prop, _ := rawProp.(map[string]any)
			if prop["id"] == "max" {
				t.Errorf("volume gauge pins max to %v; the busiest host clips and the rest flatten", prop["value"])
			}
		}
	}
}

// TestGrafanaAgentsCardColoursByRenderedText pins the fix for the card that read
// a healthy fleet as red.
//
// The value is a *string* ("4 / 4"), which Grafana cannot compare to a numeric
// threshold: the comparison is `NaN < 4`, false, so the last threshold step wins
// and a perfectly healthy fleet renders in the critical colour. The colour has
// to come from value mappings that read the rendered text, and three details of
// Grafana's mapping engine are asserted here because each one silently produces
// the wrong card:
//
//   - a regex mapping pattern is matched against the whole value, so every
//     pattern must be anchored (`^…$`) or it never fires;
//   - `$0` is not substituted — only numbered capture groups are, so the text
//     has to be echoed back as `$1` / `$2` or the card loses its digits;
//   - `displayName` on a field renames it *before* `reduceOptions.fields`
//     selects it, which turns the panel into "No data".
func TestGrafanaAgentsCardColoursByRenderedText(t *testing.T) {
	panel := panelByTitle(t, loadDashboard(t), "Agents online")

	fc, _ := panel["fieldConfig"].(map[string]any)
	overrides, _ := fc["overrides"].([]any)

	mappings := map[string][]any{}
	var displayNames []string
	for _, rawOverride := range overrides {
		override, _ := rawOverride.(map[string]any)
		matcher, _ := override["matcher"].(map[string]any)
		name, _ := matcher["options"].(string)
		for _, rawProp := range asSlice(override["properties"]) {
			prop, _ := rawProp.(map[string]any)
			switch prop["id"] {
			case "mappings":
				mappings[name] = asSlice(prop["value"])
			case "displayName":
				displayNames = append(displayNames, name)
			}
		}
	}

	if len(displayNames) > 0 {
		t.Fatalf("Agents online renames fields %v; displayName runs before reduceOptions.fields and the card would read No data",
			displayNames)
	}
	for _, field := range []string{"Agents online", "healthy"} {
		if len(mappings[field]) == 0 {
			t.Fatalf("Agents online has no value mappings on %q; a string frame cannot be coloured by thresholds", field)
		}
	}

	// Every regex must be anchored and every result must echo its captures.
	colours := map[string]bool{}
	for field, rules := range mappings {
		for _, rawRule := range rules {
			rule, _ := rawRule.(map[string]any)
			if rule["type"] != "regex" {
				continue
			}
			opts, _ := rule["options"].(map[string]any)
			pattern, _ := opts["pattern"].(string)
			if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
				t.Errorf("%s mapping pattern %q is not anchored; Grafana matches the whole value", field, pattern)
			}
			if strings.Contains(pattern, "$0") {
				t.Errorf("%s mapping pattern %q uses $0, which Grafana does not substitute", field, pattern)
			}
			result, _ := opts["result"].(map[string]any)
			text, _ := result["text"].(string)
			if text == "" {
				t.Errorf("%s mapping %q has empty replacement text; Grafana treats that as no substitution", field, pattern)
			}
			if strings.Contains(text, "$0") || strings.Contains(text, "__value") {
				t.Errorf("%s mapping text %q relies on a placeholder Grafana does not expand", field, text)
			}
			if colour, _ := result["color"].(string); colour != "" {
				colours[colour] = true
			}
		}
	}

	// The two semantic colours the design specifies: healthy green, degraded red.
	for _, want := range []string{"#22c55e", "#ef4444"} {
		if !colours[want] {
			t.Errorf("no mapping uses %s; the card cannot distinguish healthy from degraded", want)
		}
	}

	// The healthy rule has to be a backreference, not a hardcoded "4 / 4": the
	// card must read green for a fleet of any size, and red the moment the two
	// numbers differ.
	var sawBackreference bool
	for _, rules := range mappings {
		for _, rawRule := range rules {
			rule, _ := rawRule.(map[string]any)
			opts, _ := rule["options"].(map[string]any)
			pattern, _ := opts["pattern"].(string)
			if strings.Contains(pattern, `\1`) {
				sawBackreference = true
			}
		}
	}
	if !sawBackreference {
		t.Error("no mapping compares the two counts with a backreference; the green rule would only work for the seeded fleet size")
	}
}

// asSlice coerces a decoded JSON array.
func asSlice(v any) []any {
	items, _ := v.([]any)
	return items
}

// asStrings coerces a decoded JSON array of strings.
func asStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// containsString reports whether hay contains needle.
func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
