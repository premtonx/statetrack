package discovery

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEmbeddedCatalogLoads is the guard that keeps the shipped manifest valid.
// Because the catalog is embedded with //go:embed, a malformed file is a build
// defect that only surfaces at runtime — so this test is what turns it into a
// failing test run instead of a silently empty recommendation queue in
// production.
func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatalf("embedded catalog failed to parse: %v", err)
	}
	if c.Version != CatalogVersion {
		t.Errorf("version = %d, want %d", c.Version, CatalogVersion)
	}
	if len(c.Entries) == 0 {
		t.Fatal("catalog has no entries")
	}
	if len(c.Profiles) == 0 {
		t.Fatal("catalog has no profiles")
	}
}

// TestCatalogCoversEveryRuntime asserts the shipped catalog actually spans the
// four runtime environments the specification calls for. Without this, a
// mis-typed `runtime:` key would silently drop an entire environment from
// discovery and every other test would still pass.
func TestCatalogCoversEveryRuntime(t *testing.T) {
	c := MustCatalog()
	for _, runtime := range []string{RuntimeLinux, RuntimeWindows, RuntimeDocker, RuntimeKubernetes} {
		if got := c.EntriesForRuntime(runtime); len(got) == 0 {
			t.Errorf("catalog has no entries for runtime %q", runtime)
		}
	}
}

// TestCatalogRequiredCoverage pins the specific applications the specification
// requires, by entry id. It is deliberately a list of ids rather than a count:
// a count would pass if someone removed Nginx and added two unrelated entries.
func TestCatalogRequiredCoverage(t *testing.T) {
	required := map[string]string{
		// Linux web servers and proxies.
		"nginx": RuntimeLinux, "apache": RuntimeLinux, "caddy": RuntimeLinux, "haproxy": RuntimeLinux,
		// Linux databases.
		"postgresql": RuntimeLinux, "mysql": RuntimeLinux, "redis": RuntimeLinux,
		// Linux brokers.
		"rabbitmq": RuntimeLinux, "kafka": RuntimeLinux,
		// Core system and security.
		"etc_passwd": RuntimeLinux, "etc_shadow": RuntimeLinux, "sudoers": RuntimeLinux,
		"sshd": RuntimeLinux, "systemd_units": RuntimeLinux, "sysctl": RuntimeLinux,
		// Windows.
		"iis": RuntimeWindows, "mssql": RuntimeWindows, "rabbitmq_windows": RuntimeWindows,
		"msmq": RuntimeWindows, "hklm_software": RuntimeWindows, "windows_services": RuntimeWindows,
		"windows_scheduled_tasks": RuntimeWindows,
		// Docker.
		"docker_daemon": RuntimeDocker, "docker_compose": RuntimeDocker, "docker_volumes": RuntimeDocker,
		// Kubernetes.
		"k8s_configmap": RuntimeKubernetes, "k8s_secret": RuntimeKubernetes,
		"k8s_deployment": RuntimeKubernetes, "k8s_statefulset": RuntimeKubernetes,
		"k8s_ingress": RuntimeKubernetes,
	}
	c := MustCatalog()
	for id, runtime := range required {
		e, ok := c.Entry(id)
		if !ok {
			t.Errorf("catalog is missing required entry %q", id)
			continue
		}
		if e.Runtime != runtime {
			t.Errorf("entry %q runtime = %q, want %q", id, e.Runtime, runtime)
		}
		if len(e.Targets) == 0 {
			t.Errorf("entry %q has no targets", id)
		}
	}
}

// TestKubernetesEntriesHaveNoHostTarget documents the invariant the probe engine
// relies on to decide whether an entry belongs to a host scan.
func TestKubernetesEntriesHaveNoHostTarget(t *testing.T) {
	c := MustCatalog()
	for _, e := range c.EntriesForRuntime(RuntimeKubernetes) {
		if hasHostTarget(e) {
			t.Errorf("kubernetes entry %q must not be host-scannable", e.ID)
		}
	}
	// And no host entry may be Kubernetes-only.
	for _, runtime := range []string{RuntimeLinux, RuntimeWindows, RuntimeDocker} {
		for _, e := range c.EntriesForRuntime(runtime) {
			if !hasHostTarget(e) {
				t.Errorf("host entry %q (%s) has no scannable target", e.ID, runtime)
			}
		}
	}
}

// TestCatalogProbersAreDeterministicAndDeduplicated checks probe registration:
// a stable order (so "the first N matches" means the same N every scan) and no
// entry registered twice when a host declares several runtimes.
func TestCatalogProbersAreDeterministicAndDeduplicated(t *testing.T) {
	probers := CatalogProbers(RuntimeLinux, RuntimeDocker)
	if len(probers) == 0 {
		t.Fatal("no probes registered for a Linux host")
	}
	seen := make(map[string]bool, len(probers))
	for i, p := range probers {
		if p.Name == "" {
			t.Errorf("probe %d has no name", i)
		}
		if seen[p.Name] {
			t.Errorf("probe %q registered twice", p.Name)
		}
		seen[p.Name] = true
		if p.Probe == nil {
			t.Errorf("probe %q has a nil function", p.Name)
		}
	}
	// The docker runtime must contribute probes to a Linux host.
	if !seen["catalog:docker_daemon"] {
		t.Error("a Linux host should probe for the Docker daemon")
	}
	// A Kubernetes entry must never be registered as a host probe.
	if seen["catalog:k8s_configmap"] {
		t.Error("Kubernetes entries must not be registered as host probes")
	}
}

// TestParseCatalogRejectsInvalidManifests covers the validation that makes a
// hand-edited catalog fail loudly rather than half-work.
func TestParseCatalogRejectsInvalidManifests(t *testing.T) {
	valid := `
version: 1
profiles:
  web_server: {default_level: 3, diff: true}
entries:
  - id: nginx
    name: Nginx
    runtime: linux
    profile: web_server
    targets:
      - kind: file_glob
        parser: nginx
        patterns: [/etc/nginx/nginx.conf]
`
	tests := map[string]struct{ yaml, want string }{
		"wrong version": {
			yaml: strings.Replace(valid, "version: 1", "version: 99", 1),
			want: "version",
		},
		"no entries": {
			yaml: "version: 1\nprofiles:\n  web_server: {default_level: 3}\n",
			want: "no entries",
		},
		"missing id": {
			yaml: strings.Replace(valid, "id: nginx", "id: \"\"", 1),
			want: "no id",
		},
		"duplicate id": {
			yaml: valid + strings.Replace(valid[strings.Index(valid, "entries:"):], "entries:", "", 1),
			want: "duplicated",
		},
		"unknown profile": {
			yaml: strings.Replace(valid, "profile: web_server", "profile: nope", 1),
			want: "unknown profile",
		},
		"no targets": {
			yaml: strings.Replace(valid, "    targets:\n      - kind: file_glob\n        parser: nginx\n        patterns: [/etc/nginx/nginx.conf]\n", "", 1),
			want: "no targets",
		},
		"unknown field": {
			yaml: valid + "    bogus_field: 1\n",
			want: "field bogus_field",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseCatalog([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestCatalogProfileFallsBackForUnknownName ensures a hand-edited catalog
// degrades to a conservative drift tier instead of panicking.
func TestCatalogProfileFallsBackForUnknownName(t *testing.T) {
	c := &Catalog{}
	p := c.Profile("does-not-exist")
	if p.DefaultLevel != LevelDrift {
		t.Errorf("fallback default_level = %d, want %d", p.DefaultLevel, LevelDrift)
	}
	if p.Diff {
		t.Error("fallback profile must not capture a full text diff")
	}
}

// TestCatalogDigestIsStableAndShort documents the fingerprint reported in the
// discovery log so two hosts can be compared without diffing binaries.
func TestCatalogDigestIsStableAndShort(t *testing.T) {
	d := CatalogDigest()
	if len(d) != 12 {
		t.Errorf("digest %q is not 12 hex chars", d)
	}
	if d != CatalogDigest() {
		t.Error("digest is not stable across calls")
	}
}

// ---------------------------------------------------------------------------
// Smart risk tiering
// ---------------------------------------------------------------------------

// TestTierProductionWorkloadsAreCritical is the core of Part 1's risk heuristics:
// a production-facing workload must be suggested as Level 1 Critical with a full
// text diff.
func TestTierProductionWorkloadsAreCritical(t *testing.T) {
	c := MustCatalog()
	web := c.Profile("web_server")

	tests := []struct {
		name      string
		kind      string
		instance  string
		path      string
		ports     []int
		https     bool
		wantLevel int
		wantSig   string
	}{
		{
			name: "HTTPS vhost on 443", kind: "nginx vhost", instance: "shop.example.com",
			path: "/etc/nginx/sites-enabled/shop.conf", ports: []int{443}, https: true,
			wantLevel: LevelCritical, wantSig: "https_bind",
		},
		{
			// An IIS site whose binding is https but whose config only records
			// the protocol: the parser sets HTTPS without a port list.
			name: "IIS HTTPS site", kind: "IIS site", instance: "CheckoutApp",
			path: `C:\inetpub\wwwroot\checkout\web.config`, https: true,
			wantLevel: LevelCritical, wantSig: "https_bind",
		},
		{
			name: "production name on plain HTTP", kind: "nginx vhost", instance: "api.example.com",
			path: "/etc/nginx/conf.d/api.conf", ports: []int{80},
			wantLevel: LevelCritical, wantSig: "production_name",
		},
		{
			name: "wildcard www site", kind: "IIS site", instance: "www",
			path: `C:\inetpub\wwwroot\web.config`, ports: []int{8080},
			wantLevel: LevelCritical, wantSig: "production_name",
		},
		{
			name: "staging path downgrades even on 443", kind: "nginx vhost", instance: "staging.example.com",
			path: "/etc/nginx/sites-enabled/staging.conf", ports: []int{443}, https: true,
			wantLevel: LevelDrift, wantSig: "staging_name",
		},
		{
			name: "dev name on 8443", kind: "nginx vhost", instance: "dev-portal.example.com",
			path: "/etc/nginx/conf.d/dev.conf", ports: []int{8443}, https: true,
			wantLevel: LevelDrift, wantSig: "staging_name",
		},
		{
			// The dangerous direction: a production vhost living under
			// /usr/local/ must not be downgraded merely because a naive
			// substring test would find "test" inside "latest".
			name: "production path with a misleading parent dir", kind: "nginx vhost",
			instance: "checkout.example.com", path: "/opt/latest/conf/checkout.conf",
			ports: []int{443}, https: true,
			wantLevel: LevelCritical, wantSig: "https_bind",
		},
		{
			// A bare :80 bind is deliberately not a production signal.
			name: "default site on 80", kind: "IIS site", instance: "Default Web Site",
			path: `C:\inetpub\wwwroot\web.config`, ports: []int{80},
			wantLevel: LevelDrift, wantSig: "default",
		},
		{
			name: "unclassified vhost", kind: "nginx vhost", instance: "static.example.com",
			path: "/etc/nginx/conf.d/static.conf", ports: []int{8080},
			wantLevel: LevelDrift, wantSig: "default",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := web.Tier(tc.kind, tc.instance, tc.path, tc.ports, tc.https)
			if got.Level != tc.wantLevel {
				t.Errorf("level = %d, want %d (reason: %s)", got.Level, tc.wantLevel, got.Reason)
			}
			if got.Signal != tc.wantSig {
				t.Errorf("signal = %q, want %q", got.Signal, tc.wantSig)
			}
			if !got.Diff {
				t.Error("web_server profile must capture a full text diff")
			}
			if got.Reason == "" {
				t.Error("tier reason must never be empty")
			}
		})
	}
}

// TestTierForcedLevelsAreAlwaysCritical covers the "any live instance is
// production" families: databases, caches, brokers, and core system/security
// configuration.
func TestTierForcedLevelsAreAlwaysCritical(t *testing.T) {
	c := MustCatalog()
	entries := []string{"postgresql", "mysql", "redis", "rabbitmq", "kafka", "etc_shadow", "sudoers", "sshd", "sysctl"}
	for _, id := range entries {
		e, ok := c.Entry(id)
		if !ok {
			t.Errorf("catalog is missing entry %q", id)
			continue
		}
		p := c.Profile(e.Profile)
		if p.ForceLevel != LevelCritical {
			t.Errorf("entry %q profile %q force_level = %d, want %d", id, e.Profile, p.ForceLevel, LevelCritical)
		}
		// A forced profile must be immune to staging names: a file path is
		// never a reason to stop watching /etc/shadow.
		got := p.Tier("configuration file", "staging-"+id, "/tmp/staging/"+id, nil, false)
		if got.Level != LevelCritical {
			t.Errorf("forced tier for %q = %d, want %d", id, got.Level, LevelCritical)
		}
	}
}

// TestTierVolumeMountsAreHashOnly covers the counter-case: container volume
// contents are tiered as Drift with no diff, because they are huge and mostly
// opaque.
func TestTierVolumeMountsAreHashOnly(t *testing.T) {
	c := MustCatalog()
	e, ok := c.Entry("docker_volumes")
	if !ok {
		t.Fatal("catalog has no docker_volumes entry")
	}
	p := c.Profile(e.Profile)
	if p.ForceLevel != LevelDrift {
		t.Errorf("force_level = %d, want %d", p.ForceLevel, LevelDrift)
	}
	if p.Diff {
		t.Error("volume mounts must not capture a full text diff")
	}
	got := p.Tier("configuration directory", "volumes", "/var/lib/docker/volumes", nil, false)
	if got.Level != LevelDrift || got.Diff {
		t.Errorf("volume tier = %+v, want drift with no diff", got)
	}
}

// TestKubernetesTieringUsesNamespaceProfile covers the namespace-sensitive
// rule: production namespaces get the scrubbed-YAML diff, non-production ones
// get metadata and a hash only.
func TestKubernetesTieringUsesNamespaceProfile(t *testing.T) {
	c := MustCatalog()
	e, ok := c.Entry("k8s_configmap")
	if !ok {
		t.Fatal("catalog has no k8s_configmap entry")
	}
	if e.DevProfile == "" {
		t.Fatal("k8s_configmap must declare a dev_profile")
	}

	prod := c.ProfileForKubernetes(e, "payments")
	if prod.ForceLevel != LevelCritical || !prod.Diff {
		t.Errorf("production namespace profile = %+v, want critical with diff", prod)
	}
	for _, ns := range []string{"staging", "dev", "test", "kube-system", "default"} {
		p := c.ProfileForKubernetes(e, ns)
		if p.ForceLevel != LevelDrift || p.Diff {
			t.Errorf("namespace %q profile = %+v, want drift with no diff", ns, p)
		}
	}
}

// TestIsStagingNamespace covers the explicit list plus the profile's staging
// patterns, case-insensitively.
func TestIsStagingNamespace(t *testing.T) {
	c := MustCatalog()
	e, _ := c.Entry("k8s_secret")
	tests := map[string]bool{
		"payments":    false,
		"production":  false,
		"STAGING":     true,
		"dev":         true,
		"test":        true,
		"kube-system": true,
		"ci":          true,
	}
	for ns, want := range tests {
		if got := c.IsStagingNamespace(e, ns); got != want {
			t.Errorf("IsStagingNamespace(%q) = %v, want %v", ns, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

// TestMatchesAnyIsTokenAware pins the matching semantics that the tiering
// heuristics depend on. The false-positive cases matter more than the positive
// ones: an over-eager staging match silently under-tiers a production workload.
func TestMatchesAnyIsTokenAware(t *testing.T) {
	staging := []string{"stag", "stage", "staging", "dev", "test", "qa"}
	tests := []struct {
		value string
		want  bool
		why   string
	}{
		{"staging-api", true, "exact token"},
		{"Staging.Example.COM", true, "case-insensitive, token boundary at the dot"},
		{`C:\sites\staging-api`, true, "token inside a Windows path"},
		{"dev", true, "whole value is a token"},
		{"/opt/latest/nginx.conf", false, "'latest' is not 'test'"},
		{"/usr/local/nginx/conf/nginx.conf", false, "'local' is not a staging token"},
		{"/var/www/protest/index.html", false, "'protest' is not 'test'"},
		{"/srv/contest", false, "'contest' is not 'test'"},
		{"", false, "empty value"},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			if got := matchesAny(staging, tc.value); got != tc.want {
				t.Errorf("matchesAny(%q) = %v, want %v (%s)", tc.value, got, tc.want, tc.why)
			}
		})
	}
}

// TestMatchSignalHandlesHyphenatedPatterns covers the exception to tokenising:
// a pattern that contains a separator is matched as a substring too, so
// "non-prod" and "pre-prod" work despite tokenising splitting them.
func TestMatchSignalHandlesHyphenatedPatterns(t *testing.T) {
	patterns := []string{"non-prod", "pre-prod"}
	for _, v := range []string{"non-prod-cluster", "pre-prod.example.com"} {
		if !matchesAny(patterns, v) {
			t.Errorf("matchesAny(%v, %q) = false, want true", patterns, v)
		}
	}
	if matchesAny(patterns, "production") {
		t.Error("'production' must not match a 'non-prod' pattern")
	}
}

// TestFirstSignalReportsTheMatchingPattern keeps the tier reason sentence
// honest: it must name the pattern that actually fired.
func TestFirstSignalReportsTheMatchingPattern(t *testing.T) {
	got := firstSignal([]string{"prod", "staging", "dev"}, "staging-api")
	if got != "staging" {
		t.Errorf("firstSignal = %q, want %q", got, "staging")
	}
	if got := firstSignal([]string{"prod"}, "unrelated"); got != "unknown" {
		t.Errorf("firstSignal with no match = %q, want %q", got, "unknown")
	}
}

// ---------------------------------------------------------------------------
// Target expansion helpers
// ---------------------------------------------------------------------------

// TestExpandVarsLeavesUnsetVariablesInert is the safety property behind Windows
// pattern expansion: an unset variable must not collapse a pattern into a
// relative path that could match an unrelated file.
func TestExpandVarsLeavesUnsetVariablesInert(t *testing.T) {
	const unset = "STATETRACK_TEST_UNSET_VAR"
	os.Unsetenv(unset)

	got := expandVars(`%` + unset + `%\advanced.config`)
	if !strings.Contains(got, "%"+unset+"%") {
		t.Errorf("expandVars collapsed an unset variable to %q; it must stay inert", got)
	}

	t.Setenv("STATETRACK_TEST_SET_VAR", `C:\RabbitMQ`)
	got = expandVars(`%STATETRACK_TEST_SET_VAR%\advanced.config`)
	if got != `C:\RabbitMQ\advanced.config` {
		t.Errorf("expandVars with a set variable = %q", got)
	}
}

// TestWalkConfigFilesRespectsBounds covers the caps that keep a broad directory
// from flooding the review queue or stalling the scan.
func TestWalkConfigFilesRespectsBounds(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		writeFile(t, filepath.Join(root, "sub", "deep", "verydeep", "f"+string(rune('a'+i))+".conf"), "x")
	}
	writeFile(t, filepath.Join(root, "top.conf"), "x")

	// Depth 1 from root must not descend into sub/.
	shallow := walkConfigFiles(root, 1, []string{".conf"}, 100)
	for _, f := range shallow {
		if strings.Contains(filepath.ToSlash(f), "/sub/") {
			t.Errorf("depth 1 walk descended into a subdirectory: %q", f)
		}
	}

	// The file cap must be enforced during the walk, not after it.
	capped := walkConfigFiles(root, 4, []string{".conf"}, 5)
	if len(capped) > 5 {
		t.Errorf("walk returned %d files, want at most 5", len(capped))
	}

	// The result must be deterministic, so "the first N matches" is stable
	// across scans and a recommendation does not flicker in the console.
	again := walkConfigFiles(root, 4, []string{".conf"}, 5)
	if strings.Join(capped, "|") != strings.Join(again, "|") {
		t.Error("walkConfigFiles is not deterministic")
	}

	// A missing root is "not found", not an error.
	if got := walkConfigFiles(filepath.Join(root, "nope"), 2, nil, 10); got != nil {
		t.Errorf("missing root returned %v, want nil", got)
	}
}

// TestWalkConfigFilesFiltersByExtensionAndSkipsNoise covers the extension
// filter and the noise-directory skip list.
func TestWalkConfigFilesFiltersByExtensionAndSkipsNoise(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.service"), "x")
	writeFile(t, filepath.Join(root, "b.txt"), "x")
	writeFile(t, filepath.Join(root, "node_modules", "c.service"), "x")

	got := walkConfigFiles(root, 2, []string{".service"}, 50)
	if len(got) != 1 || filepath.Base(got[0]) != "a.service" {
		t.Errorf("walk = %v, want only a.service", got)
	}
}

// ---------------------------------------------------------------------------
// Documentation drift
// ---------------------------------------------------------------------------

// TestCatalogDocumentedInDocs fails the build when an entry exists in the
// embedded manifest but is missing from the human-facing reference. Without it
// the manifest and the documentation silently diverge, and the reference — the
// artifact a security team actually reviews — becomes untrustworthy.
func TestCatalogDocumentedInDocs(t *testing.T) {
	docsPath := filepath.Join("..", "..", "..", "docs", "enterprise-catalog.md")
	raw, err := os.ReadFile(docsPath)
	if err != nil {
		t.Fatalf("read %s: %v", docsPath, err)
	}
	doc := string(raw)

	// Only the Coverage section's tables list entries, by id, in the first
	// column. Scoping to it keeps the check precise: the schema and parser
	// tables elsewhere in the document also use backticked identifiers, and
	// they are not entry ids.
	coverage, ok := sectionBetween(doc, "## Coverage", "## Windows variable expansion")
	if !ok {
		t.Fatal("docs/enterprise-catalog.md has no Coverage section")
	}

	c := MustCatalog()
	documented := make(map[string]bool)
	for _, m := range docCoverageRow.FindAllStringSubmatch(coverage, -1) {
		documented[m[1]] = true
	}
	for _, e := range c.Entries {
		if !documented[e.ID] {
			t.Errorf("catalog entry %q is not documented in docs/enterprise-catalog.md", e.ID)
		}
	}
	// And the coverage tables must not advertise entries that no longer exist.
	for id := range documented {
		if _, ok := c.Entry(id); !ok {
			t.Errorf("docs/enterprise-catalog.md documents %q, which is not in the catalog", id)
		}
	}

	// Every runtime must be spelled out, since a missing one means an entire
	// environment silently stopped being scanned.
	for _, runtime := range []string{RuntimeLinux, RuntimeWindows, RuntimeDocker, RuntimeKubernetes} {
		if !strings.Contains(coverage, runtime) {
			t.Errorf("the Coverage section never mentions runtime %q", runtime)
		}
	}
}

// docCoverageRow matches a coverage table row: a line whose first column is a
// backticked identifier, e.g. "| `nginx` | Nginx | /etc/nginx/** |".
var docCoverageRow = regexp.MustCompile(`(?m)^\|\s*` + "`([a-z0-9_]+)`" + `\s*\|`)

// sectionBetween returns the text between two headings, reporting whether both
// were found.
func sectionBetween(doc, start, end string) (string, bool) {
	i := strings.Index(doc, start)
	if i < 0 {
		return "", false
	}
	rest := doc[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		return rest, true
	}
	return rest[:j], true
}
