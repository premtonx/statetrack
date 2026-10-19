package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// iisFixture is a trimmed applicationHost.config with an HTTPS production
// site, a plain HTTP site, and a staging site.
const iisFixture = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <sites>
      <site name="Default Web Site" id="1">
        <application path="/">
          <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" />
        </application>
        <bindings>
          <binding protocol="http" bindingInformation="*:80:" />
        </bindings>
      </site>
      <site name="CheckoutApp" id="2">
        <application path="/">
          <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot\checkout" />
        </application>
        <bindings>
          <binding protocol="https" bindingInformation="*:443:checkout.example.com" />
        </bindings>
      </site>
      <site name="staging-api" id="3">
        <application path="/">
          <virtualDirectory path="/" physicalPath="C:\sites\staging-api" />
        </application>
        <bindings>
          <binding protocol="http" bindingInformation="*:8080:" />
        </bindings>
      </site>
    </sites>
  </system.applicationHost>
</configuration>
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byName(ws []DiscoveredWorkload, name string) (DiscoveredWorkload, bool) {
	for _, w := range ws {
		if w.Name == name {
			return w, true
		}
	}
	return DiscoveredWorkload{}, false
}

// iisEntry returns the catalog's IIS entry, so these tests exercise the real
// embedded knowledge base rather than a hand-built fixture that could drift
// away from what the agent actually ships.
func iisEntry(t *testing.T) Entry {
	t.Helper()
	e, ok := MustCatalog().Entry("iis")
	if !ok {
		t.Fatal("embedded catalog has no iis entry")
	}
	return e
}

// parseIISFixture runs the real parse -> tier pipeline the probe engine runs,
// against one applicationHost.config file. Driving the production code path
// (rather than a reimplementation) is what keeps these assertions meaningful.
func parseIISFixture(t *testing.T, cfg string) []DiscoveredWorkload {
	t.Helper()
	c := MustCatalog()
	e := iisEntry(t)
	data, ok := readFileLimited(cfg)
	if !ok {
		return nil
	}
	target := targetWithParser(t, e, "iis")
	return c.workloads(e, []docPair{{target: target, doc: scanDoc{Path: cfg, Data: data}}})
}

// parseNginxRoots runs the pipeline for every nginx config under the given
// roots, using the catalog's own expansions.
func parseNginxRoots(t *testing.T, roots ...string) []DiscoveredWorkload {
	t.Helper()
	c := MustCatalog()
	e, ok := c.Entry("nginx")
	if !ok {
		t.Fatal("embedded catalog has no nginx entry")
	}
	var pairs []docPair
	for _, root := range roots {
		for _, target := range e.Targets {
			if target.Kind != TargetDirWalk {
				continue
			}
			// Point the target's pattern at the test root.
			target.Patterns = []string{root}
			for _, d := range c.expandTarget(target) {
				pairs = append(pairs, docPair{target: target, doc: d})
			}
		}
		// file_glob targets cannot be redirected at a temp dir, so expand the
		// root directly for the parser the entry uses.
		for _, target := range e.Targets {
			if target.Kind != TargetFileGlob {
				continue
			}
			for _, f := range walkConfigFiles(root, 2, []string{".conf"}, 50) {
				data, ok := readFileLimited(f)
				if !ok {
					continue
				}
				pairs = append(pairs, docPair{target: target, doc: scanDoc{Path: f, Data: data}})
			}
		}
	}
	return c.workloads(e, pairs)
}

// targetWithParser returns the entry's target that uses a given parser, so a
// test can drive the pipeline without hand-writing a Target.
func targetWithParser(t *testing.T, e Entry, parser string) Target {
	t.Helper()
	for _, target := range e.Targets {
		if target.Parser == parser {
			return target
		}
	}
	t.Fatalf("entry %q has no target with parser %q", e.ID, parser)
	return Target{}
}

func TestDiscoverIISSitesFromApplicationHost(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "applicationHost.config")
	// Point the CheckoutApp physical root at a real directory in the temp
	// tree (with a web.config) so the probe can prefer that file.
	checkoutRoot := filepath.Join(dir, "inetpub", "wwwroot", "checkout")
	writeFile(t, filepath.Join(checkoutRoot, "web.config"), "<configuration/>")
	writeFile(t, filepath.Join(dir, "sites", "staging-api"), "")
	fixture := strings.ReplaceAll(iisFixture, `C:\inetpub\wwwroot\checkout`, checkoutRoot)
	fixture = strings.ReplaceAll(fixture, `C:\sites\staging-api`, filepath.Join(dir, "sites", "staging-api"))
	writeFile(t, cfg, fixture)

	got := parseIISFixture(t, cfg)
	if len(got) != 3 {
		t.Fatalf("got %d IIS sites, want 3: %+v", len(got), got)
	}
	for _, w := range got {
		if w.Type != TypeIISSite {
			t.Errorf("site %q type = %q, want %q", w.Name, w.Type, TypeIISSite)
		}
		if !w.SuggestedDiff {
			t.Errorf("site %q should suggest a diff", w.Name)
		}
	}

	// HTTPS production site -> Level 1 Critical.
	checkout, ok := byName(got, "CheckoutApp")
	if !ok {
		t.Fatal("CheckoutApp not discovered")
	}
	if checkout.SuggestedLevel != LevelCritical {
		t.Errorf("CheckoutApp level = %d, want %d", checkout.SuggestedLevel, LevelCritical)
	}
	if filepath.Base(checkout.ConfigPath) != "web.config" {
		t.Errorf("CheckoutApp should prefer the site's web.config, got %q", checkout.ConfigPath)
	}
	if checkout.Reason == "" {
		t.Error("CheckoutApp reason is empty")
	}

	// Staging site -> Level 3 Drift (despite being named like an HTTP site).
	staging, ok := byName(got, "staging-api")
	if !ok {
		t.Fatal("staging-api not discovered")
	}
	if staging.SuggestedLevel != LevelDrift {
		t.Errorf("staging-api level = %d, want %d", staging.SuggestedLevel, LevelDrift)
	}

	// Plain HTTP production default site -> Level 3 Drift. A bare :80 bind is
	// not a production signal on its own (every default/placeholder site
	// listens on 80), so it must not be promoted: see the web_server profile's
	// comment in catalog.yaml.
	def, ok := byName(got, "Default Web Site")
	if !ok {
		t.Fatal("Default Web Site not discovered")
	}
	if def.SuggestedLevel != LevelDrift {
		t.Errorf("Default Web Site level = %d, want %d", def.SuggestedLevel, LevelDrift)
	}
}

func TestParseIISSitesIgnoresMalformedXML(t *testing.T) {
	if sites := parseIISSites([]byte("<configuration><sites><site")); len(sites) != 0 {
		t.Fatalf("malformed XML produced %d sites", len(sites))
	}
	if got := parseIISFixture(t, filepath.Join(t.TempDir(), "does-not-exist.config")); len(got) != 0 {
		t.Fatalf("missing config produced %+v", got)
	}
}

func TestDiscoverNginxVHosts(t *testing.T) {
	root := t.TempDir()
	// Only server blocks: a real nginx.conf with a `listen` at the http level
	// is not a vhost, and is covered by the fallback test.
	writeFile(t, filepath.Join(root, "sites-enabled", "checkout.conf"), `server {
    listen 443 ssl;
    server_name checkout.example.com;
    root /var/www/checkout;
}
`)
	writeFile(t, filepath.Join(root, "sites-enabled", "staging.conf"), `server {
    listen 8080;
    server_name staging.internal;
}
`)
	writeFile(t, filepath.Join(root, "conf.d", "static.conf"), `server {
    listen 80;
    server_name static.example.com;
}
`)

	got := parseNginxRoots(t, root)
	if len(got) != 3 {
		t.Fatalf("got %d vhosts, want 3: %+v", len(got), got)
	}

	checkout, ok := byName(got, "checkout.example.com")
	if !ok {
		t.Fatalf("checkout vhost not discovered: %+v", got)
	}
	if checkout.Type != TypeNginxVHost {
		t.Errorf("type = %q", checkout.Type)
	}
	if checkout.SuggestedLevel != LevelCritical {
		t.Errorf("checkout level = %d, want %d", checkout.SuggestedLevel, LevelCritical)
	}
	if filepath.Base(checkout.ConfigPath) != "checkout.conf" {
		t.Errorf("checkout config path = %q", checkout.ConfigPath)
	}

	staging, ok := byName(got, "staging.internal")
	if !ok {
		t.Fatalf("staging vhost not discovered: %+v", got)
	}
	if staging.SuggestedLevel != LevelDrift {
		t.Errorf("staging level = %d, want %d", staging.SuggestedLevel, LevelDrift)
	}

	// A plain-HTTP vhost with a non-production name: drift.
	static, ok := byName(got, "static.example.com")
	if !ok {
		t.Fatalf("static vhost not discovered: %+v", got)
	}
	if static.SuggestedLevel != LevelDrift {
		t.Errorf("static (port 80) level = %d, want %d", static.SuggestedLevel, LevelDrift)
	}
}

func TestNginxMainConfigFallback(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "nginx.conf"), "events {}\nhttp {\n  server {\n    listen 443 ssl;\n  }\n}\n")
	got := parseNginxRoots(t, root)
	if len(got) != 1 {
		t.Fatalf("got %+v, want a single main-config workload", got)
	}
	// The server block has no server_name, so the instance is named after the
	// file. The :443 bind inside it still promotes, which is the point of the
	// heuristic: a catch-all TLS vhost is production even without a name.
	if got[0].Name != "nginx" || got[0].SuggestedLevel != LevelCritical {
		t.Fatalf("unexpected main config workload: %+v", got[0])
	}
}

// TestNginxFileWithoutServerBlock covers a snippet or upstream-only file: it
// still produces a labelled recommendation, at the profile's default tier.
func TestNginxFileWithoutServerBlock(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "upstreams.conf"), "upstream backend {\n  server 10.0.0.1:8080;\n}\n")
	got := parseNginxRoots(t, root)
	if len(got) != 1 {
		t.Fatalf("got %+v, want one workload", got)
	}
	if got[0].Name != "upstreams" || got[0].SuggestedLevel != LevelDrift {
		t.Fatalf("unexpected snippet workload: %+v", got[0])
	}
}

func TestParseNginxServers(t *testing.T) {
	data := []byte(`server {
  listen 443 ssl http2;
  listen [::]:443 ssl;
  server_name example.com www.example.com;
}
server {
  listen 80;
  server_name _;
}`)
	got := parseNginxServers(data)
	if len(got) != 2 {
		t.Fatalf("got %d servers, want 2", len(got))
	}
	if !got[0].https {
		t.Error("first server should be HTTPS")
	}
	if len(got[0].ports) != 2 || got[0].ports[0] != 443 {
		t.Errorf("first server ports = %v", got[0].ports)
	}
	if got[1].https {
		t.Error("second server should not be HTTPS")
	}
	if got[1].primaryName() != "_" {
		t.Errorf("wildcard server name = %q", got[1].primaryName())
	}
}

func TestScannerDedupesAndSorts(t *testing.T) {
	dup := DiscoveredWorkload{Type: TypeRedis, Name: "redis", ConfigPath: "/etc/redis.conf", SuggestedLevel: LevelCritical}
	s := New(Options{
		Probers: []Prober{
			{Name: "a", Probe: func() []DiscoveredWorkload {
				return []DiscoveredWorkload{
					dup,
					{Type: TypeNginxVHost, Name: "b.example.com", ConfigPath: "/etc/nginx/b.conf", SuggestedLevel: LevelCritical},
				}
			}},
			{Name: "b", Probe: func() []DiscoveredWorkload { return []DiscoveredWorkload{dup} }},
			{Name: "panic", Probe: func() []DiscoveredWorkload { panic("boom") }},
		},
	})
	got := s.Scan()
	if len(got) != 2 {
		t.Fatalf("got %d workloads, want 2 (deduped): %+v", len(got), got)
	}
	if got[0].Type != TypeNginxVHost || got[1].Type != TypeRedis {
		t.Fatalf("not sorted by type: %+v", got)
	}
}

func TestScannerReportsAndKeepsLast(t *testing.T) {
	var reported []DiscoveredWorkload
	s := New(Options{
		Probers: []Prober{{Name: "x", Probe: func() []DiscoveredWorkload {
			return []DiscoveredWorkload{{Type: TypePostgresDB, Name: "16-main", ConfigPath: "/etc/postgresql/16/main/postgresql.conf", SuggestedLevel: LevelCritical}}
		}}},
		Report: func(ws []DiscoveredWorkload) { reported = ws },
	})
	got := s.Scan()
	if len(reported) != 1 || reported[0].Name != "16-main" {
		t.Fatalf("Report not invoked with the scan result: %+v", reported)
	}
	last, at := s.Last()
	if len(last) != 1 || at.IsZero() {
		t.Fatalf("Last() = %+v at %v", last, at)
	}
	// Mutating the returned slice must not corrupt the scanner's copy.
	got[0].Name = "mutated"
	if s.last[0].Name != "16-main" {
		t.Fatal("Last() returned a shared backing array")
	}
}

func TestParseListenPort(t *testing.T) {
	tests := map[string]int{
		"443":            443,
		"443 ssl":        443,
		"[::]:443":       443,
		"*:80":           80,
		"127.0.0.1:8080": 8080,
		"default_server": 0,
		"":               0,
		"abc":            0,
	}
	for in, want := range tests {
		if got := parseListenPort(in); got != want {
			t.Errorf("parseListenPort(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestToPB(t *testing.T) {
	in := []DiscoveredWorkload{{
		Type: TypeIISSite, Name: "CheckoutApp", ConfigPath: `C:\inetpub\wwwroot\checkout\web.config`,
		SuggestedLevel: LevelCritical, SuggestedDiff: true, Reason: "Active HTTPS site on port 443",
	}}
	out := ToPB(in)
	if len(out) != 1 {
		t.Fatalf("got %d pb workloads", len(out))
	}
	if out[0].GetName() != "CheckoutApp" || int(out[0].GetSuggestedLevel()) != LevelCritical || !out[0].GetSuggestedDiff() {
		t.Fatalf("unexpected conversion: %+v", out[0])
	}
	if ToPB(nil) == nil {
		t.Fatal("ToPB(nil) must not be nil so it serialises as an empty repeated field")
	}
}
