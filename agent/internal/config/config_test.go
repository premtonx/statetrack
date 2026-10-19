package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestZeroConfigDefaults(t *testing.T) {
	cfg, src, err := LoadFor("linux", filepath.Join(t.TempDir(), "missing.yaml"), env(nil))
	if err == nil {
		t.Fatal("explicit missing file must be an error")
	}
	cfg, src, err = LoadFor("linux", "", env(nil))
	if err != nil {
		t.Fatalf("zero-config: %v", err)
	}
	if src.Path != "/etc/statetrack/agent.yaml" || src.FileLoaded && !fileExists("/etc/statetrack/agent.yaml") {
		t.Fatalf("source %+v", src)
	}
	want := []string{"/etc", "/usr/local/etc", "/etc/systemd/system", "/var/spool/cron", "/root/.ssh", "/home/*/.ssh"}
	if !reflect.DeepEqual(cfg.Watch.Paths, want) || cfg.StateDir != "/var/lib/statetrack" || cfg.Spool.MaxMB != 200 ||
		!cfg.Systemd.Enabled || !cfg.Packages.Enabled || cfg.Packages.DpkgLog != "/var/log/dpkg.log" {
		t.Fatalf("linux defaults: %+v", cfg)
	}

	w := Default("windows")
	if w.StateDir != `C:\ProgramData\StateTrack` || DefaultPath("windows") != `C:\ProgramData\StateTrack\agent.yaml` || w.Systemd.Enabled {
		t.Fatalf("windows defaults: %+v", w)
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestYAMLOverridesDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	writeFile(t, p, `
host_id: web-01
log_level: debug
watch:
  extra_paths: [/opt/app/conf]
  exclude: ["/etc/noisy/**"]
spool:
  max_mb: 50
baseline:
  pace: 250us
systemd:
  enabled: false
forensic_until: 2026-10-13T22:00:00Z
reload_interval: 5s
`)
	cfg, src, err := LoadFor("linux", p, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !src.FileLoaded || cfg.HostID != "web-01" || cfg.LogLevel != "debug" || cfg.Spool.MaxMB != 50 ||
		cfg.Baseline.Pace.D() != 250*time.Microsecond || cfg.Systemd.Enabled || cfg.ReloadInterval.D() != 5*time.Second ||
		!cfg.ForensicUntil.Equal(time.Date(2026, 10, 13, 22, 0, 0, 0, time.UTC)) {
		t.Fatalf("cfg %+v", cfg)
	}
	// Unset sections keep their defaults; extra paths add to the defaults.
	if len(cfg.Watch.Paths) != 6 || cfg.Watch.ExtraPaths[0] != "/opt/app/conf" || !cfg.Packages.Enabled {
		t.Fatalf("defaults lost: %+v", cfg.Watch)
	}
}

func TestEnvOverridesYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	writeFile(t, p, "host_id: from-file\nspool:\n  max_mb: 50\n")
	cfg, src, err := LoadFor("linux", "", env(map[string]string{
		"STATETRACK_CONFIG":           p,
		"STATETRACK_HOST_ID":          "from-env",
		"STATETRACK_WATCH_PATHS":      "/srv/a, /srv/b ,",
		"STATETRACK_SPOOL_MAX_MB":     "10",
		"STATETRACK_SYSTEMD_ENABLED":  "false",
		"STATETRACK_FORENSIC_UNTIL":   "2026-10-13T22:05:00+02:00",
		"STATETRACK_RELOAD_INTERVAL":  "2s",
		"STATETRACK_PACKAGES_APK_LOG": "/x/apk.log",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HostID != "from-env" || cfg.Spool.MaxMB != 10 || cfg.Systemd.Enabled || cfg.ReloadInterval.D() != 2*time.Second ||
		!reflect.DeepEqual(cfg.Watch.Paths, []string{"/srv/a", "/srv/b"}) || cfg.Packages.ApkLog != "/x/apk.log" ||
		cfg.ForensicUntil.UTC().Hour() != 20 {
		t.Fatalf("cfg %+v", cfg)
	}
	if src.Path != p || len(src.EnvApplied) != 7 {
		t.Fatalf("source %+v", src)
	}
}

func TestInvalidConfigs(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"unknown field":    "watchh:\n  paths: [/etc]\n",
		"bad duration":     "reload_interval: soon\n",
		"bad level":        "log_level: loud\n",
		"relative path":    "watch:\n  paths: [etc]\n",
		"spool too small":  "spool:\n  max_mb: 0\n",
		"reload too often": "reload_interval: 10ms\n",
		"bad yaml":         "watch: [\n",
	}
	for name, content := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".yaml")
		writeFile(t, p, content)
		if _, _, err := LoadFor("linux", p, env(nil)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, _, err := LoadFor("linux", "", env(map[string]string{"STATETRACK_SPOOL_MAX_MB": "lots"})); err == nil {
		t.Error("bad env value accepted")
	}
}

func TestWatchRootsExpandsGlobsAndDropsNested(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"etc/systemd/system", "home/alice/.ssh", "home/bob/.ssh", "home/carol", "usr/local/etc"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	writeFile(t, filepath.Join(root, "home", "dave", ".ssh"), "not a dir")
	j := func(p string) string { return filepath.Join(root, p) }
	cfg := Config{Watch: Watch{
		Paths:      []string{j("etc"), j("etc/systemd/system"), j("home/*/.ssh"), j("missing")},
		ExtraPaths: []string{j("usr/local/etc"), j("etc")},
	}}
	got := cfg.WatchRoots()
	want := []string{j("etc"), j("home/alice/.ssh"), j("home/bob/.ssh"), j("usr/local/etc")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WatchRoots\n got %v\nwant %v", got, want)
	}
	// A new user's .ssh directory appears on the next expansion.
	os.MkdirAll(j("home/carol/.ssh"), 0o700)
	if got := cfg.WatchRoots(); len(got) != 5 {
		t.Fatalf("new glob match not picked up: %v", got)
	}
}

func TestReloaderAppliesChangesAndKeepsLastGoodConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	writeFile(t, p, "watch:\n  exclude: [\"/etc/a/**\"]\n")
	cfg, _, err := LoadFor("linux", p, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	var changes []Config
	ticks := 0
	r := &Reloader{Path: p, GOOS: "linux", Env: env(nil), Logger: slog.New(slog.DiscardHandler),
		OnChange: func(_, cur Config) { changes = append(changes, cur) },
		OnTick:   func(Config) { ticks++ }}

	cfg = r.Poll(cfg)
	if len(changes) != 0 || ticks != 1 {
		t.Fatalf("unchanged file triggered reload: %d changes", len(changes))
	}
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	writeFile(t, p, "watch:\n  exclude: [\"/etc/b/**\"]\nforensic_until: "+until.Format(time.RFC3339)+"\n")
	cfg = r.Poll(cfg)
	if len(changes) != 1 || cfg.Watch.Exclude[0] != "/etc/b/**" || !cfg.ForensicUntil.Equal(until) {
		t.Fatalf("change not applied: %+v", cfg)
	}
	writeFile(t, p, "watch: [broken\n")
	cfg = r.Poll(cfg)
	if len(changes) != 1 || cfg.Watch.Exclude[0] != "/etc/b/**" {
		t.Fatal("invalid file replaced the running configuration")
	}
}

func TestRestartRequired(t *testing.T) {
	a := Default("linux")
	b := a
	b.Watch.Exclude = []string{"/x"}
	b.ForensicUntil = time.Now()
	if got := RestartRequired(a, b); len(got) != 0 {
		t.Fatalf("hot-reloadable changes flagged: %v", got)
	}
	b.StateDir, b.Spool.MaxMB = "/other", 1
	if got := RestartRequired(a, b); !reflect.DeepEqual(got, []string{"state_dir", "spool"}) {
		t.Fatalf("got %v", got)
	}
}
