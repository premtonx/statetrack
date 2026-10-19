package linux

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

func TestParseDpkgLine(t *testing.T) {
	loc := time.UTC
	cases := []struct {
		line string
		want PackageChange
		ok   bool
	}{
		{"2026-10-13 21:21:56 upgrade nginx:amd64 1.24.0-1 1.26.1-1",
			PackageChange{Manager: "dpkg", Name: "nginx", Arch: "amd64", Op: "upgrade", Before: "1.24.0-1", After: "1.26.1-1"}, true},
		{"2026-10-13 21:21:57 install curl:arm64 <none> 8.11.1-1",
			PackageChange{Manager: "dpkg", Name: "curl", Arch: "arm64", Op: "install", After: "8.11.1-1"}, true},
		{"2026-10-13 21:21:58 remove curl:arm64 8.11.1-1 <none>",
			PackageChange{Manager: "dpkg", Name: "curl", Arch: "arm64", Op: "remove", Before: "8.11.1-1"}, true},
		{"2026-10-13 21:21:59 purge statetrack-e2e:all 2.0 <none>",
			PackageChange{Manager: "dpkg", Name: "statetrack-e2e", Arch: "all", Op: "purge", Before: "2.0"}, true},
		{"2026-10-13 21:21:56 status installed nginx:amd64 1.26.1-1", PackageChange{}, false},
		{"2026-10-13 21:21:56 configure nginx:amd64 1.26.1-1 <none>", PackageChange{}, false},
		{"2026-10-13 21:21:56 startup archives unpack", PackageChange{}, false},
		{"garbage", PackageChange{}, false},
	}
	for _, tc := range cases {
		got, ok := ParseDpkgLine(tc.line, loc)
		if ok != tc.ok {
			t.Errorf("%q: ok=%v", tc.line, ok)
			continue
		}
		if !ok {
			continue
		}
		got.At = time.Time{}
		if got != tc.want {
			t.Errorf("%q:\n got %+v\nwant %+v", tc.line, got, tc.want)
		}
	}
	c, _ := ParseDpkgLine(cases[0].line, loc)
	if !c.At.Equal(time.Date(2026, 10, 13, 21, 21, 56, 0, time.UTC)) || c.Action() != pb.Action_ACTION_UPGRADED ||
		c.Summary() != "Upgraded nginx 1.24.0-1 -> 1.26.1-1" {
		t.Fatalf("%+v %q", c, c.Summary())
	}
}

func TestParseNEVRA(t *testing.T) {
	cases := map[string][3]string{
		"nginx-1:1.26.1-1.el9.x86_64":     {"nginx", "1:1.26.1-1.el9", "x86_64"},
		"curl-8.11.1-1.fc41.x86_64":       {"curl", "8.11.1-1.fc41", "x86_64"},
		"python3-libs-3.12.7-1.fc41.i686": {"python3-libs", "3.12.7-1.fc41", "i686"},
		"1:nginx-1.20.1-10.el7.x86_64":    {"nginx", "1:1.20.1-10.el7", "x86_64"},
		"0:tzdata-2024a-1.el9.noarch":     {"tzdata", "2024a-1.el9", "noarch"},
		"curl":                            {"curl", "", ""},
	}
	for in, want := range cases {
		n, v, a := ParseNEVRA(in)
		if [3]string{n, v, a} != want {
			t.Errorf("%s: got %q %q %q", in, n, v, a)
		}
	}
}

func TestDnfParserPairsUpgrades(t *testing.T) {
	var p DnfParser
	var got []PackageChange
	for _, l := range []string{
		"2026-10-13T21:21:56+0000 SUBDEBUG Upgrade: nginx-1:1.26.1-1.el9.x86_64",
		"2026-10-13T21:21:56+0000 SUBDEBUG Installed: nginx-filesystem-1:1.26.1-1.el9.noarch",
		"2026-10-13T21:21:57+0000 SUBDEBUG Upgraded: nginx-1:1.24.0-1.el9.x86_64",
		"2026-10-13T21:21:58+0000 SUBDEBUG Erase: telnet-0.17-85.el9.x86_64",
		"2026-10-13T21:21:58+0000 INFO --- logging initialized ---",
		"2026-10-13T21:21:59+0000 SUBDEBUG Upgrade: openssl-1:3.2.2-6.el9.x86_64",
	} {
		got = append(got, p.Line(l)...)
	}
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Op != "install" || got[0].Name != "nginx-filesystem" || got[0].After != "1:1.26.1-1.el9" {
		t.Errorf("install: %+v", got[0])
	}
	if got[1].Op != "upgrade" || got[1].Name != "nginx" || got[1].Before != "1:1.24.0-1.el9" || got[1].After != "1:1.26.1-1.el9" {
		t.Errorf("upgrade: %+v", got[1])
	}
	if got[2].Op != "remove" || got[2].Before != "0.17-85.el9" || got[2].Action() != pb.Action_ACTION_DELETED {
		t.Errorf("erase: %+v", got[2])
	}
	at := time.Date(2026, 10, 13, 21, 21, 59, 0, time.UTC)
	if f := p.Flush(at.Add(10*time.Second), 30*time.Second); len(f) != 0 {
		t.Fatal("flushed too early")
	}
	if f := p.Flush(at.Add(31*time.Second), 30*time.Second); len(f) != 1 || f[0].Name != "openssl" || f[0].Before != "" {
		t.Fatalf("flush: %+v", f)
	}
}

func TestParseYumLine(t *testing.T) {
	ref := time.Date(2026, 10, 13, 22, 0, 0, 0, time.UTC)
	c, ok := ParseYumLine("Oct 13 21:21:56 Updated: 1:nginx-1.20.1-10.el7.x86_64", ref)
	if !ok || c.Op != "upgrade" || c.Name != "nginx" || c.After != "1:1.20.1-10.el7" || c.At.Year() != 2026 {
		t.Fatalf("%+v", c)
	}
	// A December line read in January belongs to the previous year.
	c, ok = ParseYumLine("Dec 31 23:59:00 Erased: telnet", time.Date(2027, 1, 1, 0, 5, 0, 0, time.UTC))
	if !ok || c.Op != "remove" || c.Name != "telnet" || c.At.Year() != 2026 {
		t.Fatalf("%+v", c)
	}
	if _, ok := ParseYumLine("Oct 13 21:21:56 Something: x", ref); ok {
		t.Fatal("unknown op accepted")
	}
}

func TestApkDatabaseDiff(t *testing.T) {
	before := ParseApkInstalled([]byte("C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:x86_64\n\nP:tree\nV:2.1.1-r0\nA:x86_64\n\nP:curl\nV:8.10.0-r0\nA:x86_64\n"))
	after := ParseApkInstalled([]byte("P:musl\nV:1.2.5-r0\nA:x86_64\n\nP:curl\nV:8.11.1-r0\nA:x86_64\n\nP:jq\nV:1.7.1-r0\nA:x86_64\n\n"))
	got := DiffApk(before, after, time.Time{})
	want := []PackageChange{
		{Manager: "apk", Name: "curl", Arch: "x86_64", Op: "upgrade", Before: "8.10.0-r0", After: "8.11.1-r0"},
		{Manager: "apk", Name: "jq", Arch: "x86_64", Op: "install", After: "1.7.1-r0"},
		{Manager: "apk", Name: "tree", Arch: "x86_64", Op: "remove", Before: "2.1.1-r0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	if cmd, ok := ParseApkLogCommand("Running `apk add -q tree` at 2026-10-13 21:21:56"); !ok || cmd != "apk add -q tree" {
		t.Fatalf("command %q", cmd)
	}
}

func appendFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(s)
	f.Close()
}

func TestTailerStartsAtEOFAndFollowsRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dpkg.log")
	appendFile(t, p, "old 1\nold 2\n")
	tl := &Tailer{Path: p}
	defer tl.Close()
	if lines, _ := tl.Poll(); len(lines) != 0 {
		t.Fatalf("history replayed: %v", lines)
	}
	appendFile(t, p, "new 1\nnew 2 partial")
	if lines, _ := tl.Poll(); !reflect.DeepEqual(lines, []string{"new 1"}) {
		t.Fatalf("got %v", lines)
	}
	appendFile(t, p, " done\r\n")
	if lines, _ := tl.Poll(); !reflect.DeepEqual(lines, []string{"new 2 partial done"}) {
		t.Fatalf("partial line: %v", lines)
	}

	// logrotate: a last line lands just before the rename.
	appendFile(t, p, "last before rotate\n")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Skipf("cannot rename an open file here: %v", err)
	}
	appendFile(t, p, "first after rotate\n")
	lines, _ := tl.Poll()
	if !reflect.DeepEqual(lines, []string{"last before rotate", "first after rotate"}) {
		t.Fatalf("rotation: %v", lines)
	}
}

func TestTailerTruncationAndLateFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "apk.log")
	tl := &Tailer{Path: p}
	defer tl.Close()
	tl.Poll() // file does not exist yet
	appendFile(t, p, "Running `apk add jq` at x\n")
	if lines, _ := tl.Poll(); len(lines) != 1 {
		t.Fatalf("file created after start must be read from the beginning: %v", lines)
	}
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "after truncate\n")
	if lines, _ := tl.Poll(); !reflect.DeepEqual(lines, []string{"after truncate"}) {
		t.Fatalf("truncation: %v", lines)
	}
}

func TestPackagesCollectorEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dpkg, apkLog, apkDB := filepath.Join(dir, "dpkg.log"), filepath.Join(dir, "apk.log"), filepath.Join(dir, "installed")
	appendFile(t, dpkg, "2026-10-13 21:00:00 install old:amd64 <none> 1\n")
	os.WriteFile(apkDB, []byte("P:tree\nV:2.1.1-r0\nA:x86_64\n\n"), 0o644)

	var got []PackageChange
	p := NewPackages(PackagesOptions{DpkgLog: dpkg, ApkLog: apkLog, ApkDB: apkDB, DnfLog: filepath.Join(dir, "none.log"),
		Emit: func(_ context.Context, c PackageChange) { got = append(got, c) }})
	defer p.Close()
	ctx := context.Background()
	p.Poll(ctx)
	if len(got) != 0 {
		t.Fatalf("startup must not replay history: %+v", got)
	}
	appendFile(t, dpkg, "2026-10-13 21:21:56 upgrade nginx:amd64 1.24.0-1 1.26.1-1\n")
	appendFile(t, apkLog, "Running `apk upgrade tree` at 2026-10-13 21:21:56\n")
	os.WriteFile(apkDB, []byte("P:tree\nV:2.2.0-r0\nA:x86_64\n\n"), 0o644)
	future := time.Now().Add(time.Second)
	os.Chtimes(apkDB, future, future)
	p.Poll(ctx)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Name != "nginx" || got[0].Source != dpkg {
		t.Errorf("dpkg: %+v", got[0])
	}
	a := got[1]
	if a.Name != "tree" || a.Before != "2.1.1-r0" || a.After != "2.2.0-r0" || a.Command != "apk upgrade tree" || a.Source != apkDB {
		t.Errorf("apk: %+v", a)
	}
	md := a.Metadata()
	if md["event_type"] != "PACKAGE_UPGRADE" || md["package_manager"] != "apk" || md["command"] != "apk upgrade tree" {
		t.Errorf("metadata %v", md)
	}
	if tg := a.Target(); tg.VersionBefore != "2.1.1-r0" || tg.TargetType != "package" {
		t.Errorf("target %+v", tg)
	}
}
