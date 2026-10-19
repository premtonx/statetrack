package linux

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fakeProc struct {
	pid, ppid uint32
	comm      string
	uid       uint32
	loginuid  uint32
	start     uint64
	args      []string
	env       []string
	cwd       string
}

type procFS struct {
	t    *testing.T
	root string
}

func newProcFS(t *testing.T) *procFS { return &procFS{t: t, root: t.TempDir()} }

func (fs *procFS) add(p fakeProc) {
	fs.t.Helper()
	dir := filepath.Join(fs.root, strconv.Itoa(int(p.pid)))
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fs.t.Fatal(err)
	}
	if p.start == 0 {
		p.start = uint64(p.pid) * 10
	}
	w := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			fs.t.Fatal(err)
		}
	}
	// Field 22 (starttime) is the 20th field after the comm.
	rest := []string{"S", strconv.Itoa(int(p.ppid))}
	for i := 0; i < 17; i++ {
		rest = append(rest, "0")
	}
	rest = append(rest, strconv.FormatUint(p.start, 10), "0", "0")
	w("stat", strconv.Itoa(int(p.pid))+" ("+p.comm+") "+strings.Join(rest, " ")+"\n")
	uid := strconv.Itoa(int(p.uid))
	w("status", "Name:\t"+p.comm+"\nUmask:\t0022\nState:\tS (sleeping)\nPPid:\t"+strconv.Itoa(int(p.ppid))+
		"\nUid:\t1000\t"+uid+"\t"+uid+"\t"+uid+"\n")
	w("loginuid", strconv.FormatUint(uint64(p.loginuid), 10))
	w("comm", p.comm+"\n")
	w("cmdline", strings.Join(p.args, "\x00")+"\x00")
	w("environ", strings.Join(append([]string{"PATH=/usr/bin", "LANG=C"}, p.env...), "\x00")+"\x00")
	if p.cwd != "" {
		if err := os.Symlink(p.cwd, filepath.Join(dir, "cwd")); err != nil {
			fs.t.Skipf("symlinks unavailable: %v", err)
		}
	}
}

func (fs *procFS) exit(pid uint32) { os.RemoveAll(filepath.Join(fs.root, strconv.Itoa(int(pid)))) }

func newTestResolver(t *testing.T, fs *procFS) (*Resolver, *fakeClock) {
	t.Helper()
	passwd := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"), 0o644)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	r := NewResolver(ResolverOptions{ProcRoot: fs.root, PasswdPath: passwd, Now: clk.Now, SelfPID: 99999,
		Scrub: func(s string) string { return strings.ReplaceAll(s, "-pS3cret", "-p[REDACTED]") }})
	return r, clk
}

// sshTree models: sshd listener -> sshd session -> bash (alice, via SSH) ->
// sudo -> vim (root), with sudo's env_reset dropping SSH_CONNECTION.
func sshTree(fs *procFS) {
	fs.add(fakeProc{pid: 1, comm: "systemd", loginuid: NoLoginUID, args: []string{"/sbin/init"}})
	fs.add(fakeProc{pid: 100, ppid: 1, comm: "sshd", loginuid: NoLoginUID, args: []string{"sshd: /usr/sbin/sshd -D"}})
	fs.add(fakeProc{pid: 200, ppid: 100, comm: "sshd", loginuid: 1000, args: []string{"sshd: alice@pts/0"}})
	fs.add(fakeProc{pid: 300, ppid: 200, comm: "bash", uid: 1000, loginuid: 1000, args: []string{"-bash"},
		env: []string{"SSH_CONNECTION=203.0.113.7 51234 10.0.0.5 22", "SSH_CLIENT=203.0.113.7 51234 22"}})
	fs.add(fakeProc{pid: 400, ppid: 300, comm: "sudo", loginuid: 1000, args: []string{"sudo", "vim", "/etc/nginx/nginx.conf"}})
	fs.add(fakeProc{pid: 500, ppid: 400, comm: "vim", loginuid: 1000, args: []string{"vim", "/etc/nginx/nginx.conf"}})
}

func TestActorSudoVimResolvesHumanAndSSHAddress(t *testing.T) {
	fs := newProcFS(t)
	sshTree(fs)
	r, _ := newTestResolver(t, fs)

	a, anc := r.Actor(500)
	if a == nil {
		t.Fatal("no actor")
	}
	if a.Username != "root" || a.UidOrSid != "0" || a.LoginUid != "1000" || a.LoginUsername != "alice" {
		t.Fatalf("identity: %+v", a)
	}
	if a.Pid != 500 || a.Ppid != 400 || a.ProcessName != "vim" || a.Cmdline != "vim /etc/nginx/nginx.conf" {
		t.Fatalf("process: %+v", a)
	}
	if got := strings.Join(a.ProcessLineage, ","); got != "sshd,bash,sudo,vim" {
		t.Fatalf("lineage %q", got)
	}
	if a.RemoteIp != "203.0.113.7" {
		t.Fatalf("remote ip %q", a.RemoteIp)
	}
	if len(anc) != 5 || anc[0].PID != 500 || anc[4].PID != 100 || anc[1].Cmdline != "sudo vim /etc/nginx/nginx.conf" {
		t.Fatalf("ancestry %+v", anc)
	}
}

func TestShortLivedProcessIsAttributedAfterExit(t *testing.T) {
	fs := newProcFS(t)
	sshTree(fs)
	fs.add(fakeProc{pid: 600, ppid: 300, comm: "sed", uid: 0, loginuid: 1000,
		args: []string{"sed", "-i", "s/80/8080/", "/etc/nginx/sites-enabled/default"}})
	fs.add(fakeProc{pid: 601, ppid: 1, comm: "cron", loginuid: NoLoginUID, args: []string{"/usr/sbin/cron", "-f"}})
	r, clk := newTestResolver(t, fs)

	// sed's temp file appears in the directory: snapshot candidates now.
	r.Activity("/etc/nginx/sites-enabled")
	fs.exit(600)
	clk.Advance(2 * time.Second)

	pid, method := r.Attribute("/etc/nginx/sites-enabled/default")
	if pid != 600 || method != AttrCmdline {
		t.Fatalf("attribute: pid=%d method=%s", pid, method)
	}
	a, _ := r.Actor(pid)
	if a == nil || a.ProcessName != "sed" || a.LoginUsername != "alice" || a.RemoteIp != "203.0.113.7" ||
		strings.Join(a.ProcessLineage, ",") != "sshd,bash,sed" {
		t.Fatalf("actor after exit: %+v", a)
	}
	if contains(r.sortedPIDs(), 601) {
		t.Fatal("unrelated process was snapshotted")
	}

	clk.Advance(DefaultCacheTTL + time.Second)
	r.Sweep()
	if a, _ := r.Actor(600); a != nil {
		t.Fatal("exited process must expire after the TTL")
	}
}

func contains(s []uint32, v uint32) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestActivityScanIsRateLimited(t *testing.T) {
	fs := newProcFS(t)
	r, clk := newTestResolver(t, fs)
	r.Activity("/etc")
	fs.add(fakeProc{pid: 700, ppid: 1, comm: "cp", args: []string{"cp", "/tmp/x", "/etc/x"}})
	r.Activity("/etc")
	if r.Len() != 0 {
		t.Fatal("second scan within the interval should be skipped")
	}
	clk.Advance(DefaultScanInterval)
	r.Activity("/etc")
	if !contains(r.sortedPIDs(), 700) {
		t.Fatal("scan after the interval missed cp")
	}
}

func TestPIDReuseIsDetected(t *testing.T) {
	fs := newProcFS(t)
	fs.add(fakeProc{pid: 800, ppid: 1, comm: "cp", start: 100, args: []string{"cp", "a", "b"}})
	r, _ := newTestResolver(t, fs)
	r.Remember(800)
	fs.add(fakeProc{pid: 800, ppid: 1, comm: "nginx", start: 200, args: []string{"nginx", "-g", "daemon off;"}})
	if a, _ := r.Actor(800); a == nil || a.ProcessName != "nginx" {
		t.Fatalf("stale process returned for reused PID: %+v", a)
	}
}

func TestAttributionPrecedence(t *testing.T) {
	fs := newProcFS(t)
	fs.add(fakeProc{pid: 900, ppid: 1, comm: "tee", args: []string{"tee", "-a", "/etc/hosts"}})
	fs.add(fakeProc{pid: 901, ppid: 1, comm: "useradd", args: []string{"useradd", "-m", "bob"}})
	fs.add(fakeProc{pid: 902, ppid: 1, comm: "python3", args: []string{"python3", "script.py"}})
	r, clk := newTestResolver(t, fs)
	r.Activity("/etc")

	if pid, m := r.Attribute("/etc/hosts"); pid != 900 || m != AttrCmdline {
		t.Fatalf("cmdline: %d %s", pid, m)
	}
	if pid, m := r.Attribute("/etc/shadow"); pid != 901 || m != AttrTool {
		t.Fatalf("tool: %d %s", pid, m)
	}
	// An exact writer observation (fanotify) beats everything.
	r.NoteWriter("/etc/hosts", 902)
	if pid, m := r.Attribute("/etc/hosts"); pid != 902 || m != AttrWriter {
		t.Fatalf("writer: %d %s", pid, m)
	}
	// A same-directory writer is the last resort.
	if pid, m := r.Attribute("/etc/motd"); pid != 902 || m != AttrDir {
		t.Fatalf("dir writer: %d %s", pid, m)
	}
	clk.Advance(writerNoteTTL + time.Second)
	r.Sweep()
	if pid, m := r.Attribute("/etc/motd"); pid != 0 || m != AttrUnknown {
		t.Fatalf("expired note used: %d %s", pid, m)
	}
	if pid, _ := r.Attribute("/etc/hosts"); pid != 900 {
		t.Fatalf("after note expiry: %d", pid)
	}
}

func TestRelativeArgumentsUseCwd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux symlink semantics for /proc/<pid>/cwd")
	}
	fs := newProcFS(t)
	fs.add(fakeProc{pid: 950, ppid: 1, comm: "sed", args: []string{"sed", "-i", "s/a/b/", "hosts"}, cwd: "/etc"})
	r, _ := newTestResolver(t, fs)
	r.Activity("/etc")
	if pid, m := r.Attribute("/etc/hosts"); pid != 950 || m != AttrCmdline {
		t.Fatalf("relative path: %d %s", pid, m)
	}
}

func TestDirectoryArgumentCoversFilesInside(t *testing.T) {
	fs := newProcFS(t)
	fs.add(fakeProc{pid: 960, ppid: 1, comm: "rsync", args: []string{"rsync", "-a", "--delete", "/srv/build/", "/etc/app"}})
	r, _ := newTestResolver(t, fs)
	r.Activity("/etc/app/conf.d")
	if pid, _ := r.Attribute("/etc/app/conf.d/site.conf"); pid != 960 {
		t.Fatalf("got %d", pid)
	}
	if pid, _ := r.Attribute("/etc/hosts"); pid != 0 {
		t.Fatal("/etc/app must not cover /etc/hosts")
	}
}

func TestDescendantBeatsAncestorWithSameStartTick(t *testing.T) {
	fs := newProcFS(t)
	// sudo and the editor it runs start within the same 10 ms tick.
	fs.add(fakeProc{pid: 980, ppid: 1, comm: "sudo", start: 5000, args: []string{"sudo", "vim", "/etc/app/db.conf"}})
	fs.add(fakeProc{pid: 979, ppid: 980, comm: "vim", start: 5000, args: []string{"vim", "/etc/app/db.conf"}})
	r, _ := newTestResolver(t, fs)
	r.Activity("/etc/app")
	if pid, _ := r.Attribute("/etc/app/db.conf"); pid != 979 {
		t.Fatalf("got pid %d, want the editor (979)", pid)
	}
}

func TestShellCommandArgumentsAreTokenized(t *testing.T) {
	fs := newProcFS(t)
	fs.add(fakeProc{pid: 990, ppid: 1, comm: "sh",
		args: []string{"sh", "-c", `echo "bob ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/90-bob >/dev/null`}})
	fs.add(fakeProc{pid: 991, ppid: 1, comm: "cp", args: []string{"cp", "x", "/etc/my file.conf"}})
	r, clk := newTestResolver(t, fs)
	r.Activity("/etc/sudoers.d")
	clk.Advance(DefaultScanInterval)
	r.Activity("/etc")
	if pid, m := r.Attribute("/etc/sudoers.d/90-bob"); pid != 990 || m != AttrCmdline {
		t.Fatalf("sh -c: %d %s", pid, m)
	}
	if pid, _ := r.Attribute("/etc/my file.conf"); pid != 991 {
		t.Fatalf("path with a space: %d", pid)
	}
}

func TestLoginUIDInheritedFromSessionWhenLeafUnreadable(t *testing.T) {
	fs := newProcFS(t)
	sshTree(fs)
	// A zombie: stat/status still readable, loginuid and environ not.
	fs.add(fakeProc{pid: 510, ppid: 300, comm: "tee", loginuid: NoLoginUID, args: []string{"tee", "/etc/x"}})
	r, _ := newTestResolver(t, fs)
	a, _ := r.Actor(510)
	if a.LoginUid != "1000" || a.LoginUsername != "alice" || a.RemoteIp != "203.0.113.7" {
		t.Fatalf("got %+v", a)
	}
}

func TestReapedWriterNoteFallsThrough(t *testing.T) {
	fs := newProcFS(t)
	fs.add(fakeProc{pid: 520, ppid: 1, comm: "sh", args: []string{"sh", "-c", "date | tee /etc/stamp"}})
	r, _ := newTestResolver(t, fs)
	r.Activity("/etc")
	r.NoteWriter("/etc/stamp", 521) // tee: already reaped, never snapshotted
	if pid, m := r.Attribute("/etc/stamp"); pid != 520 || m != AttrCmdline {
		t.Fatalf("got %d %s", pid, m)
	}
}

func TestAuditFactsOverrideProc(t *testing.T) {
	fs := newProcFS(t)
	r, _ := newTestResolver(t, fs)
	// The process already exited; only the audit record knows it.
	r.RememberInfo(ProcInfo{PID: 1234, PPID: 0, UID: 0, LoginUID: 1000, Name: "mv", Exe: "/usr/bin/mv",
		Args: []string{"mv", "/tmp/new", "/etc/hosts"}, Cwd: "/root", Source: "audit"})
	a, _ := r.Actor(1234)
	if a == nil || a.ProcessName != "mv" || a.LoginUsername != "alice" || a.Cmdline != "mv /tmp/new /etc/hosts" {
		t.Fatalf("audit-only actor: %+v", a)
	}
}

func TestCmdlineIsScrubbed(t *testing.T) {
	fs := newProcFS(t)
	fs.add(fakeProc{pid: 970, ppid: 1, comm: "mysql", args: []string{"mysql", "-uroot", "-pS3cret"}})
	r, _ := newTestResolver(t, fs)
	if a, _ := r.Actor(970); a.Cmdline != "mysql -uroot -p[REDACTED]" {
		t.Fatalf("cmdline %q", a.Cmdline)
	}
}

func TestUnknownPIDAndMissingProc(t *testing.T) {
	r := NewResolver(ResolverOptions{ProcRoot: filepath.Join(t.TempDir(), "nope")})
	if a, anc := r.Actor(4242); a != nil || anc != nil {
		t.Fatal("expected nil for unknown pid")
	}
	if a, _ := r.Actor(0); a != nil {
		t.Fatal("pid 0")
	}
	r.Activity("/etc") // must not panic without /proc
}

func TestRemoteIPFromEnviron(t *testing.T) {
	cases := map[string]string{
		"SSH_CONNECTION=203.0.113.7 51234 10.0.0.5 22\x00":        "203.0.113.7",
		"A=1\x00SSH_CLIENT=2001:db8::1 40000 22\x00":              "2001:db8::1",
		"SSH_CLIENT=::ffff:198.51.100.2 1 22\x00":                 "198.51.100.2",
		"SSH_CONNECTION=garbage\x00SSH_CLIENT=192.0.2.1 1 22\x00": "192.0.2.1",
		"PATH=/bin\x00": "",
	}
	for env, want := range cases {
		if got := RemoteIPFromEnviron([]byte(env)); got != want {
			t.Errorf("%q: got %q want %q", env, got, want)
		}
	}
}

func TestParseStatHandlesHostileComm(t *testing.T) {
	line := "4242 (evil) S 1 (x) R 77 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 555 0 0"
	comm, ppid, start, ok := parseStat([]byte(line))
	if !ok || comm != "evil) S 1 (x" || ppid != 77 || start != 555 {
		t.Fatalf("comm=%q ppid=%d start=%d ok=%v", comm, ppid, start, ok)
	}
	if _, _, _, ok := parseStat([]byte("garbage")); ok {
		t.Fatal("garbage accepted")
	}
}

func TestUserDBReloadsAfterChange(t *testing.T) {
	p := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(p, []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
	u := NewUserDB(p)
	if u.Name(1001) != "1001" || u.Name(0) != "root" {
		t.Fatal("initial lookup")
	}
	os.WriteFile(p, []byte("root:x:0:0::/root:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n"), 0o644)
	u.Invalidate()
	if got := u.Name(1001); got != "bob" {
		t.Fatalf("after useradd: %q", got)
	}
}
