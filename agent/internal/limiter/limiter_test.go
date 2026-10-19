package limiter

import (
	"bytes"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

func TestMatcher(t *testing.T) {
	m := MustMatcher("/proc/**", "/var/lib/postgresql/**/data/**", "*.log", `C:\Windows\Temp\**`,
		"**/web.config", "/etc/*.conf", "sed??????")
	tests := []struct {
		path string
		want bool
	}{
		{"/proc", true},
		{"/proc/1/status", true},
		{"/procfs/x", false},
		{"/var/lib/postgresql/17/main/data/base/1", true},
		{"/var/lib/postgresql/17/main/base/1", false},
		{"/var/lib/postgresql/17/data/base/1", true},
		{"/var/log/syslog.log", true},
		{"/srv/APP.LOG", true},
		{"/etc/logrotate.conf", true},
		{"/etc/nginx/nginx.conf", false},
		{`C:\Windows\Temp\x\y.tmp`, true},
		{`c:\windows\TEMP\a`, true},
		{`C:\Windows\System32\a`, false},
		{`D:\sites\app\Web.Config`, true},
		{"/srv/app/web.config", true},
		{"/etc/sedAb12Cd", true},
		{"/etc/sedan", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := m.Match(tc.path); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestMatcherUnixPatternsAreCaseSensitive(t *testing.T) {
	m := MustMatcher("/etc/**")
	if m.Match("/ETC/passwd") {
		t.Fatal("unix pattern matched case-insensitively")
	}
	if MustMatcher(`C:\Windows\**`).Match("/windows/x") {
		t.Fatal("windows pattern matched a unix path")
	}
}

func TestMatcherRejectsBadPattern(t *testing.T) {
	if _, err := NewMatcher("/etc/[abc"); err == nil {
		t.Fatal("expected error for malformed pattern")
	}
}

func TestDefaultBlacklist(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{})
	if err != nil {
		t.Fatal(err)
	}
	drop := []string{
		"/proc/self/environ", "/sys/kernel/x", "/tmp/foo", "/var/log/nginx/access.log", "/var/cache/apt/a.bin",
		"/var/lib/docker/overlay2/abc/diff/etc/passwd", "/var/lib/postgresql/data/pg_wal/1",
		"/var/lib/postgresql/16/main/data/x", "/var/lib/mysql/ibdata1",
		`C:\Windows\Temp\x.tmp`, `C:\app\trace.ETL`, `C:\Windows\System32\winevt\Logs\System.evtx`,
		"/etc/.nginx.conf.swp", "/etc/nginx/nginx.conf~", "/etc/nginx/4913", "/etc/sedX1y2Z3",
		"/var/lib/statetrack/shadow/objects/ab/cd.zst",
		"/var/spool/postfix/active/A1B2", "/var/spool/cups/c00001",
		"/etc/passwd+", "/etc/shadow.lock", "/etc/.pwd.lock", "/etc/passwd-", "/etc/sudoers.tmp",
	}
	for _, p := range drop {
		if d := c.Classify(Candidate{Path: p}); !d.Drop || !c.Blacklisted(p) {
			t.Errorf("%s: expected Level 0 drop, got %+v", p, d)
		}
	}
	keep := []string{"/etc/nginx/nginx.conf", "/etc/logrotate.d/nginx", "/opt/app/config.yml", `C:\inetpub\wwwroot\web.config`}
	for _, p := range keep {
		if d := c.Classify(Candidate{Path: p}); d.Drop {
			t.Errorf("%s: unexpectedly dropped (%s)", p, d.Reason)
		}
	}
}

func TestClassifyLevels(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{})
	if err != nil {
		t.Fatal(err)
	}
	apt := &Tool{Name: "apt", Kind: ToolPackageManager}
	const (
		L1 = pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL
		L2 = pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED
		L3 = pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT
	)
	tests := []struct {
		name     string
		cand     Candidate
		level    pb.ImpactLevel
		category pb.Category
		diff     bool
	}{
		{"etc config", Candidate{Path: "/etc/nginx/nginx.conf"}, L1, pb.Category_CATEGORY_CONFIG, true},
		{"usr local etc", Candidate{Path: "/usr/local/etc/redis.conf"}, L1, pb.Category_CATEGORY_CONFIG, true},
		{"crontab spool", Candidate{Path: "/var/spool/cron/crontabs/root"}, L1, pb.Category_CATEGORY_CONFIG, true},
		{"passwd", Candidate{Path: "/etc/passwd"}, L1, pb.Category_CATEGORY_USER, true},
		{"sudoers.d", Candidate{Path: "/etc/sudoers.d/90-ops"}, L1, pb.Category_CATEGORY_USER, true},
		{"authorized_keys", Candidate{Path: "/home/alice/.ssh/authorized_keys"}, L1, pb.Category_CATEGORY_USER, true},
		{"systemd unit", Candidate{Path: "/etc/systemd/system/nginx.service"}, L1, pb.Category_CATEGORY_SERVICE, true},
		{"iis config", Candidate{Path: `C:\Windows\System32\inetsrv\config\applicationHost.config`}, L1, pb.Category_CATEGORY_CONFIG, true},
		{"web.config", Candidate{Path: `D:\sites\shop\web.config`}, L1, pb.Category_CATEGORY_CONFIG, true},
		{"service event", Candidate{Category: pb.Category_CATEGORY_SERVICE}, L1, pb.Category_CATEGORY_SERVICE, false},
		{"self tamper", Candidate{Path: "/etc/statetrack/agent.yaml"}, L1, pb.Category_CATEGORY_AGENT_HEALTH, true},
		{"self tamper beats grouping", Candidate{Path: "/usr/bin/statetrack-agent", Tool: apt}, L1, pb.Category_CATEGORY_AGENT_HEALTH, true},
		{"apt config", Candidate{Path: "/etc/nginx/nginx.conf", Tool: apt}, L2, pb.Category_CATEGORY_CONFIG, true},
		{"apt payload", Candidate{Path: "/usr/sbin/nginx", Tool: apt}, L2, pb.Category_CATEGORY_CONFIG, false},
		{"web asset", Candidate{Path: "/var/www/html/index.html"}, L3, pb.Category_CATEGORY_CONFIG, false},
		{"opt", Candidate{Path: "/opt/app/lib/x.jar"}, L3, pb.Category_CATEGORY_CONFIG, false},
		{"registry minor", Candidate{Path: `HKLM\SOFTWARE\Vendor\App\Theme`, Category: pb.Category_CATEGORY_REGISTRY}, L3, pb.Category_CATEGORY_REGISTRY, false},
		{"registry service", Candidate{Path: `HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Start`}, L1, pb.Category_CATEGORY_SERVICE, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := c.Classify(tc.cand)
			if d.Drop || d.Level != tc.level || d.Category != tc.category || d.Diff != tc.diff {
				t.Fatalf("got %+v, want level=%v category=%v diff=%v", d, tc.level, tc.category, tc.diff)
			}
		})
	}
}

func TestReconfigureSwapsRulesAndKeepsForensicState(t *testing.T) {
	c, _ := NewClassifier(ClassifierConfig{})
	now := time.Unix(1_800_000_000, 0)
	c.SetForensicUntil(now, now.Add(time.Minute))

	if c.Blacklisted("/etc/noisy/state.json") {
		t.Fatal("precondition")
	}
	if err := c.Reconfigure(ClassifierConfig{
		ExtraBlacklist: []string{"/etc/noisy/**"},
		ExtraCritical:  []string{"/opt/app/conf/**"},
		ExtraSelf:      []string{"/opt/statetrack/agent"},
	}); err != nil {
		t.Fatal(err)
	}
	if !c.Blacklisted("/etc/noisy/state.json") || !c.Blacklisted("/proc/1/status") {
		t.Fatal("extra blacklist must be added to the defaults")
	}
	if d := c.Classify(Candidate{Path: "/opt/app/conf/app.yml"}); d.Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL || !d.Diff {
		t.Fatalf("extra critical not applied: %+v", d)
	}
	if !c.SelfPath("/opt/statetrack/agent") || !c.SelfPath("/etc/statetrack/agent.yaml") {
		t.Fatal("extra self path not applied")
	}
	if !c.ForensicActive(now) {
		t.Fatal("Reconfigure cleared the forensic window")
	}
	if err := c.Reconfigure(ClassifierConfig{ExtraBlacklist: []string{"[bad"}}); err == nil {
		t.Fatal("bad pattern accepted")
	}
	if !c.Blacklisted("/etc/noisy/state.json") {
		t.Fatal("failed Reconfigure must keep the previous rules")
	}
}

func TestForensicToggle(t *testing.T) {
	c, _ := NewClassifier(ClassifierConfig{})
	now := time.Unix(1_800_000_000, 0)
	exec := Candidate{Category: pb.Category_CATEGORY_PROCESS, Now: now}

	if d := c.Classify(exec); !d.Drop || d.Level != pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC {
		t.Fatalf("Level 4 must be dropped by default, got %+v", d)
	}
	c.SetForensicUntil(now, now.Add(5*time.Minute))
	if d := c.Classify(exec); d.Drop {
		t.Fatalf("Level 4 should be collected in forensic mode, got %+v", d)
	}
	exec.Now = now.Add(5*time.Minute + time.Second)
	if d := c.Classify(exec); !d.Drop {
		t.Fatal("forensic mode should have expired")
	}

	// Requests longer than 15 minutes are capped.
	c.SetForensicUntil(now, now.Add(24*time.Hour))
	if !c.ForensicActive(now.Add(14*time.Minute)) || c.ForensicActive(now.Add(15*time.Minute)) {
		t.Fatal("forensic window not capped at 15 minutes")
	}
	c.SetForensicUntil(now, time.Time{})
	if c.ForensicActive(now) {
		t.Fatal("zero time should disable forensic mode")
	}
}

func TestDetectContent(t *testing.T) {
	text := []byte("server {\n listen 80;\n}\n")
	if k := DetectContent(int64(len(text)), text); k != ContentText {
		t.Errorf("text detected as %v", k)
	}
	bin := append([]byte("\x7fELF"), 0, 1, 2)
	if k := DetectContent(int64(len(bin)), bin); k != ContentBinary {
		t.Errorf("ELF detected as %v", k)
	}
	lateNUL := append(bytes.Repeat([]byte("a"), BinarySniffLen), 0)
	if k := DetectContent(int64(len(lateNUL)), lateNUL); k != ContentText {
		t.Errorf("NUL after sniff window should not make the file binary, got %v", k)
	}
	if k := DetectContent(MaxDiffFileSize, text); k != ContentText {
		t.Errorf("exactly 1 MiB should still be diffed, got %v", k)
	}
	if k := DetectContent(MaxDiffFileSize+1, text); k != ContentTooLarge {
		t.Errorf("> 1 MiB detected as %v", k)
	}
}

func TestGroupingTools(t *testing.T) {
	tests := []struct {
		p    Process
		want string
	}{
		{Process{Name: "apt-get"}, "apt"},
		{Process{Name: "unattended-upgr"}, "apt"},
		{Process{Name: "dpkg"}, "dpkg"},
		{Process{Name: "dnf"}, "dnf"},
		{Process{Name: "MsiExec.exe"}, "msiexec"},
		{Process{Name: `C:\Windows\System32\msiexec.exe`}, "msiexec"},
		{Process{Name: "python3", Cmdline: "/usr/bin/python3 /usr/bin/ansible-playbook site.yml"}, "ansible"},
		{Process{Name: "python3", Cmdline: "/usr/bin/python3 /root/.ansible/tmp/x/AnsiballZ_copy.py"}, "ansible"},
		{Process{Name: "Runner.Worker"}, "github-actions"},
		{Process{Name: "vim"}, ""},
		{Process{Name: "bash", Cmdline: "bash -c echo apt"}, ""},
	}
	for _, tc := range tests {
		tool, ok := GroupingTool(tc.p)
		if got := tool.Name; ok != (tc.want != "") || got != tc.want {
			t.Errorf("GroupingTool(%+v) = %q,%v want %q", tc.p, got, ok, tc.want)
		}
	}
}

func TestGroupingRootIsOutermostTool(t *testing.T) {
	ancestry := []Process{
		{PID: 400, Name: "sh", Cmdline: "/bin/sh /var/lib/dpkg/info/nginx.postinst configure"},
		{PID: 300, Name: "dpkg"},
		{PID: 200, Name: "apt-get", Cmdline: "apt-get install -y nginx"},
		{PID: 100, Name: "bash"},
		{PID: 1, Name: "systemd"},
	}
	root, tool, ok := GroupingRoot(ancestry)
	if !ok || root.PID != 200 || tool.Name != "apt" || tool.Category() != pb.Category_CATEGORY_PACKAGE {
		t.Fatalf("got root=%+v tool=%+v ok=%v", root, tool, ok)
	}
	if _, _, ok := GroupingRoot([]Process{{PID: 9, Name: "vim"}, {PID: 1, Name: "systemd"}}); ok {
		t.Fatal("vim must not be grouped")
	}
}

func TestBreakerTripsAfterBurstAndSummarises(t *testing.T) {
	b := NewBreaker(DefaultBreakerConfig())
	t0 := time.Unix(1_800_000_000, 0)
	ev := StormEvent{Dir: "/var/www/html", Level: pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT}

	// 50 events within 10 s pass.
	for i := 0; i < 50; i++ {
		if v := b.Allow(t0.Add(time.Duration(i)*time.Millisecond), ev); v.Throttled {
			t.Fatalf("event %d throttled too early", i)
		}
	}
	// The 51st trips the circuit.
	v := b.Allow(t0.Add(60*time.Millisecond), ev)
	if !v.Throttled || !v.Tripped || v.Kind != ScopeDirectory || v.Scope != "/var/www/html" {
		t.Fatalf("51st event: %+v", v)
	}
	// Everything during the 30 s cooldown is suppressed, including a more
	// severe event.
	for i := 0; i < 99; i++ {
		e := ev
		if i == 10 {
			e.Level = pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL
		}
		if v := b.Allow(t0.Add(time.Second+time.Duration(i)*100*time.Millisecond), e); !v.Throttled || v.Tripped {
			t.Fatalf("cooldown event %d: %+v", i, v)
		}
	}
	if got := b.Sweep(t0.Add(20 * time.Second)); len(got) != 0 {
		t.Fatalf("summary emitted before cooldown ended: %+v", got)
	}
	sums := b.Sweep(t0.Add(31 * time.Second))
	if len(sums) != 1 {
		t.Fatalf("want 1 summary, got %+v", sums)
	}
	s := sums[0]
	if s.Suppressed != 100 || s.Kind != ScopeDirectory || s.Scope != "/var/www/html" ||
		s.Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL || s.Until.Sub(s.Since) != 30*time.Second {
		t.Fatalf("bad summary %+v", s)
	}
	// After the cooldown the bucket has refilled and events flow again.
	if v := b.Allow(t0.Add(32*time.Second), ev); v.Throttled {
		t.Fatal("still throttled after cooldown")
	}
	if got := b.Sweep(t0.Add(40 * time.Second)); len(got) != 0 {
		t.Fatalf("duplicate summary: %+v", got)
	}
}

func TestBreakerSustainedRateBelowThresholdNeverTrips(t *testing.T) {
	b := NewBreaker(DefaultBreakerConfig())
	t0 := time.Unix(1_800_000_000, 0)
	// 4 events/s is below 50 per 10 s.
	for i := 0; i < 400; i++ {
		if v := b.Allow(t0.Add(time.Duration(i)*250*time.Millisecond), StormEvent{Dir: "/etc"}); v.Throttled {
			t.Fatalf("throttled at event %d", i)
		}
	}
}

func TestBreakerPIDScopeAcrossDirectories(t *testing.T) {
	b := NewBreaker(DefaultBreakerConfig())
	t0 := time.Unix(1_800_000_000, 0)
	var tripped Verdict
	for i := 0; i < 60; i++ {
		dir := "/srv/d" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if v := b.Allow(t0, StormEvent{Dir: dir, PID: 4242}); v.Tripped {
			tripped = v
		}
	}
	if tripped.Kind != ScopePID || tripped.Scope != "4242" {
		t.Fatalf("expected PID scope to trip, got %+v", tripped)
	}
	if !b.Throttled(t0, ScopePID, "4242") || b.Throttled(t0, ScopeDirectory, "/srv/daa") {
		t.Fatal("Throttled() state mismatch")
	}
}

func TestBreakerScopesAreIndependentAndIdleScopesExpire(t *testing.T) {
	b := NewBreaker(BreakerConfig{Burst: 2, Window: time.Second, Cooldown: time.Second, IdleTTL: time.Minute, MaxScopes: 2})
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		b.Allow(t0, StormEvent{Dir: "/a"})
	}
	if v := b.Allow(t0, StormEvent{Dir: "/b"}); v.Throttled {
		t.Fatal("storm in /a throttled /b")
	}
	// MaxScopes reached: a third scope is not tracked (fail open).
	for i := 0; i < 5; i++ {
		if v := b.Allow(t0, StormEvent{Dir: "/c"}); v.Throttled {
			t.Fatal("untracked scope throttled")
		}
	}
	b.Sweep(t0.Add(2 * time.Minute))
	b.mu.Lock()
	n := len(b.scopes)
	b.mu.Unlock()
	if n != 0 {
		t.Fatalf("idle scopes not evicted: %d left", n)
	}
}

func TestBreakerCooldownEndObservedByAllow(t *testing.T) {
	b := NewBreaker(BreakerConfig{Burst: 1, Window: time.Second, Cooldown: time.Second})
	t0 := time.Unix(1_800_000_000, 0)
	b.Allow(t0, StormEvent{Dir: "/x"})
	b.Allow(t0, StormEvent{Dir: "/x"}) // trips
	b.Allow(t0.Add(5*time.Second), StormEvent{Dir: "/x"})
	if sums := b.Sweep(t0.Add(5 * time.Second)); len(sums) != 1 || sums[0].Suppressed != 1 {
		t.Fatalf("summary lost when cooldown end was observed by Allow: %+v", sums)
	}
}
