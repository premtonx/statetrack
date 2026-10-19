package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/statetrack/statetrack/agent/internal/baseline"
	"github.com/statetrack/statetrack/agent/internal/debouncer"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	"github.com/statetrack/statetrack/agent/internal/shadow"
	"github.com/statetrack/statetrack/agent/internal/spool"
	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/pkg/redact"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fixture struct {
	eng   *Engine
	clk   *clock
	root  string // simulated host filesystem
	state string // agent state dir (shadow + spool)
	salt  []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{clk: &clock{t: time.Unix(1_800_000_000, 0)}, root: t.TempDir(), state: t.TempDir(), salt: []byte("host-salt")}
	r := filepath.ToSlash(f.root)
	cls, err := limiter.NewClassifier(limiter.ClassifierConfig{
		Blacklist: []string{r + "/var/cache/**", "*.swp", "*~", "4913", "sed??????", "*.log"},
		Critical:  []string{r + "/etc/**"},
		Self:      []string{r + "/etc/statetrack/**"},
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := shadow.Open(ctx, filepath.Join(f.state, "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sp, err := spool.Open(ctx, filepath.Join(f.state, "spool.db"), spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sp.Close() })

	f.eng = &Engine{
		HostID:     "host-1",
		Classifier: cls,
		Breaker:    limiter.NewBreaker(limiter.DefaultBreakerConfig()),
		Tracker:    shadow.NewTracker(store, redact.New(f.salt), shadow.TrackerOptions{DiffContext: -1, Now: f.clk.Now}),
		Debouncer:  debouncer.New(debouncer.Config{HostID: "host-1"}),
		Spool:      sp,
		Now:        f.clk.Now,
	}
	return f
}

func (f *fixture) path(rel string) string { return filepath.Join(f.root, filepath.FromSlash(rel)) }

func (f *fixture) write(t *testing.T, rel, content string) string {
	t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) handle(t *testing.T, p string, actor *pb.ActorContext, ancestry []limiter.Process) {
	t.Helper()
	if err := f.eng.HandleFile(context.Background(), FileEvent{Path: p, Actor: actor, Ancestry: ancestry}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) tick(t *testing.T) {
	t.Helper()
	if err := f.eng.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) spooled(t *testing.T) []*pb.MutationEvent {
	t.Helper()
	evs, err := f.eng.Spool.ReadBatch(context.Background(), 10000, 0)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func (f *fixture) baseline(t *testing.T, roots ...string) baseline.Stats {
	t.Helper()
	w := &baseline.Walker{Tracker: f.eng.Tracker, Policy: f.eng.Policy()}
	var abs []string
	for _, r := range roots {
		abs = append(abs, f.path(r))
	}
	st, err := w.Run(context.Background(), abs)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func unzip(t *testing.T, ev *pb.MutationEvent) string {
	t.Helper()
	if len(ev.UnifiedDiffZstd) == 0 {
		return ""
	}
	s, err := diff.DecompressString(ev.UnifiedDiffZstd)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var (
	vimActor = &pb.ActorContext{Username: "root", UidOrSid: "0", LoginUid: "1000", Pid: 28411, Ppid: 8819,
		ProcessName: "vim", ProcessLineage: []string{"sshd", "bash", "sudo", "vim"}, RemoteIp: "192.168.1.50"}
	vimAncestry = []limiter.Process{{PID: 28411, Name: "vim"}, {PID: 8819, Name: "sudo"}, {PID: 4412, Name: "bash"}, {PID: 1022, Name: "sshd"}}
)

func aptAncestry(leaf uint32) []limiter.Process {
	return []limiter.Process{{PID: leaf, Name: "sh"}, {PID: 300, Name: "dpkg"},
		{PID: 200, Name: "apt-get", Cmdline: "apt-get install -y nginx"}, {PID: 1, Name: "systemd"}}
}

func TestDayZeroBaselineThenScrubbedCriticalDiff(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/app/db.ini", "[db]\nhost = db.internal\npassword = hunter2\n")
	f.write(t, "etc/hosts", "127.0.0.1 localhost\n")
	f.write(t, "var/cache/x.bin", "cache")
	if st := f.baseline(t, "etc", "var"); st.Files != 2 {
		t.Fatalf("baseline stats %+v", st)
	}

	// Collectors may report pre-existing files (e.g. initial inotify scan):
	// nothing is emitted for unchanged baselined files.
	f.handle(t, f.path("etc/hosts"), vimActor, vimAncestry)
	if evs := f.spooled(t); len(evs) != 0 {
		t.Fatalf("baselined file produced %d events", len(evs))
	}

	p := f.write(t, "etc/app/db.ini", "[db]\nhost = db.internal\npassword = correct-horse\n")
	f.handle(t, p, vimActor, vimAncestry)
	f.tick(t)

	evs := f.spooled(t)
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL || ev.Category != pb.Category_CATEGORY_CONFIG ||
		ev.Action != pb.Action_ACTION_MODIFIED || ev.ParentEventId != "" || ev.HostId != "host-1" {
		t.Fatalf("event: %v", ev)
	}
	if ev.Target.HashBefore == "" || ev.Target.HashAfter == "" || ev.Target.HashBefore == ev.Target.HashAfter {
		t.Fatalf("hashes: %v", ev.Target)
	}
	if ev.Actor.RemoteIp != "192.168.1.50" || ev.Actor.LoginUid != "1000" {
		t.Fatalf("actor: %v", ev.Actor)
	}
	d := unzip(t, ev)
	s := redact.New(f.salt)
	if strings.Contains(d, "hunter2") || strings.Contains(d, "correct-horse") ||
		!strings.Contains(d, "-password = "+s.Stub("hunter2")+"\n+password = "+s.Stub("correct-horse")+"\n") {
		t.Fatalf("diff not scrubbed correctly:\n%s", d)
	}
	if !strings.HasSuffix(ev.Summary, "db.ini (+1 -1)") {
		t.Fatalf("summary %q", ev.Summary)
	}
}

func TestPackageBurstCollapsesUnderOneParent(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 30; i++ {
		f.write(t, fmt.Sprintf("usr/share/nginx/f%02d.html", i), "v1\n")
	}
	f.write(t, "etc/nginx/nginx.conf", "worker_processes 1;\n")
	f.baseline(t, "usr", "etc")

	aptActor := &pb.ActorContext{Username: "root", UidOrSid: "0", LoginUid: "1000", Pid: 400}
	for i := 0; i < 30; i++ {
		f.clk.Advance(50 * time.Millisecond)
		p := f.write(t, fmt.Sprintf("usr/share/nginx/f%02d.html", i), "v2\n")
		f.handle(t, p, aptActor, aptAncestry(uint32(400+i)))
	}
	conf := f.write(t, "etc/nginx/nginx.conf", "worker_processes auto;\n")
	f.handle(t, conf, aptActor, aptAncestry(450))

	// An unrelated human edit during the upgrade stays separate.
	hosts := f.write(t, "etc/hosts", "10.0.0.1 db\n")
	f.handle(t, hosts, vimActor, vimAncestry)

	f.clk.Advance(2 * time.Second)
	f.tick(t)
	if n := len(f.spooled(t)); n != 32 {
		t.Fatalf("before window close: %d events, want 32 children/standalone", n)
	}
	f.clk.Advance(time.Second)
	f.tick(t)

	var parent *pb.MutationEvent
	children := map[string]int{}
	var standalone []*pb.MutationEvent
	for _, ev := range f.spooled(t) {
		switch {
		case ev.Metadata["event_type"] == "TRANSACTION":
			parent = ev
		case ev.ParentEventId != "":
			children[ev.ParentEventId]++
			if ev.Level != pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED {
				t.Errorf("child level %v", ev.Level)
			}
			if strings.HasSuffix(ev.Target.PathOrKey, "nginx.conf") && unzip(t, ev) == "" {
				t.Error("config file under apt lost its diff")
			}
			if strings.HasSuffix(ev.Target.PathOrKey, ".html") && len(ev.UnifiedDiffZstd) != 0 {
				t.Error("package payload file was diffed")
			}
		default:
			standalone = append(standalone, ev)
		}
	}
	if parent == nil || parent.ChildCount != 31 || len(children) != 1 || children[parent.EventId] != 31 {
		t.Fatalf("parent=%v children=%v", parent, children)
	}
	if parent.Summary != "apt transaction: 31 related changes" || parent.Actor.ProcessName != "apt-get" {
		t.Fatalf("parent: %v", parent)
	}
	if len(standalone) != 1 || !strings.HasSuffix(standalone[0].Target.PathOrKey, "hosts") ||
		standalone[0].Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
		t.Fatalf("standalone: %v", standalone)
	}
}

func TestChangeStormIsThrottledAndSummarised(t *testing.T) {
	f := newFixture(t)
	deployer := &pb.ActorContext{Username: "deploy", Pid: 4242, ProcessName: "rsync"}
	anc := []limiter.Process{{PID: 4242, Name: "rsync"}, {PID: 1, Name: "systemd"}}
	// The whole burst lands at one instant, so the bucket cannot refill.
	for i := 0; i < 120; i++ {
		p := f.write(t, fmt.Sprintf("var/www/html/asset%03d.js", i), "x")
		f.handle(t, p, deployer, anc)
	}
	if n := len(f.spooled(t)); n != 50 {
		t.Fatalf("expected 50 events before throttling, got %d", n)
	}
	// Throttled files were not shadowed: they surface after the storm.
	if _, ok, _ := f.eng.Tracker.Store().Get(context.Background(), f.path("var/www/html/asset119.js")); ok {
		t.Fatal("throttled file was processed")
	}

	f.clk.Advance(29 * time.Second)
	f.tick(t)
	if n := len(f.spooled(t)); n != 50 {
		t.Fatal("storm summary emitted before cooldown ended")
	}
	f.clk.Advance(2 * time.Second)
	f.tick(t)
	evs := f.spooled(t)
	if len(evs) != 51 {
		t.Fatalf("got %d events, want 50 + 1 summary", len(evs))
	}
	s := evs[50]
	if s.Action != pb.Action_ACTION_THROTTLED || s.Metadata["event_type"] != "CHANGE_STORM_THROTTLED" ||
		s.Metadata["mutation_count"] != "70" || s.Level != pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT ||
		s.Target.PathOrKey != filepath.Dir(f.path("var/www/html/x")) {
		t.Fatalf("summary: %v", s)
	}
	if !strings.Contains(s.Summary, "70 mutations under") {
		t.Fatalf("summary text %q", s.Summary)
	}
}

func TestThrottledPackageChildrenStillCountTowardsParent(t *testing.T) {
	f := newFixture(t)
	actor := &pb.ActorContext{Pid: 400}
	for i := 0; i < 80; i++ {
		p := f.write(t, fmt.Sprintf("usr/lib/x/lib%02d.so", i), "\x7fELF\x00")
		f.handle(t, p, actor, aptAncestry(400))
	}
	f.clk.Advance(31 * time.Second)
	f.tick(t)
	var parent, storm *pb.MutationEvent
	children := 0
	for _, ev := range f.spooled(t) {
		switch {
		case ev.Metadata["event_type"] == "TRANSACTION":
			parent = ev
		case ev.Metadata["event_type"] == "CHANGE_STORM_THROTTLED":
			storm = ev
		case ev.ParentEventId != "":
			children++
		}
	}
	if parent == nil || parent.ChildCount != 80 || children != 50 || parent.Metadata["children_throttled"] != "30" {
		t.Fatalf("parent=%v children=%d", parent, children)
	}
	if storm == nil || storm.Metadata["mutation_count"] != "30" {
		t.Fatalf("storm summary: %v", storm)
	}
}

func TestPackageLogEventsGroupWithFileMutations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	conf := f.write(t, "etc/nginx/nginx.conf", "worker_processes 1;\n")
	f.baseline(t, f.root)

	os.WriteFile(conf, []byte("worker_processes auto;\n"), 0o644)
	f.handle(t, conf, &pb.ActorContext{Pid: 400, LoginUsername: "alice"}, aptAncestry(400))
	f.clk.Advance(500 * time.Millisecond)
	err := f.eng.HandleEvent(ctx, Event{
		Category: pb.Category_CATEGORY_PACKAGE, Action: pb.Action_ACTION_UPGRADED,
		Summary:  "Upgraded nginx 1.24.0 -> 1.26.1",
		Target:   &pb.TargetResource{TargetType: "package", PathOrKey: "nginx", VersionBefore: "1.24.0", VersionAfter: "1.26.1"},
		Ancestry: []limiter.Process{{Name: "dpkg"}},
		Metadata: map[string]string{"source": "dpkg.log"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(time.Second)
	// The postinst restart reported by the service collector has no ancestry.
	if err := f.eng.HandleEvent(ctx, Event{
		Category: pb.Category_CATEGORY_SERVICE, Action: pb.Action_ACTION_RESTARTED, Summary: "Restarted nginx.service",
		Target: &pb.TargetResource{TargetType: "service", PathOrKey: "nginx.service"}, Correlate: true,
	}); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(3 * time.Second)
	f.tick(t)

	evs := f.spooled(t)
	if len(evs) != 4 {
		t.Fatalf("want file + package + service + parent, got %d", len(evs))
	}
	parent := evs[3]
	for _, c := range evs[:3] {
		if c.ParentEventId != parent.EventId || c.Level != pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED {
			t.Fatalf("child %s not grouped: parent=%q level=%v", c.Summary, c.ParentEventId, c.Level)
		}
	}
	if pkg := evs[1]; pkg.Category != pb.Category_CATEGORY_PACKAGE || pkg.Metadata["source"] != "dpkg.log" ||
		pkg.Target.VersionAfter != "1.26.1" {
		t.Fatalf("package event: %+v", pkg)
	}
	if parent.ChildCount != 3 || parent.Actor.Pid != 200 || parent.Actor.LoginUsername != "alice" ||
		parent.Metadata["packages"] != "nginx 1.24.0 -> 1.26.1" || parent.Metadata["categories"] != "config=1,package=1,service=1" {
		t.Fatalf("parent: %+v %v", parent.Actor, parent.Metadata)
	}
}

func TestUncorrelatedServiceEventIsCritical(t *testing.T) {
	f := newFixture(t)
	if err := f.eng.HandleEvent(context.Background(), Event{
		Category: pb.Category_CATEGORY_SERVICE, Action: pb.Action_ACTION_STOPPED, Summary: "nginx.service crashed",
		Target: &pb.TargetResource{TargetType: "service", PathOrKey: "nginx.service"}, Correlate: true,
		Metadata: map[string]string{"event_type": "SERVICE_CRASHED"},
	}); err != nil {
		t.Fatal(err)
	}
	evs := f.spooled(t)
	if len(evs) != 1 || evs[0].Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL || evs[0].ParentEventId != "" ||
		evs[0].Metadata["event_type"] != "SERVICE_CRASHED" || evs[0].Metadata["classification"] != "critical_category" {
		t.Fatalf("got %+v", evs)
	}
}

func TestBinaryAndLargeFilesAreHashOnly(t *testing.T) {
	f := newFixture(t)
	bin := f.write(t, "etc/ssl/cert.der", "\x30\x82\x00\x01")
	big := f.write(t, "etc/big.conf", strings.Repeat("k=v\n", limiter.MaxDiffFileSize/4+1))
	f.baseline(t, "etc")
	f.write(t, "etc/ssl/cert.der", "\x30\x82\x00\x02")
	f.write(t, "etc/big.conf", strings.Repeat("k=w\n", limiter.MaxDiffFileSize/4+1))
	f.handle(t, bin, vimActor, vimAncestry)
	f.handle(t, big, vimActor, vimAncestry)

	evs := f.spooled(t)
	if len(evs) != 2 {
		t.Fatalf("got %d events", len(evs))
	}
	for _, ev := range evs {
		if ev.Metadata["event_type"] != "BINARY_MODIFIED" || len(ev.UnifiedDiffZstd) != 0 ||
			ev.Target.HashBefore == ev.Target.HashAfter || ev.Target.SizeAfter == 0 || ev.Action != pb.Action_ACTION_MODIFIED {
			t.Errorf("%s: %v", ev.Target.PathOrKey, ev)
		}
	}
	if evs[0].Metadata["content"] != "binary" || evs[1].Metadata["content"] != "too_large" {
		t.Fatalf("content kinds: %s, %s", evs[0].Metadata["content"], evs[1].Metadata["content"])
	}
}

func TestBlacklistedPathsProduceNothing(t *testing.T) {
	f := newFixture(t)
	for _, rel := range []string{"var/cache/apt/pkgcache.bin", "etc/.hosts.swp", "etc/hosts~", "etc/4913", "etc/sedAb12Cd", "etc/app.log"} {
		f.handle(t, f.write(t, rel, "x"), vimActor, vimAncestry)
	}
	f.tick(t)
	if evs := f.spooled(t); len(evs) != 0 {
		t.Fatalf("blacklisted paths produced %d events", len(evs))
	}
	if n, _ := f.eng.Tracker.Store().Count(context.Background()); n != 0 {
		t.Fatalf("blacklisted paths were shadowed: %d", n)
	}
}

func TestVimSaveSequenceIsOneModification(t *testing.T) {
	f := newFixture(t)
	p := f.write(t, "etc/nginx/nginx.conf", "worker_processes 1;\n")
	f.baseline(t, "etc")

	// vim: write 4913 probe, rename original to backup~, write new file, remove backup.
	f.handle(t, f.write(t, "etc/nginx/4913", ""), vimActor, vimAncestry)
	os.Remove(f.path("etc/nginx/4913"))
	if err := os.Rename(p, p+"~"); err != nil {
		t.Fatal(err)
	}
	f.handle(t, p, vimActor, vimAncestry)
	f.handle(t, p+"~", vimActor, vimAncestry)
	f.clk.Advance(100 * time.Millisecond)
	f.write(t, "etc/nginx/nginx.conf", "worker_processes auto;\n")
	f.handle(t, p, vimActor, vimAncestry)
	os.Remove(p + "~")
	f.clk.Advance(5 * time.Second)
	f.tick(t)

	evs := f.spooled(t)
	if len(evs) != 1 || evs[0].Action != pb.Action_ACTION_MODIFIED ||
		!strings.Contains(unzip(t, evs[0]), "-worker_processes 1;\n+worker_processes auto;\n") {
		t.Fatalf("vim save: %v", evs)
	}
}

func TestDeleteIsConfirmedOnTickWithOriginalActor(t *testing.T) {
	f := newFixture(t)
	p := f.write(t, "etc/sudoers.d/90-ops", "ops ALL=(ALL) NOPASSWD: ALL\n")
	f.baseline(t, "etc")
	os.Remove(p)
	f.handle(t, p, vimActor, vimAncestry)
	f.tick(t)
	if len(f.spooled(t)) != 0 {
		t.Fatal("delete emitted before grace period")
	}
	f.clk.Advance(2 * time.Second)
	f.tick(t)
	evs := f.spooled(t)
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	ev := evs[0]
	if ev.Action != pb.Action_ACTION_DELETED || ev.Actor.GetPid() != vimActor.Pid || ev.Target.HashAfter != "" ||
		!strings.Contains(unzip(t, ev), "-ops ALL=(ALL) NOPASSWD: ALL\n") {
		t.Fatalf("delete event: %v", ev)
	}
}

func TestSelfTamperIsCritical(t *testing.T) {
	f := newFixture(t)
	p := f.write(t, "etc/statetrack/agent.yaml", "server: a\n")
	f.baseline(t, "etc")
	f.write(t, "etc/statetrack/agent.yaml", "server: evil\n")
	f.handle(t, p, vimActor, vimAncestry)
	evs := f.spooled(t)
	if len(evs) != 1 || evs[0].Category != pb.Category_CATEGORY_AGENT_HEALTH || evs[0].Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL ||
		evs[0].Metadata["classification"] != "agent_self_tamper" {
		t.Fatalf("self tamper: %v", evs)
	}
}

func TestSpoolSurvivesRestartAndDrainsWithAcks(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/a.conf", "1\n")
	f.baseline(t, "etc")
	for i := 2; i < 6; i++ {
		f.handle(t, f.write(t, "etc/a.conf", fmt.Sprintf("%d\n", i)), vimActor, vimAncestry)
	}
	ctx := context.Background()
	f.eng.Spool.Close()
	sp, err := spool.Open(ctx, filepath.Join(f.state, "spool.db"), spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	batch, err := sp.ReadBatch(ctx, 2, 0)
	if err != nil || len(batch) != 2 {
		t.Fatalf("batch: %d %v", len(batch), err)
	}
	if n, _ := sp.Ack(ctx, []string{batch[0].EventId, batch[1].EventId}); n != 2 {
		t.Fatal("ack failed")
	}
	rest, _ := sp.ReadBatch(ctx, 100, 0)
	if len(rest) != 2 || rest[0].MonotonicSeq <= batch[1].MonotonicSeq {
		t.Fatalf("remaining: %d", len(rest))
	}
}
