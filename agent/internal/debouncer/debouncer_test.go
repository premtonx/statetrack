package debouncer

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

var t0 = time.Unix(1_800_000_000, 0)

func seqIDs() func() string {
	n := 0
	return func() string { n++; return fmt.Sprintf("parent-%d", n) }
}

func aptAncestry(leafPID uint32, leaf string) []limiter.Process {
	return []limiter.Process{
		{PID: leafPID, Name: leaf},
		{PID: 300, Name: "dpkg", Cmdline: "/usr/bin/dpkg --status-fd 23 --configure nginx"},
		{PID: 200, Name: "apt-get", Cmdline: "apt-get install -y nginx"},
		{PID: 150, Name: "sudo"},
		{PID: 100, Name: "bash"},
		{PID: 90, Name: "sshd"},
		{PID: 1, Name: "systemd"},
	}
}

func child(id string, cat pb.Category, action pb.Action, path string) *pb.MutationEvent {
	return &pb.MutationEvent{
		EventId: id, Level: pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED, Category: cat, Action: action,
		Actor:  &pb.ActorContext{Username: "alice", UidOrSid: "0", LoginUid: "1000", RemoteIp: "192.168.1.50", Pid: 400},
		Target: &pb.TargetResource{TargetType: "file", PathOrKey: path},
	}
}

func TestUngroupedEventsPassThrough(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	ev := child("e1", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/hosts")
	out := d.Add(t0, Input{Event: ev, Ancestry: []limiter.Process{{PID: 9, Name: "vim"}, {PID: 1, Name: "systemd"}}})
	if len(out) != 1 || out[0] != ev || ev.ParentEventId != "" || d.Open() != 0 {
		t.Fatalf("passthrough: %+v open=%d", out, d.Open())
	}
}

func TestPackageBurstCollapsesIntoOneParent(t *testing.T) {
	d := New(Config{HostID: "host-1", NewID: seqIDs()})

	var children []*pb.MutationEvent
	// 134 child mutations from different leaf processes under one apt-get,
	// spread over 10 s but never more than 1 s apart.
	for i := 0; i < 134; i++ {
		now := t0.Add(time.Duration(i) * 75 * time.Millisecond)
		cat, action, path := pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, fmt.Sprintf("/usr/share/nginx/f%d", i)
		switch i {
		case 0:
			cat, action, path = pb.Category_CATEGORY_PACKAGE, pb.Action_ACTION_UPGRADED, "nginx"
		case 1:
			cat, action, path = pb.Category_CATEGORY_SERVICE, pb.Action_ACTION_RESTARTED, "nginx.service"
		}
		ev := child(fmt.Sprintf("c%d", i), cat, action, path)
		if i == 0 {
			ev.Target.VersionBefore, ev.Target.VersionAfter = "1.24.0", "1.26.1"
		}
		out := d.Add(now, Input{Event: ev, Ancestry: aptAncestry(uint32(400+i%7), "sh")})
		if len(out) != 1 || out[0] != ev {
			t.Fatalf("child %d: expected immediate release, got %d events", i, len(out))
		}
		children = append(children, ev)
	}
	last := t0.Add(133 * 75 * time.Millisecond)

	if got := d.Flush(last.Add(2900 * time.Millisecond)); len(got) != 0 {
		t.Fatal("transaction closed before the 3 s window elapsed")
	}
	parents := d.Flush(last.Add(3 * time.Second))
	if len(parents) != 1 {
		t.Fatalf("want exactly 1 parent, got %d", len(parents))
	}
	p := parents[0]
	for _, c := range children {
		if c.ParentEventId != p.EventId {
			t.Fatalf("child %s has parent %q, want %q", c.EventId, c.ParentEventId, p.EventId)
		}
	}
	if p.Level != pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED || p.Category != pb.Category_CATEGORY_PACKAGE ||
		p.Action != pb.Action_ACTION_UPGRADED || p.ChildCount != 134 || p.ParentEventId != "" || p.HostId != "host-1" {
		t.Fatalf("parent fields: %+v", p)
	}
	if p.AgentTimestampMs != t0.UnixMilli() {
		t.Fatalf("parent timestamp %d, want first child %d", p.AgentTimestampMs, t0.UnixMilli())
	}
	if p.Summary != "apt transaction: 134 related changes (1 package)" {
		t.Fatalf("summary %q", p.Summary)
	}
	a := p.Actor
	if a.Pid != 200 || a.ProcessName != "apt-get" || a.Username != "alice" || a.LoginUid != "1000" || a.RemoteIp != "192.168.1.50" ||
		strings.Join(a.ProcessLineage, ">") != "systemd>sshd>bash>sudo>apt-get" {
		t.Fatalf("parent actor: %+v", a)
	}
	md := p.Metadata
	if md["packages"] != "nginx 1.24.0 -> 1.26.1" || md["root_pid"] != "200" || md["tool"] != "apt" ||
		md["categories"] != "config=132,package=1,service=1" || md["duration_ms"] != "9975" {
		t.Fatalf("metadata: %v", md)
	}
	if p.Target.GetTargetType() != "transaction" || p.Target.GetPathOrKey() != "apt-get install -y nginx" {
		t.Fatalf("target: %+v", p.Target)
	}
	if d.Open() != 0 {
		t.Fatal("group not removed")
	}
}

func TestWindowIsSliding(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	add := func(at time.Duration) []*pb.MutationEvent {
		return d.Add(t0.Add(at), Input{Event: child("x", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a"),
			Ancestry: aptAncestry(400, "sh")})
	}
	add(0)
	add(2 * time.Second)
	add(4 * time.Second) // 2 s gap: still the same transaction
	if got := d.Flush(t0.Add(6 * time.Second)); len(got) != 0 {
		t.Fatal("closed while still within the sliding window")
	}
	// A 3 s gap closes the first transaction; the next event starts a new one.
	out := add(7 * time.Second)
	if len(out) != 2 || out[0].ChildCount != 3 || out[1].ParentEventId != "parent-2" {
		t.Fatalf("expected closed parent + new child, got %+v", out)
	}
}

func TestSeparateRootsAreSeparateTransactions(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	a := child("a", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a")
	b := child("b", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/b")
	d.Add(t0, Input{Event: a, Ancestry: aptAncestry(400, "sh")})
	d.Add(t0, Input{Event: b, Ancestry: []limiter.Process{{PID: 777, Name: "ansible-playbook"}, {PID: 1, Name: "systemd"}}})
	if a.ParentEventId == b.ParentEventId || d.Open() != 2 {
		t.Fatalf("distinct roots merged: %q %q", a.ParentEventId, b.ParentEventId)
	}
	parents := d.FlushAll()
	if len(parents) != 2 || d.Open() != 0 {
		t.Fatalf("FlushAll: %d parents", len(parents))
	}
}

func syntheticPkg(id, name, before, after string) (*pb.MutationEvent, []limiter.Process) {
	ev := &pb.MutationEvent{EventId: id, Category: pb.Category_CATEGORY_PACKAGE, Action: pb.Action_ACTION_UPGRADED,
		Target: &pb.TargetResource{TargetType: "package", PathOrKey: name, VersionBefore: before, VersionAfter: after}}
	return ev, []limiter.Process{{Name: "dpkg"}}
}

func TestLogDerivedPackageEventsJoinFileTransaction(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	// File writes by dpkg under apt-get arrive first ...
	f := child("f", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/nginx/nginx.conf")
	d.Add(t0, Input{Event: f, Ancestry: aptAncestry(400, "dpkg")})
	// ... then the dpkg.log line, which has no PID.
	p, anc := syntheticPkg("p", "nginx", "1.24.0", "1.26.1")
	d.Add(t0.Add(500*time.Millisecond), Input{Event: p, Ancestry: anc})
	if f.ParentEventId == "" || p.ParentEventId != f.ParentEventId || d.Open() != 1 {
		t.Fatalf("not correlated: file=%q pkg=%q open=%d", f.ParentEventId, p.ParentEventId, d.Open())
	}
	parent := d.FlushAll()[0]
	if parent.Actor.Pid != 200 || parent.Metadata["tool"] != "apt" || parent.Metadata["packages"] != "nginx 1.24.0 -> 1.26.1" ||
		parent.Actor.LoginUid != "1000" {
		t.Fatalf("parent: %+v %v", parent.Actor, parent.Metadata)
	}
}

func TestSyntheticRootIsUpgradedWhenRealRootAppears(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	p, anc := syntheticPkg("p", "curl", "8.5.0", "8.11.1")
	d.Add(t0, Input{Event: p, Ancestry: anc})
	f := child("f", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/usr/bin/curl")
	d.Add(t0.Add(time.Second), Input{Event: f, Ancestry: aptAncestry(400, "dpkg")})
	if p.ParentEventId != f.ParentEventId {
		t.Fatal("not correlated")
	}
	parent := d.FlushAll()[0]
	if parent.Actor.Pid != 200 || parent.Actor.ProcessName != "apt-get" || parent.Actor.Username != "alice" ||
		strings.Join(parent.Actor.ProcessLineage, ">") != "systemd>sshd>bash>sudo>apt-get" || parent.ChildCount != 2 {
		t.Fatalf("root not upgraded: %+v", parent.Actor)
	}
}

func TestSyntheticPackageOnlyTransaction(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	for i, name := range []string{"libssl3", "openssl"} {
		p, anc := syntheticPkg(fmt.Sprint(i), name, "3.0.1", "3.0.2")
		d.Add(t0, Input{Event: p, Ancestry: anc})
	}
	parent := d.FlushAll()[0]
	if parent.ChildCount != 2 || parent.Actor.Pid != 0 || parent.Metadata["tool"] != "dpkg" ||
		parent.Metadata["packages"] != "libssl3 3.0.1 -> 3.0.2, openssl 3.0.1 -> 3.0.2" || parent.Target.PathOrKey != "dpkg" {
		t.Fatalf("parent: %+v %v", parent, parent.Metadata)
	}
}

func TestDeploymentToolAdoptsPackageTransaction(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	ansible := []limiter.Process{
		{PID: 610, Name: "dpkg"}, {PID: 600, Name: "apt-get"},
		{PID: 550, Name: "python3", Cmdline: "/usr/bin/python3 /root/.ansible/tmp/AnsiballZ_apt.py"},
		{PID: 500, Name: "sshd"}, {PID: 1, Name: "systemd"},
	}
	// Log line first, then ansible-driven file writes, then another log line.
	p1, anc := syntheticPkg("p1", "nginx", "", "1.26.1")
	d.Add(t0, Input{Event: p1, Ancestry: anc})
	f := child("f", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/nginx/nginx.conf")
	d.Add(t0.Add(time.Second), Input{Event: f, Ancestry: ansible})
	p2, _ := syntheticPkg("p2", "nginx-common", "", "1.26.1")
	d.Add(t0.Add(2*time.Second), Input{Event: p2, Ancestry: anc})
	if p1.ParentEventId != f.ParentEventId || p2.ParentEventId != f.ParentEventId || d.Open() != 1 {
		t.Fatalf("not one transaction: %q %q %q open=%d", p1.ParentEventId, f.ParentEventId, p2.ParentEventId, d.Open())
	}
	parent := d.FlushAll()[0]
	if parent.Metadata["tool"] != "ansible" || parent.Actor.Pid != 550 || parent.ChildCount != 3 {
		t.Fatalf("parent: %+v %v", parent.Actor, parent.Metadata)
	}
}

func TestAttachToOpen(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	svc := &pb.MutationEvent{Category: pb.Category_CATEGORY_SERVICE, Action: pb.Action_ACTION_RESTARTED}
	if _, ok := d.AttachToOpen(t0, svc); ok || svc.ParentEventId != "" {
		t.Fatal("attached with no open transaction")
	}
	d.Add(t0, Input{Event: child("a", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a"), Ancestry: aptAncestry(400, "sh")})
	if _, ok := d.AttachToOpen(t0.Add(2*time.Second), svc); !ok || svc.ParentEventId != "parent-1" {
		t.Fatal("service event not attached to open transaction")
	}
	// Attaching extends the window.
	if got := d.Flush(t0.Add(4 * time.Second)); len(got) != 0 {
		t.Fatal("attach did not extend the window")
	}
	late := &pb.MutationEvent{Category: pb.Category_CATEGORY_SERVICE}
	out, ok := d.AttachToOpen(t0.Add(time.Minute), late)
	if ok || len(out) != 1 || out[0].Metadata["categories"] != "config=1,service=1" {
		t.Fatalf("expired transaction: ok=%v out=%v", ok, out)
	}
}

func TestDpkgWithoutAptIsItsOwnRoot(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	ev := child("a", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a")
	d.Add(t0, Input{Event: ev, Ancestry: []limiter.Process{{PID: 5, Name: "sh"}, {PID: 4, Name: "dpkg", Cmdline: "dpkg -i x.deb"}, {PID: 1, Name: "systemd"}}})
	p := d.FlushAll()[0]
	if p.Metadata["tool"] != "dpkg" || p.Actor.Pid != 4 {
		t.Fatalf("parent: %+v", p)
	}
}

func TestMaxGroupAgeSplitsLongRuns(t *testing.T) {
	d := New(Config{NewID: seqIDs(), MaxGroupAge: 10 * time.Second})
	var parents []*pb.MutationEvent
	for i := 0; i < 25; i++ {
		out := d.Add(t0.Add(time.Duration(i)*time.Second), Input{
			Event: child("x", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a"), Ancestry: aptAncestry(400, "sh")})
		parents = append(parents, out[:len(out)-1]...)
	}
	parents = append(parents, d.FlushAll()...)
	if len(parents) != 3 || parents[0].ChildCount != 10 || parents[1].ChildCount != 10 || parents[2].ChildCount != 5 {
		t.Fatalf("got %d parents", len(parents))
	}
}

func TestSuppressedChildrenAreCounted(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	d.Add(t0, Input{Event: child("a", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a"), Ancestry: aptAncestry(400, "sh")})
	if _, ok := d.AddSuppressed(t0.Add(time.Second), aptAncestry(401, "cp"), nil, 500); !ok {
		t.Fatal("suppressed children not grouped")
	}
	if _, ok := d.AddSuppressed(t0, []limiter.Process{{PID: 1, Name: "vim"}}, nil, 5); ok {
		t.Fatal("ungrouped ancestry accepted")
	}
	if id, ok := d.ParentID(aptAncestry(999, "x")); !ok || id != "parent-1" {
		t.Fatalf("ParentID = %q %v", id, ok)
	}
	p := d.Flush(t0.Add(10 * time.Second))[0]
	if p.ChildCount != 501 || p.Metadata["children_throttled"] != "500" || p.Metadata["children_emitted"] != "1" {
		t.Fatalf("parent: count=%d md=%v", p.ChildCount, p.Metadata)
	}
}

func TestAddSuppressedReturnsExpiredParents(t *testing.T) {
	d := New(Config{NewID: seqIDs()})
	d.Add(t0, Input{Event: child("a", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a"), Ancestry: aptAncestry(400, "sh")})
	out, ok := d.AddSuppressed(t0.Add(time.Minute), aptAncestry(400, "sh"), nil, 1)
	if !ok || len(out) != 1 || out[0].EventId != "parent-1" || out[0].ChildCount != 1 {
		t.Fatalf("expired parent lost: %+v", out)
	}
	if id, _ := d.ParentID(aptAncestry(400, "sh")); id != "parent-2" {
		t.Fatalf("new transaction not started: %q", id)
	}
}

func TestDefaultIDsAreUUIDv7(t *testing.T) {
	d := New(Config{})
	ev := child("a", pb.Category_CATEGORY_CONFIG, pb.Action_ACTION_MODIFIED, "/etc/a")
	d.Add(t0, Input{Event: ev, Ancestry: aptAncestry(400, "sh")})
	if len(ev.ParentEventId) != 36 || ev.ParentEventId[14] != '7' {
		t.Fatalf("not a UUIDv7: %q", ev.ParentEventId)
	}
}
