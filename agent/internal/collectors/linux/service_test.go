package linux

import (
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

var st0 = time.Unix(1_800_000_000, 0)

type step struct {
	at     time.Duration
	active string
	sub    string
	inv    string
	result string
}

func run(t *testing.T, tr *UnitTracker, unit string, steps []step, tickAt time.Duration) []ServiceChange {
	t.Helper()
	var out []ServiceChange
	for _, s := range steps {
		out = append(out, tr.Tick(st0.Add(s.at))...)
		out = append(out, tr.Update(st0.Add(s.at), unit, UnitState{Active: s.active, Sub: s.sub, Invocation: s.inv}, s.result)...)
	}
	return append(out, tr.Tick(st0.Add(tickAt))...)
}

func seeded(unit, active, sub string) *UnitTracker {
	tr := &UnitTracker{}
	tr.Seed(map[string]UnitState{unit: {Active: active, Sub: sub}})
	return tr
}

func TestServiceStartStop(t *testing.T) {
	tr := seeded("nginx.service", "inactive", "dead")
	got := run(t, tr, "nginx.service", []step{
		{0, "activating", "start", "", ""},
		{100 * time.Millisecond, "active", "running", "inv1", ""},
	}, time.Second)
	if len(got) != 1 || got[0].Action != pb.Action_ACTION_STARTED || got[0].EventType() != "SERVICE_STARTED" ||
		got[0].Summary() != "Started nginx.service" {
		t.Fatalf("start: %+v", got)
	}

	got = run(t, tr, "nginx.service", []step{
		{10 * time.Second, "deactivating", "stop-sigterm", "", ""},
		{10*time.Second + 50*time.Millisecond, "inactive", "dead", "", ""},
	}, 11*time.Second)
	if len(got) != 0 {
		t.Fatalf("stop reported before the hold elapsed: %+v", got)
	}
	got = tr.Tick(st0.Add(12100 * time.Millisecond))
	if len(got) != 1 || got[0].Action != pb.Action_ACTION_STOPPED || got[0].From.Active != "active" ||
		got[0].Metadata()["state_after"] != "inactive/dead" {
		t.Fatalf("stop: %+v", got)
	}
}

func TestServiceRestartIsOneEvent(t *testing.T) {
	tr := seeded("nginx.service", "active", "running")
	got := run(t, tr, "nginx.service", []step{
		{0, "deactivating", "stop-sigterm", "", ""},
		{50 * time.Millisecond, "inactive", "dead", "", ""},
		{80 * time.Millisecond, "activating", "start", "", ""},
		{200 * time.Millisecond, "active", "running", "inv2", ""},
	}, 5*time.Second)
	if len(got) != 1 || got[0].Action != pb.Action_ACTION_RESTARTED || got[0].Summary() != "Restarted nginx.service" {
		t.Fatalf("restart: %+v", got)
	}
}

func TestServiceRestartDetectedByInvocationID(t *testing.T) {
	tr := &UnitTracker{}
	tr.Update(st0, "app.service", UnitState{Active: "active", Sub: "running", Invocation: "a"}, "")
	tr.Tick(st0.Add(time.Minute))
	got := tr.Update(st0.Add(2*time.Minute), "app.service", UnitState{Active: "active", Sub: "running", Invocation: "b"}, "")
	if len(got) != 1 || got[0].Action != pb.Action_ACTION_RESTARTED {
		t.Fatalf("coalesced restart: %+v", got)
	}
	// A SubState-only update without an invocation keeps the old one.
	if got := tr.Update(st0.Add(3*time.Minute), "app.service", UnitState{Active: "active", Sub: "running"}, ""); len(got) != 0 {
		t.Fatalf("spurious change: %+v", got)
	}
}

func TestServiceReload(t *testing.T) {
	tr := seeded("nginx.service", "active", "running")
	got := run(t, tr, "nginx.service", []step{
		{0, "reloading", "reload", "", ""},
		{30 * time.Millisecond, "active", "running", "", ""},
	}, time.Second)
	if len(got) != 1 || !got[0].Reloaded || got[0].EventType() != "SERVICE_RELOADED" || got[0].Summary() != "Reloaded nginx.service" {
		t.Fatalf("reload: %+v", got)
	}
}

func TestServiceCrashWithAutoRestart(t *testing.T) {
	tr := seeded("api.service", "active", "running")
	got := run(t, tr, "api.service", []step{
		{0, "activating", "auto-restart", "", "exit-code"},
		{100 * time.Millisecond, "activating", "start", "", ""},
		{300 * time.Millisecond, "active", "running", "inv9", ""},
	}, 5*time.Second)
	if len(got) != 2 {
		t.Fatalf("want crash + restart, got %+v", got)
	}
	c := got[0]
	if !c.Crashed || c.Action != pb.Action_ACTION_STOPPED || c.EventType() != "SERVICE_CRASHED" ||
		c.Summary() != "api.service crashed (exit-code); systemd is restarting it" || c.Metadata()["result"] != "exit-code" {
		t.Fatalf("crash: %+v", c)
	}
	if got[1].Action != pb.Action_ACTION_RESTARTED {
		t.Fatalf("after crash: %+v", got[1])
	}
}

func TestServiceCrashLoopReportsOnce(t *testing.T) {
	tr := seeded("api.service", "active", "running")
	var steps []step
	for i := 0; i < 5; i++ {
		base := time.Duration(i) * time.Second
		steps = append(steps, step{base, "activating", "auto-restart", "", "exit-code"},
			step{base + 100*time.Millisecond, "activating", "start", "", ""})
	}
	steps = append(steps, step{6 * time.Second, "failed", "failed", "", "start-limit-hit"})
	got := run(t, tr, "api.service", steps, 10*time.Second)
	if len(got) != 1 || !got[0].Crashed {
		t.Fatalf("crash loop must be one event, got %d: %+v", len(got), got)
	}
}

func TestServiceStartLongAfterFailureIsStart(t *testing.T) {
	tr := seeded("api.service", "active", "running")
	tr.Update(st0, "api.service", UnitState{Active: "failed", Sub: "failed"}, "signal")
	got := tr.Update(st0.Add(time.Hour), "api.service", UnitState{Active: "active", Sub: "running"}, "")
	if len(got) != 1 || got[0].Action != pb.Action_ACTION_STARTED {
		t.Fatalf("got %+v", got)
	}
}

func TestServiceUnitFilterAndRemove(t *testing.T) {
	tr := &UnitTracker{}
	if got := tr.Update(st0, "dev-sda.device", UnitState{Active: "active", Sub: "plugged"}, ""); got != nil || tr.Known() != 0 {
		t.Fatal("non-service unit tracked by default")
	}
	tr = &UnitTracker{Match: []string{"*.service", "*.timer"}}
	tr.Update(st0, "backup.timer", UnitState{Active: "active", Sub: "waiting"}, "")
	got := tr.Remove(st0.Add(time.Second), "backup.timer")
	if len(got) != 1 || got[0].Action != pb.Action_ACTION_STOPPED {
		t.Fatalf("remove: %+v", got)
	}
}

func TestDecodeUnitPath(t *testing.T) {
	cases := map[string]string{
		"/org/freedesktop/systemd1/unit/nginx_2eservice":                "nginx.service",
		"/org/freedesktop/systemd1/unit/getty_40tty1_2eservice":         "getty@tty1.service",
		"/org/freedesktop/systemd1/unit/systemd_2djournald_2eservice":   "systemd-journald.service",
		"/org/freedesktop/systemd1/unit/var_2dlib_2dstatetrack_2emount": "var-lib-statetrack.mount",
	}
	for p, want := range cases {
		if got, ok := DecodeUnitPath(p); !ok || got != want {
			t.Errorf("%s: got %q", p, got)
		}
	}
	if _, ok := DecodeUnitPath("/org/freedesktop/systemd1"); ok {
		t.Error("manager path accepted")
	}
}

func TestParseListUnits(t *testing.T) {
	out := "  nginx.service    loaded active   running A high performance web server\n" +
		"● api.service     loaded failed   failed  API\n" +
		"cron.service      loaded inactive dead    Regular background program processing daemon\n\n"
	m := ParseListUnits(out)
	if len(m) != 3 || m["nginx.service"] != (UnitState{Active: "active", Sub: "running"}) ||
		m["api.service"].Active != "failed" || m["cron.service"].Sub != "dead" {
		t.Fatalf("got %+v", m)
	}
}
