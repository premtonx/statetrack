package windows

import (
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

func TestParseSCMState7036(t *testing.T) {
	// Binary is "W32TimeSrv/4" (service name / state Running).
	ev := parseXML(t, "Service Control Manager", 7036, "",
		`<Data Name="param1">Windows Time</Data><Data Name="param2">running</Data>`+
			`<Binary>570033003200540069006D0065005300720076002F0034000000</Binary>`)
	rec, ok := ParseSCM(ev, nil)
	if !ok {
		t.Fatal("ParseSCM returned not-ok")
	}
	if !rec.StateUpdate || rec.Service != "W32TimeSrv" || rec.DisplayName != "Windows Time" || rec.State != StateRunning {
		t.Fatalf("rec = %+v", rec)
	}
}

func TestParseSCMStateFromParamText(t *testing.T) {
	// No binary payload: fall back to the param2 text.
	ev := parseXML(t, "Service Control Manager", 7036, "",
		`<Data Name="param1">Spooler</Data><Data Name="param2">stopped</Data>`)
	rec, ok := ParseSCM(ev, nil)
	if !ok || rec.State != StateStopped || rec.Service != "Spooler" {
		t.Fatalf("rec = %+v, ok=%v", rec, ok)
	}
}

func TestParseSCMInstalled7045(t *testing.T) {
	ev := parseXML(t, "Service Control Manager", 7045, "S-1-5-21-100",
		`<Data Name="ServiceName">FakeSvc</Data>`+
			`<Data Name="ImagePath">C:\svc\fake.exe -u alice -p secret</Data>`+
			`<Data Name="ServiceType">user mode service</Data>`+
			`<Data Name="StartType">auto start</Data>`+
			`<Data Name="AccountName">LocalSystem</Data>`)
	rec, ok := ParseSCM(ev, func(s string) string {
		// Scrubber redacts the password token.
		return "C:\\svc\\fake.exe -u alice -p [REDACTED]"
	})
	if !ok || rec.Change == nil {
		t.Fatalf("rec = %+v", rec)
	}
	c := rec.Change
	if c.Action != pb.Action_ACTION_CREATED || c.EventType != "SERVICE_INSTALLED" || c.Service != "FakeSvc" {
		t.Fatalf("change = %+v", c)
	}
	if c.ImagePath != "C:\\svc\\fake.exe -u alice -p [REDACTED]" {
		t.Fatalf("ImagePath not scrubbed: %q", c.ImagePath)
	}
	if c.StartType != "auto" || c.Account != "LocalSystem" || c.UserSID != "S-1-5-21-100" {
		t.Fatalf("change = %+v", c)
	}
}

func TestParseSCMStartType7040(t *testing.T) {
	ev := parseXML(t, "Service Control Manager", 7040, "",
		`<Data Name="param1">W32Time</Data><Data Name="param2">auto start</Data><Data Name="param3">disabled</Data><Data Name="param4">w32time</Data>`)
	rec, ok := ParseSCM(ev, nil)
	if !ok || rec.Change == nil {
		t.Fatalf("rec = %+v", rec)
	}
	c := rec.Change
	if c.Action != pb.Action_ACTION_MODIFIED || c.EventType != "SERVICE_START_TYPE_CHANGED" || c.From != "auto" || c.To != "disabled" {
		t.Fatalf("change = %+v", c)
	}
}

func TestParseSCMCrash7034(t *testing.T) {
	ev := parseXML(t, "Service Control Manager", 7034, "",
		`<Data Name="param1">BITS</Data><Data Name="param2">1</Data>`+
			`<Binary>42004900540053002F0031000000</Binary>`)
	rec, ok := ParseSCM(ev, nil)
	if !ok || !rec.Crash || rec.Change == nil {
		t.Fatalf("rec = %+v", rec)
	}
	c := rec.Change
	if c.EventType != "SERVICE_CRASHED" || c.Action != pb.Action_ACTION_STOPPED {
		t.Fatalf("change = %+v", c)
	}
}

func TestServiceTrackerStartStop(t *testing.T) {
	var tr ServiceTracker
	now := time.Now()
	tr.Seed([]ServiceStatus{{Name: "svc", State: StateStopped}})

	if got := tr.Observe(now, ServiceStatus{Name: "svc", State: StateRunning, PID: 7}, "x"); len(got) != 1 {
		t.Fatalf("start: got %d changes, want 1", len(got))
	} else if got[0].Action != pb.Action_ACTION_STARTED || got[0].PIDAfter != 7 {
		t.Fatalf("start change = %+v", got[0])
	}

	// A stop is held until Tick releases it.
	if got := tr.Observe(now.Add(time.Second), ServiceStatus{Name: "svc", State: StateStopped}, "x"); len(got) != 0 {
		t.Fatalf("stop should be held, got %d", len(got))
	}
	if got := tr.Tick(now.Add(time.Second + DefaultServiceHold + time.Second)); len(got) != 1 {
		t.Fatalf("tick: got %d changes, want 1", len(got))
	} else if got[0].Action != pb.Action_ACTION_STOPPED {
		t.Fatalf("stop change = %+v", got[0])
	}
}

func TestServiceTrackerRestart(t *testing.T) {
	var tr ServiceTracker
	now := time.Now()
	tr.Seed([]ServiceStatus{{Name: "svc", State: StateRunning, PID: 7}})

	tr.Observe(now.Add(time.Second), ServiceStatus{Name: "svc", State: StateStopped}, "x")
	got := tr.Observe(now.Add(2*time.Second), ServiceStatus{Name: "svc", State: StateRunning, PID: 8}, "x")
	if len(got) != 1 {
		t.Fatalf("restart: got %d changes, want 1", len(got))
	}
	if got[0].Action != pb.Action_ACTION_RESTARTED || got[0].PIDBefore != 7 || got[0].PIDAfter != 8 {
		t.Fatalf("restart change = %+v", got[0])
	}
}

func TestServiceTrackerCrashSuppressesStop(t *testing.T) {
	var tr ServiceTracker
	now := time.Now()
	tr.Seed([]ServiceStatus{{Name: "svc", State: StateRunning, PID: 7}})

	tr.NoteCrash(now, "svc")
	got := tr.Observe(now.Add(time.Second), ServiceStatus{Name: "svc", State: StateStopped}, "x")
	if len(got) != 0 {
		t.Fatalf("crash stop should be suppressed, got %+v", got)
	}
}

func TestStateName(t *testing.T) {
	cases := map[uint32]string{StateStopped: "stopped", StateRunning: "running", StatePaused: "paused", 99: "unknown"}
	for st, want := range cases {
		if got := StateName(st); got != want {
			t.Errorf("StateName(%d) = %q, want %q", st, got, want)
		}
	}
}
