package linux

import (
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// DefaultStopHold delays reporting a stop so a stop quickly followed by a
// start (systemctl restart) is reported once, as RESTARTED.
const DefaultStopHold = 2 * time.Second

// crashRestartWindow bounds how long after a crash a start counts as the
// service being restarted.
const crashRestartWindow = time.Minute

// UnitState is a systemd unit's ActiveState/SubState pair.
type UnitState struct {
	Active string // active, reloading, inactive, failed, activating, deactivating
	Sub    string // running, exited, dead, auto-restart, ...
	// Invocation is the unit's InvocationID (new on every start); empty
	// when unknown (systemctl fallback).
	Invocation string
}

// ServiceChange is a reportable unit transition.
type ServiceChange struct {
	Unit     string
	Action   pb.Action
	Crashed  bool
	Reloaded bool
	// DaemonReload marks `systemctl daemon-reload` (unit files re-read).
	DaemonReload bool
	From, To     UnitState
	At           time.Time
	// Result is systemd's failure reason (exit-code, signal, core-dump, ...)
	// when known.
	Result string
}

// EventType returns the metadata event_type for the change.
func (c ServiceChange) EventType() string {
	switch {
	case c.DaemonReload:
		return "SYSTEMD_DAEMON_RELOAD"
	case c.Crashed:
		return "SERVICE_CRASHED"
	case c.Reloaded:
		return "SERVICE_RELOADED"
	}
	return "SERVICE_" + strings.TrimPrefix(c.Action.String(), "ACTION_")
}

// Summary renders a one-line description.
func (c ServiceChange) Summary() string {
	switch {
	case c.DaemonReload:
		return "systemd reloaded its unit files (daemon-reload)"
	case c.Crashed:
		s := c.Unit + " crashed"
		if c.Result != "" && c.Result != "success" {
			s += " (" + c.Result + ")"
		}
		if c.To.Sub == "auto-restart" {
			s += "; systemd is restarting it"
		}
		return s
	case c.Reloaded:
		return "Reloaded " + c.Unit
	}
	verb := map[pb.Action]string{pb.Action_ACTION_STARTED: "Started", pb.Action_ACTION_STOPPED: "Stopped",
		pb.Action_ACTION_RESTARTED: "Restarted"}[c.Action]
	return verb + " " + c.Unit
}

// Metadata returns event metadata for the change.
func (c ServiceChange) Metadata() map[string]string {
	md := map[string]string{
		"event_type":   c.EventType(),
		"unit":         c.Unit,
		"state_before": c.From.Active + "/" + c.From.Sub,
		"state_after":  c.To.Active + "/" + c.To.Sub,
	}
	if c.Result != "" {
		md["result"] = c.Result
	}
	return md
}

// UnitTracker turns a stream of unit state observations into service
// events. It is not safe for concurrent use.
type UnitTracker struct {
	Hold time.Duration
	// Match selects the units to report (glob patterns on the unit name);
	// empty means all .service units.
	Match []string

	states  map[string]UnitState
	stopped map[string]ServiceChange // held stops
	crashed map[string]time.Time     // crash reported; a prompt start is a restart
}

func (t *UnitTracker) init() {
	if t.states == nil {
		t.states = make(map[string]UnitState)
		t.stopped = make(map[string]ServiceChange)
		t.crashed = make(map[string]time.Time)
	}
	if t.Hold <= 0 {
		t.Hold = DefaultStopHold
	}
}

// Wants reports whether unit is selected.
func (t *UnitTracker) Wants(unit string) bool {
	if len(t.Match) == 0 {
		return strings.HasSuffix(unit, ".service")
	}
	for _, m := range t.Match {
		if ok, _ := path.Match(m, unit); ok {
			return true
		}
	}
	return false
}

// Seed records initial states without reporting them.
func (t *UnitTracker) Seed(states map[string]UnitState) {
	t.init()
	for u, s := range states {
		if t.Wants(u) {
			t.states[u] = s
		}
	}
}

// Known returns the number of tracked units.
func (t *UnitTracker) Known() int { t.init(); return len(t.states) }

// Update records a new observation of unit and returns changes to report.
// result is the unit's Result property, if known.
func (t *UnitTracker) Update(now time.Time, unit string, s UnitState, result string) []ServiceChange {
	t.init()
	if !t.Wants(unit) {
		return nil
	}
	prev, known := t.states[unit]
	if !known {
		prev = UnitState{Active: "inactive", Sub: "dead"}
	}
	if s.Invocation == "" && prev.Active == s.Active {
		s.Invocation = prev.Invocation
	}
	t.states[unit] = s
	if prev == s {
		return nil
	}
	var out []ServiceChange
	up := func(a string) bool { return a == "active" || a == "reloading" }
	_, crashed := t.crashed[unit]

	switch {
	case s.Active == "failed" || (s.Active == "activating" && s.Sub == "auto-restart"):
		if crashed && prev.Active != "active" {
			// Already reported (failed -> auto-restart, or a unit failing
			// repeatedly before it ever becomes active).
			break
		}
		delete(t.stopped, unit)
		t.crashed[unit] = now
		out = append(out, ServiceChange{Unit: unit, Action: pb.Action_ACTION_STOPPED, Crashed: true,
			From: prev, To: s, At: now, Result: result})

	case s.Active == "active" && prev.Active == "reloading":
		out = append(out, ServiceChange{Unit: unit, Action: pb.Action_ACTION_RESTARTED, Reloaded: true,
			From: prev, To: s, At: now})

	case s.Active == "active" && prev.Active == "active" && prev.Invocation != "" && s.Invocation != prev.Invocation:
		// A restart whose intermediate states were coalesced away.
		out = append(out, ServiceChange{Unit: unit, Action: pb.Action_ACTION_RESTARTED, From: prev, To: s, At: now})

	case s.Active == "active" && !up(prev.Active):
		action := pb.Action_ACTION_STARTED
		from := prev
		if held, ok := t.stopped[unit]; ok {
			action, from = pb.Action_ACTION_RESTARTED, held.From
			delete(t.stopped, unit)
		} else if at, ok := t.crashed[unit]; ok && now.Sub(at) <= crashRestartWindow {
			action = pb.Action_ACTION_RESTARTED
		}
		delete(t.crashed, unit)
		out = append(out, ServiceChange{Unit: unit, Action: action, From: from, To: s, At: now})

	case s.Active == "inactive" && prev.Active != "inactive" && prev.Active != "failed":
		if _, held := t.stopped[unit]; !held && !crashed {
			from := prev
			if prev.Active == "deactivating" {
				from = UnitState{Active: "active", Sub: "running"}
			}
			t.stopped[unit] = ServiceChange{Unit: unit, Action: pb.Action_ACTION_STOPPED, From: from, To: s, At: now}
		}
		delete(t.crashed, unit)
	}
	return out
}

// Remove forgets a unit (unloaded); a running unit that disappears is
// reported as stopped.
func (t *UnitTracker) Remove(now time.Time, unit string) []ServiceChange {
	t.init()
	prev, ok := t.states[unit]
	if !ok {
		return nil
	}
	delete(t.states, unit)
	delete(t.crashed, unit)
	if held, ok := t.stopped[unit]; ok {
		delete(t.stopped, unit)
		return []ServiceChange{held}
	}
	if prev.Active == "active" || prev.Active == "reloading" {
		return []ServiceChange{{Unit: unit, Action: pb.Action_ACTION_STOPPED, From: prev,
			To: UnitState{Active: "inactive", Sub: "dead"}, At: now}}
	}
	return nil
}

// Tick releases held stops older than Hold.
func (t *UnitTracker) Tick(now time.Time) []ServiceChange {
	t.init()
	var out []ServiceChange
	for u, c := range t.stopped {
		if now.Sub(c.At) >= t.Hold {
			out = append(out, c)
			delete(t.stopped, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Unit < out[j].Unit })
	return out
}

// DecodeUnitPath turns a systemd D-Bus object path back into a unit name:
// /org/freedesktop/systemd1/unit/nginx_2eservice -> nginx.service.
func DecodeUnitPath(p string) (string, bool) {
	const prefix = "/org/freedesktop/systemd1/unit/"
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	enc := p[len(prefix):]
	var b strings.Builder
	for i := 0; i < len(enc); i++ {
		if enc[i] == '_' && i+2 < len(enc) {
			if v, err := strconv.ParseUint(enc[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(enc[i])
	}
	return b.String(), b.Len() > 0
}

// ParseListUnits parses `systemctl list-units --all --plain --no-legend
// --no-pager` output (UNIT LOAD ACTIVE SUB DESCRIPTION).
func ParseListUnits(out string) map[string]UnitState {
	m := make(map[string]UnitState)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimLeft(line, "●* "))
		if len(f) < 4 {
			continue
		}
		m[f[0]] = UnitState{Active: f[2], Sub: f[3]}
	}
	return m
}
