package windows

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// Service Control Manager event IDs (System log, provider "Service Control
// Manager").
const (
	EventServiceState       = 7036 // entered the running/stopped state
	EventServiceStartType   = 7040 // start type changed
	EventServiceInstalled   = 7045 // a service was installed
	EventServiceCrashed     = 7034 // terminated unexpectedly
	EventServiceCrashAction = 7031 // terminated unexpectedly; recovery action follows
	SCMProvider             = "Service Control Manager"
)

// SCM service states (SERVICE_STATUS.dwCurrentState).
const (
	StateStopped         = 1
	StateStartPending    = 2
	StateStopPending     = 3
	StateRunning         = 4
	StateContinuePending = 5
	StatePausePending    = 6
	StatePaused          = 7
)

// StateName names an SCM state.
func StateName(s uint32) string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStartPending:
		return "start_pending"
	case StateStopPending:
		return "stop_pending"
	case StateRunning:
		return "running"
	case StateContinuePending:
		return "continue_pending"
	case StatePausePending:
		return "pause_pending"
	case StatePaused:
		return "paused"
	}
	return "unknown"
}

// ServiceChange is a normalized service event.
type ServiceChange struct {
	Service     string // key name (e.g. "BITS"); the display name if unknown
	DisplayName string
	Action      pb.Action
	EventType   string
	From, To    string // states or start types
	At          time.Time
	UserSID     string
	Source      string // "eventlog:7036", "scm_poll", ...
	PIDBefore   uint32
	PIDAfter    uint32

	// 7045 (installation) details.
	ImagePath, ServiceType, StartType, Account string
	// Crash details.
	CrashCount, RecoveryAction string
}

// Summary is the human-readable event summary.
func (c ServiceChange) Summary() string {
	name := c.Service
	if c.DisplayName != "" && !strings.EqualFold(c.DisplayName, c.Service) {
		name = fmt.Sprintf("%s (%s)", c.Service, c.DisplayName)
	}
	switch c.EventType {
	case "SERVICE_INSTALLED":
		return fmt.Sprintf("Service %s installed (%s, %s, runs as %s)", name, c.StartType, c.ImagePath, c.Account)
	case "SERVICE_START_TYPE_CHANGED":
		return fmt.Sprintf("Service %s start type changed: %s -> %s", name, c.From, c.To)
	case "SERVICE_CRASHED":
		return fmt.Sprintf("Service %s terminated unexpectedly", name)
	case "SERVICE_RESTARTED":
		return fmt.Sprintf("Service %s restarted", name)
	case "SERVICE_STARTED":
		return fmt.Sprintf("Service %s started", name)
	case "SERVICE_STOPPED":
		return fmt.Sprintf("Service %s stopped", name)
	}
	return fmt.Sprintf("Service %s: %s -> %s", name, c.From, c.To)
}

// Metadata is the event metadata.
func (c ServiceChange) Metadata() map[string]string {
	md := map[string]string{"event_type": c.EventType, "source": c.Source}
	set := func(k, v string) {
		if v != "" {
			md[k] = v
		}
	}
	set("display_name", c.DisplayName)
	set("state_before", c.From)
	set("state_after", c.To)
	if c.EventType == "SERVICE_START_TYPE_CHANGED" {
		delete(md, "state_before")
		delete(md, "state_after")
		set("start_type_before", c.From)
		set("start_type_after", c.To)
	}
	set("image_path", c.ImagePath)
	set("service_type", c.ServiceType)
	set("start_type", c.StartType)
	set("account", c.Account)
	set("crash_count", c.CrashCount)
	set("recovery_action", c.RecoveryAction)
	if c.PIDBefore != 0 {
		md["pid_before"] = strconv.FormatUint(uint64(c.PIDBefore), 10)
	}
	if c.PIDAfter != 0 {
		md["pid_after"] = strconv.FormatUint(uint64(c.PIDAfter), 10)
	}
	return md
}

// Target is the event target.
func (c ServiceChange) Target() *pb.TargetResource {
	return &pb.TargetResource{TargetType: "service", PathOrKey: c.Service}
}

// startTypes maps the English 7040/7045 start type texts to stable names.
var startTypes = map[string]string{
	"boot start": "boot", "system start": "system", "auto start": "auto",
	"demand start": "demand", "disabled": "disabled",
}

func startType(s string) string {
	if v, ok := startTypes[strings.ToLower(s)]; ok {
		return v
	}
	return s
}

// stateWords maps the English 7036 param2 texts to SCM states.
var stateWords = map[string]uint32{
	"running": StateRunning, "stopped": StateStopped, "paused": StatePaused,
	"start pending": StateStartPending, "stop pending": StateStopPending,
	"continue pending": StateContinuePending, "pause pending": StatePausePending,
}

// binaryServiceState decodes the 7036/7031/7034 binary payload: the UTF-16
// string "<service key name>/<state>" (the state part only for 7036).
func binaryServiceState(b []byte) (name string, state uint32) {
	s := utf16String(b)
	if s == "" {
		return "", 0
	}
	if i := strings.LastIndexByte(s, '/'); i > 0 {
		if n, err := strconv.ParseUint(s[i+1:], 10, 32); err == nil {
			return s[:i], uint32(n)
		}
	}
	return s, 0
}

// SCMRecord is a decoded System-log SCM record. Records about state are fed
// to a ServiceTracker; the others are complete changes.
type SCMRecord struct {
	// State transition (7036).
	StateUpdate bool
	Service     string
	DisplayName string
	State       uint32
	// Crash (7031/7034): the tracker suppresses the matching "stopped".
	Crash bool
	// Change is set for 7040, 7045 and crashes.
	Change *ServiceChange
}

// ParseSCM decodes an SCM event. scrub is applied to the image path (its
// arguments may carry credentials).
func ParseSCM(ev Event, scrub func(string) string) (SCMRecord, bool) {
	if ev.Provider != SCMProvider {
		return SCMRecord{}, false
	}
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	at := ev.When(time.Now())
	src := "eventlog:" + strconv.FormatUint(uint64(ev.ID), 10)
	switch ev.ID {
	case EventServiceState:
		name, state := binaryServiceState(ev.Binary)
		display := firstNonEmpty(ev.Data["param1"], ev.Param(0))
		if state == 0 {
			state = stateWords[strings.ToLower(firstNonEmpty(ev.Data["param2"], ev.Param(1)))]
		}
		if state == 0 {
			return SCMRecord{}, false
		}
		return SCMRecord{StateUpdate: true, Service: firstNonEmpty(name, display), DisplayName: display, State: state}, true
	case EventServiceStartType:
		display := ev.Data["param1"]
		c := &ServiceChange{Service: firstNonEmpty(ev.Data["param4"], display), DisplayName: display,
			Action: pb.Action_ACTION_MODIFIED, EventType: "SERVICE_START_TYPE_CHANGED",
			From: startType(ev.Data["param2"]), To: startType(ev.Data["param3"]), At: at, UserSID: ev.UserSID, Source: src}
		return SCMRecord{Change: c}, true
	case EventServiceInstalled:
		display := ev.Data["ServiceName"]
		c := &ServiceChange{Service: display, DisplayName: display, Action: pb.Action_ACTION_CREATED,
			EventType: "SERVICE_INSTALLED", At: at, UserSID: ev.UserSID, Source: src,
			ImagePath: scrub(ev.Data["ImagePath"]), ServiceType: ev.Data["ServiceType"],
			StartType: startType(ev.Data["StartType"]), Account: ev.Data["AccountName"]}
		return SCMRecord{Change: c}, true
	case EventServiceCrashed, EventServiceCrashAction:
		name, _ := binaryServiceState(ev.Binary)
		display := ev.Data["param1"]
		c := &ServiceChange{Service: firstNonEmpty(name, display), DisplayName: display,
			Action: pb.Action_ACTION_STOPPED, EventType: "SERVICE_CRASHED", From: "running", To: "stopped",
			At: at, Source: src, CrashCount: ev.Data["param2"]}
		if ev.ID == EventServiceCrashAction {
			c.RecoveryAction = ev.Data["param4"]
		}
		return SCMRecord{Crash: true, Service: c.Service, DisplayName: display, Change: c}, true
	}
	return SCMRecord{}, false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// ServiceStatus is one service in an SCM snapshot.
type ServiceStatus struct {
	Name, DisplayName string
	State             uint32
	PID               uint32
}

// DefaultServiceHold is how long a stop is held back waiting for a start
// that turns it into a restart.
const DefaultServiceHold = 3 * time.Second

// ServiceTracker turns service state observations (SCM snapshots or 7036
// records) into STARTED / STOPPED / RESTARTED changes. Not safe for
// concurrent use.
type ServiceTracker struct {
	Hold time.Duration

	known   map[string]svcState
	held    map[string]ServiceChange // pending stops
	crashed map[string]time.Time     // recent crash records
}

type svcState struct {
	display string
	state   uint32
	pid     uint32
}

const crashWindow = 30 * time.Second

func (t *ServiceTracker) init() {
	if t.known == nil {
		t.known = make(map[string]svcState)
		t.held = make(map[string]ServiceChange)
		t.crashed = make(map[string]time.Time)
	}
	if t.Hold <= 0 {
		t.Hold = DefaultServiceHold
	}
}

// Seed records the current states without reporting changes.
func (t *ServiceTracker) Seed(list []ServiceStatus) {
	t.init()
	for _, s := range list {
		t.known[strings.ToLower(s.Name)] = svcState{s.DisplayName, s.State, s.PID}
	}
}

// Known reports how many services are tracked.
func (t *ServiceTracker) Known() int { return len(t.known) }

// Snapshot applies a full SCM snapshot. Services that disappeared are
// forgotten (deletions are reported by the registry collector).
func (t *ServiceTracker) Snapshot(now time.Time, list []ServiceStatus, source string) []ServiceChange {
	t.init()
	present := make(map[string]bool, len(list))
	var out []ServiceChange
	for _, s := range list {
		present[strings.ToLower(s.Name)] = true
		out = append(out, t.observe(now, s, source)...)
	}
	for k := range t.known {
		if !present[k] {
			delete(t.known, k)
		}
	}
	return append(out, t.Tick(now)...)
}

// Observe applies one state observation (a 7036 record).
func (t *ServiceTracker) Observe(now time.Time, s ServiceStatus, source string) []ServiceChange {
	t.init()
	return append(t.observe(now, s, source), t.Tick(now)...)
}

// NoteCrash records a crash so the following "stopped" observation is not
// reported a second time.
func (t *ServiceTracker) NoteCrash(now time.Time, service string) {
	t.init()
	k := strings.ToLower(service)
	t.crashed[k] = now
	delete(t.held, k)
}

func (t *ServiceTracker) observe(now time.Time, s ServiceStatus, source string) []ServiceChange {
	k := strings.ToLower(s.Name)
	prev, seen := t.known[k]
	display := firstNonEmpty(s.DisplayName, prev.display)
	cur := svcState{display, s.State, s.PID}
	if !seen {
		// New service (installation is reported by 7045 / the registry).
		t.known[k] = cur
		return nil
	}
	settled := func(st uint32) bool { return st == StateRunning || st == StateStopped || st == StatePaused }
	if !settled(s.State) {
		return nil // keep the last settled state
	}
	t.known[k] = cur
	base := ServiceChange{Service: s.Name, DisplayName: display, At: now, Source: source}
	var out []ServiceChange
	switch {
	case prev.state == StateRunning && s.State == StateRunning:
		if prev.pid != 0 && s.PID != 0 && prev.pid != s.PID {
			c := base
			c.Action, c.EventType, c.From, c.To = pb.Action_ACTION_RESTARTED, "SERVICE_RESTARTED", "running", "running"
			c.PIDBefore, c.PIDAfter = prev.pid, s.PID
			out = append(out, c)
		}
	case prev.state != StateRunning && s.State == StateRunning:
		if held, ok := t.held[k]; ok {
			delete(t.held, k)
			c := base
			c.Action, c.EventType, c.From, c.To = pb.Action_ACTION_RESTARTED, "SERVICE_RESTARTED", "running", "running"
			c.PIDBefore, c.PIDAfter = held.PIDBefore, s.PID
			out = append(out, c)
			break
		}
		c := base
		c.Action, c.EventType, c.From, c.To = pb.Action_ACTION_STARTED, "SERVICE_STARTED", StateName(prev.state), "running"
		c.PIDAfter = s.PID
		if at, ok := t.crashed[k]; ok && now.Sub(at) <= crashWindow {
			c.Action, c.EventType = pb.Action_ACTION_RESTARTED, "SERVICE_RESTARTED"
			delete(t.crashed, k)
		}
		out = append(out, c)
	case prev.state == StateRunning && s.State != StateRunning:
		if at, ok := t.crashed[k]; ok && now.Sub(at) <= crashWindow {
			break // already reported as SERVICE_CRASHED
		}
		c := base
		c.Action, c.EventType, c.From, c.To = pb.Action_ACTION_STOPPED, "SERVICE_STOPPED", "running", StateName(s.State)
		c.PIDBefore = prev.pid
		t.held[k] = c
	}
	return out
}

// Tick releases held stops older than Hold.
func (t *ServiceTracker) Tick(now time.Time) []ServiceChange {
	t.init()
	var out []ServiceChange
	for k, c := range t.held {
		if now.Sub(c.At) >= t.Hold {
			out = append(out, c)
			delete(t.held, k)
		}
	}
	for k, at := range t.crashed {
		if now.Sub(at) > crashWindow {
			delete(t.crashed, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}
