//go:build windows

package windows

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// Event-log XPath queries (EvtSubscribe).
const (
	SCMQuery   = `*[System[Provider[@Name='Service Control Manager'] and (EventID=7036 or EventID=7040 or EventID=7045 or EventID=7031 or EventID=7034)]]`
	MSIQuery   = `*[System[Provider[@Name='MsiInstaller'] and (EventID=1033 or EventID=1034)]]`
	AuditQuery = `*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4657 or EventID=4663)]]`
)

// MonitorOptions configures the service/package/audit monitor.
type MonitorOptions struct {
	// Queries; empty disables that subscription.
	SCMQuery   string
	MSIQuery   string
	AuditQuery string
	// CCS is the CurrentControlSet number (HKLM\SYSTEM\Select\Current).
	CCS   int
	Notes *Notes
	// PollSCM polls the SCM in addition to (or instead of) the System log,
	// for hosts that do not log 7036. PollInterval must be >= 1s.
	PollSCM      bool
	PollInterval time.Duration
	Scrub        func(string) string
	Resolve      func(string) (Account, bool)
	Emit         func(context.Context, engine.Event) error
	Logger       *slog.Logger
}

// Monitor runs the service (SCM), MSI and security-audit collectors. All
// tracker/pairer state is owned by its single dispatch goroutine, so the
// ServiceTracker and MsiPairer stay unsynchronised.
type Monitor struct {
	o       MonitorOptions
	log     *slog.Logger
	tracker ServiceTracker
	msi     MsiPairer
	events  chan Event
}

// NewMonitor creates the monitor; Run starts it.
func NewMonitor(o MonitorOptions) *Monitor {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Monitor{o: o, log: o.Logger.With("collector", "monitor"), events: make(chan Event, 64)}
}

// Run blocks until ctx is done.
func (m *Monitor) Run(ctx context.Context) error {
	for _, s := range []Subscriber{
		{Channel: "System", Query: m.o.SCMQuery, onEvent: m.onEvent(ctx)},
		{Channel: "Application", Query: m.o.MSIQuery, onEvent: m.onEvent(ctx)},
		{Channel: "Security", Query: m.o.AuditQuery, onEvent: m.onEvent(ctx)},
	} {
		if s.Query != "" {
			go s.run(ctx, m.log)
		}
	}

	var pollC <-chan time.Time
	if m.o.PollSCM {
		iv := m.o.PollInterval
		if iv <= 0 {
			iv = 5 * time.Second
		}
		t := time.NewTicker(iv)
		defer t.Stop()
		pollC = t.C
		m.pollSCM(ctx) // initial snapshot seeds state
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-m.events:
			m.dispatch(ctx, ev)
		case now := <-tick.C:
			if m.o.Notes != nil {
				m.o.Notes.Sweep(now)
			}
			for _, c := range m.tracker.Tick(now) {
				m.emitSCM(ctx, c)
			}
			for _, c := range m.msi.Tick(now) {
				m.emitMSI(ctx, c)
			}
		case <-pollC:
			m.pollSCM(ctx)
		}
	}
}

func (m *Monitor) onEvent(ctx context.Context) func(Event) {
	return func(ev Event) {
		select {
		case m.events <- ev:
		case <-ctx.Done():
		}
	}
}

func (m *Monitor) dispatch(ctx context.Context, ev Event) {
	switch ev.Provider {
	case SCMProvider:
		m.handleSCM(ctx, ev)
	case MsiProvider:
		m.handleMSI(ctx, ev)
	case SecurityProvider:
		m.handleAudit(ev)
	}
}

func (m *Monitor) handleSCM(ctx context.Context, ev Event) {
	rec, ok := ParseSCM(ev, m.o.Scrub)
	if !ok {
		return
	}
	if rec.Crash {
		m.tracker.NoteCrash(rec.Change.At, rec.Service)
		m.emitSCM(ctx, *rec.Change)
		return
	}
	if rec.Change != nil {
		m.emitSCM(ctx, *rec.Change)
		return
	}
	if rec.StateUpdate {
		changes := m.tracker.Observe(ev.When(time.Now()), ServiceStatus{
			Name: rec.Service, DisplayName: rec.DisplayName, State: rec.State,
		}, "eventlog:"+eventID(ev))
		for _, c := range changes {
			m.emitSCM(ctx, c)
		}
	}
}

func (m *Monitor) handleMSI(ctx context.Context, ev Event) {
	c, ok := ParseMsi(ev)
	if !ok {
		return
	}
	for _, ch := range m.msi.Add(ev.When(time.Now()), c) {
		m.emitMSI(ctx, ch)
	}
}

func (m *Monitor) handleAudit(ev Event) {
	n, ok := ParseAudit(ev, m.o.CCS)
	if !ok || m.o.Notes == nil {
		return
	}
	m.o.Notes.Add(n)
}

func (m *Monitor) emitSCM(ctx context.Context, c ServiceChange) {
	if err := m.o.Emit(ctx, engine.Event{
		Category:  pb.Category_CATEGORY_SERVICE,
		Action:    c.Action,
		Summary:   c.Summary(),
		Target:    c.Target(),
		Actor:     ActorFromSID(c.UserSID, m.o.Resolve, "", 0),
		Metadata:  c.Metadata(),
		Correlate: c.EventType != "SERVICE_CRASHED",
		Time:      c.At,
	}); err != nil {
		m.log.Error("service event", "service", c.Service, "err", err)
	}
}

func (m *Monitor) emitMSI(ctx context.Context, c MsiChange) {
	if err := m.o.Emit(ctx, engine.Event{
		Category: pb.Category_CATEGORY_PACKAGE,
		Action:   c.Action(),
		Summary:  c.Summary(),
		Target:   c.Target(),
		Actor:    ActorFromSID(c.UserSID, m.o.Resolve, "msiexec.exe", c.PID),
		// Synthetic ancestry: the debouncer joins the MSI event to the
		// msiexec transaction (group key "pkg").
		Ancestry: []limiter.Process{{Name: "msiexec"}},
		Metadata: c.Metadata(),
		Time:     c.At,
	}); err != nil {
		m.log.Error("msi event", "product", c.Product, "err", err)
	}
}

func (m *Monitor) pollSCM(ctx context.Context) {
	list, err := ListServices()
	if err != nil {
		m.log.Warn("scm snapshot", "err", err)
		return
	}
	statuses := make([]ServiceStatus, 0, len(list))
	for _, s := range list {
		statuses = append(statuses, s)
	}
	for _, c := range m.tracker.Snapshot(time.Now(), statuses, "scm_poll") {
		m.emitSCM(ctx, c)
	}
}

func eventID(ev Event) string {
	if ev.ID != 0 {
		return strconv.FormatUint(uint64(ev.ID), 10)
	}
	return "?"
}
