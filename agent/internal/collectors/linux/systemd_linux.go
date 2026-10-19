//go:build linux

package linux

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/godbus/dbus/v5"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// ErrNoSystemd means neither D-Bus nor systemctl is usable (not a systemd
// host, or a container without it).
var ErrNoSystemd = errors.New("systemd not available")

const (
	systemdDest     = "org.freedesktop.systemd1"
	systemdPath     = "/org/freedesktop/systemd1"
	managerIface    = "org.freedesktop.systemd1.Manager"
	unitIface       = "org.freedesktop.systemd1.Unit"
	serviceIface    = "org.freedesktop.systemd1.Service"
	propertiesIface = "org.freedesktop.DBus.Properties"
)

// SystemdOptions configures the service collector.
type SystemdOptions struct {
	// Units are glob patterns of unit names to report (default *.service).
	Units []string
	// Emit receives each reportable change.
	Emit func(context.Context, ServiceChange)
	// PollInterval is used by the systemctl fallback.
	PollInterval time.Duration
	Logger       *slog.Logger
}

// Systemd tracks unit state transitions over D-Bus (pure Go), falling back
// to polling systemctl.
type Systemd struct {
	o   SystemdOptions
	log *slog.Logger
	tr  UnitTracker
}

// NewSystemd creates the collector.
func NewSystemd(o SystemdOptions) *Systemd {
	if o.PollInterval <= 0 {
		o.PollInterval = 5 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Systemd{o: o, log: o.Logger.With("collector", "systemd"), tr: UnitTracker{Match: o.Units}}
}

// Run collects until ctx is done. It returns ErrNoSystemd immediately when
// the host has no usable systemd.
func (s *Systemd) Run(ctx context.Context) error {
	conn, private, err := connectSystemd()
	if err == nil {
		defer conn.Close()
		if err = s.runDBus(ctx, conn, private); err == nil || ctx.Err() != nil {
			return nil
		}
		s.log.Warn("systemd D-Bus collection failed; falling back to systemctl polling", "err", err)
	} else {
		s.log.Info("systemd D-Bus unavailable", "err", err)
	}
	if _, statErr := os.Stat("/run/systemd/system"); statErr != nil {
		return ErrNoSystemd
	}
	if _, lookErr := exec.LookPath("systemctl"); lookErr != nil {
		return ErrNoSystemd
	}
	return s.runPoll(ctx)
}

func connectSystemd() (conn *dbus.Conn, private bool, err error) {
	if conn, err = dbus.ConnectSystemBus(); err == nil {
		return conn, false, nil
	}
	// systemd's private socket works without dbus-daemon (root only).
	priv, perr := dbus.Dial("unix:path=/run/systemd/private")
	if perr != nil {
		return nil, false, fmt.Errorf("system bus: %v; private socket: %w", err, perr)
	}
	if aerr := priv.Auth(nil); aerr != nil {
		priv.Close()
		return nil, false, fmt.Errorf("private socket auth: %w", aerr)
	}
	return priv, true, nil
}

type listedUnit struct {
	Name, Description, Load, Active, Sub, Following string
	Path                                            dbus.ObjectPath
	JobID                                           uint32
	JobType                                         string
	JobPath                                         dbus.ObjectPath
}

func (s *Systemd) runDBus(ctx context.Context, conn *dbus.Conn, private bool) error {
	mgr := conn.Object(systemdDest, systemdPath)
	if err := mgr.CallWithContext(ctx, managerIface+".Subscribe", 0).Err; err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	if !private {
		// On the private socket systemd sends all signals to subscribers.
		if err := conn.AddMatchSignal(dbus.WithMatchInterface(propertiesIface), dbus.WithMatchMember("PropertiesChanged"),
			dbus.WithMatchPathNamespace(systemdPath+"/unit")); err != nil {
			return fmt.Errorf("add match: %w", err)
		}
		if err := conn.AddMatchSignal(dbus.WithMatchInterface(managerIface), dbus.WithMatchObjectPath(systemdPath)); err != nil {
			return fmt.Errorf("add match: %w", err)
		}
	}
	signals := make(chan *dbus.Signal, 1024)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	var units []listedUnit
	if err := mgr.CallWithContext(ctx, managerIface+".ListUnits", 0).Store(&units); err != nil {
		return fmt.Errorf("list units: %w", err)
	}
	seed := make(map[string]UnitState, len(units))
	for _, u := range units {
		seed[u.Name] = UnitState{Active: u.Active, Sub: u.Sub}
	}
	s.tr.Seed(seed)
	s.log.Info("systemd collector started", "transport", map[bool]string{true: "private", false: "dbus"}[private], "units", s.tr.Known())

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			s.emit(ctx, s.tr.Tick(time.Now()))
		case sig, ok := <-signals:
			if !ok {
				return errors.New("D-Bus connection closed")
			}
			s.signal(ctx, conn, sig)
		}
	}
}

func (s *Systemd) signal(ctx context.Context, conn *dbus.Conn, sig *dbus.Signal) {
	now := time.Now()
	switch sig.Name {
	case propertiesIface + ".PropertiesChanged":
		if len(sig.Body) < 2 {
			return
		}
		iface, _ := sig.Body[0].(string)
		changed, _ := sig.Body[1].(map[string]dbus.Variant)
		if iface != unitIface {
			return
		}
		unit, ok := DecodeUnitPath(string(sig.Path))
		if !ok || !s.tr.Wants(unit) {
			return
		}
		obj := conn.Object(systemdDest, sig.Path)
		st := UnitState{
			Active:     stringProp(ctx, obj, changed, unitIface, "ActiveState"),
			Sub:        stringProp(ctx, obj, changed, unitIface, "SubState"),
			Invocation: invocationProp(changed),
		}
		if st.Active == "" {
			return
		}
		result := ""
		if st.Active == "failed" || st.Sub == "auto-restart" {
			result = stringProp(ctx, obj, nil, serviceIface, "Result")
		}
		s.emit(ctx, s.tr.Update(now, unit, st, result))
	case managerIface + ".UnitRemoved":
		if len(sig.Body) >= 1 {
			if unit, ok := sig.Body[0].(string); ok {
				s.emit(ctx, s.tr.Remove(now, unit))
			}
		}
	case managerIface + ".Reloading":
		if len(sig.Body) >= 1 {
			if active, ok := sig.Body[0].(bool); ok && !active {
				s.emit(ctx, []ServiceChange{{Unit: "systemd", DaemonReload: true, Action: pb.Action_ACTION_RESTARTED, At: now}})
			}
		}
	}
}

func stringProp(ctx context.Context, obj dbus.BusObject, changed map[string]dbus.Variant, iface, name string) string {
	if v, ok := changed[name]; ok {
		if s, ok := v.Value().(string); ok {
			return s
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, propertiesIface+".Get", 0, iface, name).Store(&v); err != nil {
		return ""
	}
	s, _ := v.Value().(string)
	return s
}

func invocationProp(changed map[string]dbus.Variant) string {
	if v, ok := changed["InvocationID"]; ok {
		if b, ok := v.Value().([]byte); ok && len(b) > 0 {
			return hex.EncodeToString(b)
		}
	}
	return ""
}

func (s *Systemd) runPoll(ctx context.Context) error {
	list := func() (map[string]UnitState, error) {
		out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager").Output()
		if err != nil {
			return nil, err
		}
		return ParseListUnits(string(out)), nil
	}
	seed, err := list()
	if err != nil {
		return fmt.Errorf("systemctl: %w", err)
	}
	s.tr.Seed(seed)
	known := seed
	s.log.Info("systemd collector started", "transport", "systemctl", "units", s.tr.Known(), "interval", s.o.PollInterval)

	t := time.NewTicker(s.o.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		now := time.Now()
		cur, err := list()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Warn("systemctl poll failed", "err", err)
			continue
		}
		for u, st := range cur {
			s.emit(ctx, s.tr.Update(now, u, st, ""))
		}
		for u := range known {
			if _, ok := cur[u]; !ok {
				s.emit(ctx, s.tr.Remove(now, u))
			}
		}
		known = cur
		s.emit(ctx, s.tr.Tick(now))
	}
}

func (s *Systemd) emit(ctx context.Context, changes []ServiceChange) {
	for _, c := range changes {
		s.o.Emit(ctx, c)
	}
}
