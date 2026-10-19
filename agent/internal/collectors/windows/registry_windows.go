//go:build windows

package windows

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
)

// DefaultRegistrySettle coalesces the burst of changes an installer writes
// into a single re-scan.
const DefaultRegistrySettle = 500 * time.Millisecond

// notifyFilter watches name, value and attribute changes under a key.
const notifyFilter = windows.REG_NOTIFY_CHANGE_NAME | windows.REG_NOTIFY_CHANGE_LAST_SET |
	windows.REG_NOTIFY_CHANGE_ATTRIBUTES | windows.REG_NOTIFY_CHANGE_SECURITY

// RegistryOptions configures the registry collector.
type RegistryOptions struct {
	// Keys are watched recursively (HKLM\... or HKCU\...); the classifier's
	// blacklist applies to keys too.
	Keys       []string
	Classifier *limiter.Classifier
	Attrib     Attributor
	// Handle receives rendered-key changes (engine.HandleDoc).
	Handle func(context.Context, engine.DocEvent) error
	// Seed records a key's baseline without an event (engine.SeedDoc).
	Seed func(ctx context.Context, key string, content []byte, modTime time.Time) error
	// Known lists the shadow-indexed keys under a root (store.PathsUnder).
	Known  func(ctx context.Context, key string) []string
	Settle time.Duration
	Logger *slog.Logger
}

// Registry is the registry collector: it renders each watched key as a text
// document and diffs it through the engine, re-scanning on
// RegNotifyChangeKeyValue signals.
type Registry struct {
	o      RegistryOptions
	log    *slog.Logger
	roots  []regRoot
	dirty  chan regRoot
	mu     sync.Mutex
	stamps map[string]keyStamp
}

type regRoot struct {
	hive registry.Key
	sub  string
	path string
}

type keyStamp struct {
	mod           time.Time
	subkeys, vals uint32
}

func (s keyStamp) equal(o keyStamp) bool {
	return s.subkeys == o.subkeys && s.vals == o.vals && s.mod.Equal(o.mod)
}

// NewRegistry creates the collector; Run starts it.
func NewRegistry(o RegistryOptions) *Registry {
	if o.Settle <= 0 {
		o.Settle = DefaultRegistrySettle
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	r := &Registry{o: o, log: o.Logger.With("collector", "registry"), dirty: make(chan regRoot, 1),
		stamps: make(map[string]keyStamp)}
	for _, k := range o.Keys {
		hive, sub, ok := splitHive(k)
		if !ok {
			r.log.Warn("ignoring invalid registry key", "key", k)
			continue
		}
		r.roots = append(r.roots, regRoot{hive: hive, sub: sub, path: k})
	}
	return r
}

// splitHive maps a HKLM\... or HKCU\... key to its hive and sub-path.
func splitHive(key string) (registry.Key, string, bool) {
	up := strings.ToUpper(key)
	switch {
	case strings.HasPrefix(up, `HKLM\`):
		return registry.LOCAL_MACHINE, key[len(`HKLM\`):], true
	case strings.HasPrefix(up, `HKCU\`):
		return registry.CURRENT_USER, key[len(`HKCU\`):], true
	}
	return 0, "", false
}

// CurrentControlSet reads HKLM\SYSTEM\Select\Current, used to map
// ControlSet00N paths in audit records to CurrentControlSet.
func CurrentControlSet() (int, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\Select`, registry.READ)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("Current")
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// Run baselines and then watches until ctx is done.
func (r *Registry) Run(ctx context.Context) error {
	r.baseline(ctx)
	r.log.Info("registry collector started", "keys", r.o.Keys)
	for _, root := range r.roots {
		go r.watch(ctx, root)
	}

	tick := time.NewTicker(r.o.Settle / 3)
	defer tick.Stop()
	// A slow full re-scan catches notifications missed while re-arming.
	full := time.NewTicker(30 * time.Second)
	defer full.Stop()

	pending := map[regRoot]time.Time{}
	for {
		select {
		case <-ctx.Done():
			for root := range pending {
				r.rescanRoot(context.WithoutCancel(ctx), root, false)
			}
			return nil
		case root := <-r.dirty:
			pending[root] = time.Now()
		case <-tick.C:
			now := time.Now()
			for root, at := range pending {
				if now.Sub(at) >= r.o.Settle {
					delete(pending, root)
					r.rescanRoot(ctx, root, false)
				}
			}
		case <-full.C:
			for _, root := range r.roots {
				r.rescanRoot(ctx, root, false)
			}
		}
	}
}

// Rescan re-observes every watched key now (used by tests and diagnostics).
func (r *Registry) Rescan(ctx context.Context) {
	for _, root := range r.roots {
		r.rescanRoot(ctx, root, false)
	}
}

// baseline seeds keys on first run and reconciles on later runs (so changes
// made while the agent was stopped are reported).
func (r *Registry) baseline(ctx context.Context) {
	for _, root := range r.roots {
		seed := true
		if r.o.Known != nil && len(r.o.Known(ctx, root.path)) > 0 {
			seed = false
		}
		r.rescanRoot(ctx, root, seed)
	}
}

// watch blocks on RegNotifyChangeKeyValue and signals a re-scan.
func (r *Registry) watch(ctx context.Context, root regRoot) {
	for {
		if ctx.Err() != nil {
			return
		}
		k, err := registry.OpenKey(root.hive, root.sub, registry.READ)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		// Blocks until a change (returns nil) or the key is deleted
		// (returns ERROR_KEY_DELETED). Either way, re-scan.
		_ = windows.RegNotifyChangeKeyValue(windows.Handle(uintptr(k)), true, notifyFilter, 0, false)
		k.Close()
		select {
		case r.dirty <- root:
		default:
		}
	}
}

func (r *Registry) rescanRoot(ctx context.Context, root regRoot, seed bool) {
	present := make(map[string]bool)
	r.walkKey(ctx, root.hive, root.sub, root.path, seed, present)
	if seed || r.o.Known == nil {
		return
	}
	for _, k := range r.o.Known(ctx, root.path) {
		if present[k] {
			continue
		}
		hive, sub, ok := splitHive(k)
		if !ok {
			continue
		}
		if _, err := registry.OpenKey(hive, sub, registry.READ); err == nil {
			continue // still present; transient walk miss
		}
		actor, method := r.o.Attrib.Attribute(k, time.Now())
		if err := r.o.Handle(ctx, engine.DocEvent{Path: k, TargetType: "registry", Actor: actor, Attribution: method}); err != nil {
			r.log.Error("registry delete", "key", k, "err", err)
		}
	}
}

func (r *Registry) walkKey(ctx context.Context, hive registry.Key, sub, path string, seed bool, present map[string]bool) {
	k, err := registry.OpenKey(hive, sub, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	present[path] = true

	info, err := k.Stat()
	if err != nil {
		return
	}
	stamp := keyStamp{mod: info.ModTime(), subkeys: info.SubKeyCount, vals: info.ValueCount}

	r.mu.Lock()
	prev, seen := r.stamps[path]
	changed := !seen || !stamp.equal(prev)
	r.stamps[path] = stamp
	r.mu.Unlock()

	if changed && !r.o.Classifier.Blacklisted(path) {
		if content, err := renderKey(k, path); err == nil {
			switch {
			case seed && r.o.Seed != nil:
				if err := r.o.Seed(ctx, path, content, stamp.mod); err != nil {
					r.log.Error("registry seed", "key", path, "err", err)
				}
			case !seed && r.o.Handle != nil:
				actor, method := r.o.Attrib.Attribute(path, time.Now())
				if err := r.o.Handle(ctx, engine.DocEvent{Path: path, TargetType: "registry", Content: content, ModTime: stamp.mod, Actor: actor, Attribution: method}); err != nil {
					r.log.Error("registry change", "key", path, "err", err)
				}
			}
		}
	}

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, n := range names {
		child := path + `\` + n
		if r.o.Classifier.Blacklisted(child) {
			continue
		}
		r.walkKey(ctx, hive, sub+`\`+n, child, seed, present)
	}
}

// renderKey reads a key's values and renders them as a stable text document.
func renderKey(k registry.Key, path string) ([]byte, error) {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	vals := make([]RegValue, 0, len(names))
	for _, name := range names {
		v, err := readValue(k, name)
		if err != nil {
			continue // raced with a delete
		}
		vals = append(vals, v)
	}
	return RenderKey(path, vals), nil
}

// readValue reads a value's raw data and type.
func readValue(k registry.Key, name string) (RegValue, error) {
	n, typ, err := k.GetValue(name, nil)
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return RegValue{}, err
	}
	if n == 0 {
		return RegValue{Name: name, Type: typ}, nil
	}
	buf := make([]byte, n)
	got, typ2, err := k.GetValue(name, buf)
	if err != nil {
		return RegValue{}, err
	}
	return RegValue{Name: name, Type: typ2, Data: buf[:got]}, nil
}
