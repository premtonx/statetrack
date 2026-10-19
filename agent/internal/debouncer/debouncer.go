// Package debouncer groups mutations caused by one package-management or
// deployment run (apt, dpkg, yum, dnf, msiexec, ansible, ...) into a single
// synthesized Level 2 parent event.
//
// Grouping is causal: events whose process ancestry shares the same
// outermost tool process belong to the same transaction, which stays open
// while events keep arriving within a sliding window (3 s by default).
// Children are released immediately, already linked to the parent ID, so
// memory stays bounded however long the run is; the parent, carrying
// child_count and an aggregate summary, is released when the window closes.
//
// Package managers serialise on a system-wide lock (dpkg, rpm, apk), so all
// package-manager activity shares one transaction regardless of root PID.
// This lets log-derived package events (which carry only a synthetic,
// PID-less ancestry such as [{Name: "dpkg"}]) join the transaction formed by
// the tool's file mutations; the transaction adopts the real root process
// once it is seen.
package debouncer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/eventid"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

const (
	DefaultWindow      = 3 * time.Second
	DefaultMaxGroupAge = 15 * time.Minute
	// maxListedPackages bounds the package list kept in parent metadata.
	maxListedPackages = 50
)

// Config configures a Debouncer.
type Config struct {
	HostID string
	// Window is the sliding inactivity window that closes a transaction.
	Window time.Duration
	// MaxGroupAge force-closes very long transactions; a new parent is
	// started for further events.
	MaxGroupAge time.Duration
	NewID       func() string
}

// Input is a classified child event and its actor's process ancestry,
// ordered from the acting process up towards init.
type Input struct {
	Event    *pb.MutationEvent
	Ancestry []limiter.Process
}

type group struct {
	id          string
	root        limiter.Process
	tool        limiter.Tool
	lineage     []string
	actor       *pb.ActorContext
	pkgManager  bool // a package manager appears in some member's ancestry
	first, last time.Time
	emitted     uint32
	suppressed  uint32
	categories  map[pb.Category]int
	actions     map[pb.Action]int
	packages    []string
	morePkgs    int
}

// Debouncer is safe for concurrent use. Time is passed in explicitly so the
// caller owns the clock (and tests are deterministic).
type Debouncer struct {
	mu     sync.Mutex
	cfg    Config
	groups map[string]*group
}

// New creates a Debouncer; zero config fields take defaults.
func New(cfg Config) *Debouncer {
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.MaxGroupAge <= 0 {
		cfg.MaxGroupAge = DefaultMaxGroupAge
	}
	if cfg.NewID == nil {
		cfg.NewID = eventid.New
	}
	return &Debouncer{cfg: cfg, groups: make(map[string]*group)}
}

// Add routes one event. Events without a grouping-tool ancestor are returned
// unchanged; grouped events are returned with ParentEventId set. Any
// transaction that expired before now is closed and its parent returned too.
func (d *Debouncer) Add(now time.Time, in Input) []*pb.MutationEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.flushLocked(now, false)

	root, tool, ok := limiter.GroupingRoot(in.Ancestry)
	if !ok {
		return append(out, in.Event)
	}
	g := d.groupFor(now, root, tool, in.Ancestry, in.Event.GetActor())
	g.emitted++
	g.record(in.Event)
	in.Event.ParentEventId = g.id
	return append(out, in.Event)
}

// AttachToOpen links an event that has no useful ancestry (e.g. a service
// restarted by systemd on behalf of a package postinst script) to the most
// recently active open transaction, if any. It reports whether the event
// was attached; expired parents are returned either way.
func (d *Debouncer) AttachToOpen(now time.Time, ev *pb.MutationEvent) (out []*pb.MutationEvent, attached bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out = d.flushLocked(now, false)
	var best *group
	for _, g := range d.groups {
		if best == nil || g.last.After(best.last) {
			best = g
		}
	}
	if best == nil {
		return out, false
	}
	best.last = now
	best.emitted++
	best.record(ev)
	ev.ParentEventId = best.id
	return out, true
}

// AddSuppressed counts n child mutations that were not emitted individually
// (e.g. throttled by the storm breaker) towards the transaction of their
// ancestry. grouped is false if the ancestry has no grouping tool. Parents
// of transactions that expired before now are returned.
func (d *Debouncer) AddSuppressed(now time.Time, ancestry []limiter.Process, actor *pb.ActorContext, n int) (out []*pb.MutationEvent, grouped bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out = d.flushLocked(now, false)
	root, tool, ok := limiter.GroupingRoot(ancestry)
	if !ok || n <= 0 {
		return out, false
	}
	g := d.groupFor(now, root, tool, ancestry, actor)
	g.suppressed += uint32(n)
	return out, true
}

// Flush closes transactions idle for at least the window (or older than
// MaxGroupAge) and returns their parent events. Call it periodically.
func (d *Debouncer) Flush(now time.Time) []*pb.MutationEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushLocked(now, false)
}

// FlushAll closes every open transaction (agent shutdown).
func (d *Debouncer) FlushAll() []*pb.MutationEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushLocked(time.Time{}, true)
}

// Open returns the number of open transactions.
func (d *Debouncer) Open() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.groups)
}

// ParentID returns the open transaction ID for an ancestry, if any.
func (d *Debouncer) ParentID(ancestry []limiter.Process) (string, bool) {
	root, tool, ok := limiter.GroupingRoot(ancestry)
	if !ok {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	g, ok := d.groups[d.keyFor(root, tool)]
	if !ok {
		return "", false
	}
	return g.id, true
}

const pkgKey = "pkg"

func (d *Debouncer) keyFor(root limiter.Process, tool limiter.Tool) string {
	if tool.Kind == limiter.ToolPackageManager {
		if root.PID == 0 {
			// A synthetic package event joins the deployment run that is
			// driving the package manager, if one is open.
			if _, ok := d.groups[pkgKey]; !ok {
				if k, ok := d.recentPkgDeployment(); ok {
					return k
				}
			}
		}
		return pkgKey
	}
	return strconv.FormatUint(uint64(root.PID), 10) + "/" + tool.Name
}

func (d *Debouncer) recentPkgDeployment() (string, bool) {
	var key string
	var best *group
	for k, g := range d.groups {
		if g.pkgManager && k != pkgKey && (best == nil || g.last.After(best.last)) {
			key, best = k, g
		}
	}
	return key, best != nil
}

func (d *Debouncer) groupFor(now time.Time, root limiter.Process, tool limiter.Tool, ancestry []limiter.Process, actor *pb.ActorContext) *group {
	// Callers flush expired transactions first, so g is always live.
	key := d.keyFor(root, tool)
	pkg := hasPackageManager(ancestry)
	g := d.groups[key]
	if g == nil && pkg && key != pkgKey {
		// A deployment tool (ansible, ...) is driving the package manager:
		// adopt a transaction already opened by log-derived package events.
		if pg, ok := d.groups[pkgKey]; ok && pg.root.PID == 0 {
			delete(d.groups, pkgKey)
			d.groups[key] = pg
			g = pg
		}
	}
	if g == nil {
		g = &group{
			id: d.cfg.NewID(), first: now,
			categories: make(map[pb.Category]int),
			actions:    make(map[pb.Action]int),
		}
		g.setRoot(root, tool, ancestry, actor)
		d.groups[key] = g
	} else if g.root.PID == 0 && (root.PID != 0 || tool.Kind == limiter.ToolDeployment && g.tool.Kind != limiter.ToolDeployment) {
		g.setRoot(root, tool, ancestry, actor)
	} else if g.actor == nil && actor != nil {
		g.actor = actor
	}
	g.pkgManager = g.pkgManager || pkg
	g.last = now
	return g
}

func (g *group) setRoot(root limiter.Process, tool limiter.Tool, ancestry []limiter.Process, actor *pb.ActorContext) {
	g.root, g.tool = root, tool
	g.lineage = rootLineage(root, ancestry)
	if actor != nil || g.actor == nil {
		g.actor = actor
	}
}

func hasPackageManager(ancestry []limiter.Process) bool {
	for _, p := range ancestry {
		if t, ok := limiter.GroupingTool(p); ok && t.Kind == limiter.ToolPackageManager {
			return true
		}
	}
	return false
}

func (d *Debouncer) expired(g *group, now time.Time) bool {
	return now.Sub(g.last) >= d.cfg.Window || now.Sub(g.first) >= d.cfg.MaxGroupAge
}

func (d *Debouncer) flushLocked(now time.Time, all bool) []*pb.MutationEvent {
	var closed []*group
	for key, g := range d.groups {
		if all || d.expired(g, now) {
			closed = append(closed, g)
			delete(d.groups, key)
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].first.Before(closed[j].first) })
	out := make([]*pb.MutationEvent, 0, len(closed))
	for _, g := range closed {
		out = append(out, d.parentEvent(g))
	}
	return out
}

func (g *group) record(ev *pb.MutationEvent) {
	g.categories[ev.GetCategory()]++
	g.actions[ev.GetAction()]++
	t := ev.GetTarget()
	if ev.GetCategory() != pb.Category_CATEGORY_PACKAGE || t == nil {
		return
	}
	if len(g.packages) >= maxListedPackages {
		g.morePkgs++
		return
	}
	entry := t.GetPathOrKey()
	switch {
	case t.GetVersionBefore() != "" && t.GetVersionAfter() != "":
		entry += " " + t.GetVersionBefore() + " -> " + t.GetVersionAfter()
	case t.GetVersionAfter() != "":
		entry += " " + t.GetVersionAfter()
	}
	g.packages = append(g.packages, entry)
}

func (d *Debouncer) parentEvent(g *group) *pb.MutationEvent {
	total := g.emitted + g.suppressed
	action := pb.Action_ACTION_MODIFIED
	if g.actions[pb.Action_ACTION_UPGRADED] > 0 {
		action = pb.Action_ACTION_UPGRADED
	}

	summary := fmt.Sprintf("%s transaction: %d related change%s", g.tool.Name, total, plural(int(total)))
	if n := len(g.packages) + g.morePkgs; n > 0 {
		summary += fmt.Sprintf(" (%d package%s)", n, plural(n))
	}

	md := map[string]string{
		"event_type":         "TRANSACTION",
		"tool":               g.tool.Name,
		"root_pid":           strconv.FormatUint(uint64(g.root.PID), 10),
		"duration_ms":        strconv.FormatInt(g.last.Sub(g.first).Milliseconds(), 10),
		"children_emitted":   strconv.FormatUint(uint64(g.emitted), 10),
		"children_throttled": strconv.FormatUint(uint64(g.suppressed), 10),
	}
	if c := countsString(g.categories, func(c pb.Category) string {
		return strings.ToLower(strings.TrimPrefix(c.String(), "CATEGORY_"))
	}); c != "" {
		md["categories"] = c
	}
	if len(g.packages) > 0 {
		md["packages"] = strings.Join(g.packages, ", ")
		if g.morePkgs > 0 {
			md["packages"] += fmt.Sprintf(", +%d more", g.morePkgs)
		}
	}

	actor := &pb.ActorContext{
		Pid:            g.root.PID,
		ProcessName:    g.root.Name,
		Cmdline:        g.root.Cmdline,
		ProcessLineage: g.lineage,
	}
	if a := g.actor; a != nil {
		actor.Username, actor.UidOrSid, actor.LoginUid, actor.RemoteIp = a.Username, a.UidOrSid, a.LoginUid, a.RemoteIp
		actor.LoginUsername, actor.Ppid = a.LoginUsername, a.Ppid
		if g.root.PID == 0 {
			actor.Ppid = 0
		}
	}
	target := g.root.Cmdline
	if target == "" {
		target = g.root.Name
	}
	return &pb.MutationEvent{
		EventId:          g.id,
		HostId:           d.cfg.HostID,
		AgentTimestampMs: g.first.UnixMilli(),
		Level:            pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
		Category:         g.tool.Category(),
		Action:           action,
		Summary:          summary,
		Actor:            actor,
		Target:           &pb.TargetResource{TargetType: "transaction", PathOrKey: target},
		ChildCount:       total,
		Metadata:         md,
	}
}

// rootLineage renders the ancestry from init down to the root tool, in the
// spec's top-down order, e.g. ["sshd", "bash", "sudo", "apt-get"].
func rootLineage(root limiter.Process, ancestry []limiter.Process) []string {
	idx := -1
	for i, p := range ancestry {
		if p.PID == root.PID {
			idx = i
		}
	}
	if idx < 0 {
		return []string{root.Name}
	}
	out := make([]string, 0, len(ancestry)-idx)
	for i := len(ancestry) - 1; i >= idx; i-- {
		out = append(out, ancestry[i].Name)
	}
	return out
}

func countsString[K comparable](m map[K]int, name func(K) string) string {
	parts := make([]string, 0, len(m))
	for k, n := range m {
		parts = append(parts, name(k)+"="+strconv.Itoa(n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
