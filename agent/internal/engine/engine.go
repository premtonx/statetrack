// Package engine wires the agent core together: classify (limiter) ->
// storm breaker (limiter) -> shadow diff (shadow) -> transaction grouping
// (debouncer) -> durable queue (spool). Platform collectors feed it file
// notifications; Tick drives the time-based parts.
package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/debouncer"
	"github.com/statetrack/statetrack/agent/internal/eventid"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	"github.com/statetrack/statetrack/agent/internal/shadow"
	"github.com/statetrack/statetrack/agent/internal/spool"
	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// Engine is safe for concurrent use.
type Engine struct {
	HostID     string
	Classifier *limiter.Classifier
	Breaker    *limiter.Breaker
	Tracker    *shadow.Tracker
	Debouncer  *debouncer.Debouncer
	Spool      *spool.Spool
	Now        func() time.Time
	NewID      func() string

	mu             sync.Mutex
	pendingDeletes map[string]FileEvent
}

// FileEvent is a collector notification that something happened to Path.
type FileEvent struct {
	Path     string
	Actor    *pb.ActorContext
	Ancestry []limiter.Process // acting process first, up towards init
	// Attribution names how Actor was determined (reported as metadata).
	Attribution string
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) newID() string {
	if e.NewID != nil {
		return e.NewID()
	}
	return eventid.New()
}

func (e *Engine) classify(path string, ancestry []limiter.Process, now time.Time) limiter.Decision {
	cand := limiter.Candidate{Path: path, Now: now}
	if _, tool, ok := limiter.GroupingRoot(ancestry); ok {
		cand.Tool = &tool
	}
	return e.Classifier.Classify(cand)
}

// classifyDoc is classify for a virtual document (a registry key, an IIS app
// pool, a database table). The collector's target type travels with the
// candidate so a granular rule matches the document's real kind instead of
// guessing "file" from its path.
func (e *Engine) classifyDoc(path, targetType string, ancestry []limiter.Process, now time.Time) limiter.Decision {
	cand := limiter.Candidate{Path: path, TargetType: targetType, Now: now}
	if _, tool, ok := limiter.GroupingRoot(ancestry); ok {
		cand.Tool = &tool
	}
	return e.Classifier.Classify(cand)
}

// Policy adapts the classifier for the baseline walker.
func (e *Engine) Policy() Policy { return Policy{c: e.Classifier} }

// Policy implements baseline.Policy.
type Policy struct{ c *limiter.Classifier }

func (p Policy) Skip(path string) bool { return p.c.Blacklisted(path) }

func (p Policy) Mode(path string) shadow.Mode {
	return modeFor(p.c.Classify(limiter.Candidate{Path: path}))
}

func modeFor(d limiter.Decision) shadow.Mode {
	if d.Diff {
		return shadow.ModeFull
	}
	return shadow.ModeMetadata
}

// HandleFile processes one file notification.
func (e *Engine) HandleFile(ctx context.Context, fe FileEvent) error {
	now := e.now()
	dec := e.classify(fe.Path, fe.Ancestry, now)
	if dec.Drop {
		return nil
	}

	v := e.Breaker.Allow(now, limiter.StormEvent{Dir: filepath.Dir(fe.Path), PID: fe.Actor.GetPid(), Level: dec.Level})
	if v.Throttled {
		// Individual diffing is paused for this scope; the shadow is left
		// untouched so the first post-storm diff shows the cumulative change.
		out, _ := e.Debouncer.AddSuppressed(now, fe.Ancestry, fe.Actor, 1)
		return e.Spool.Append(ctx, out...)
	}

	ch, err := e.Tracker.Observe(ctx, fe.Path, modeFor(dec))
	if err != nil {
		return fmt.Errorf("engine: observe %s: %w", fe.Path, err)
	}
	e.mu.Lock()
	if ch == nil && e.Tracker.PendingDelete(fe.Path) {
		if e.pendingDeletes == nil {
			e.pendingDeletes = make(map[string]FileEvent)
		}
		e.pendingDeletes[fe.Path] = fe
	} else {
		delete(e.pendingDeletes, fe.Path)
	}
	e.mu.Unlock()
	if ch == nil {
		return nil
	}

	ev, err := e.buildEvent(ch, dec, fe, now)
	if err != nil {
		return err
	}
	out := e.Debouncer.Add(now, debouncer.Input{Event: ev, Ancestry: fe.Ancestry})
	return e.Spool.Append(ctx, out...)
}

// DocEvent reports the current state of a virtual document: a resource
// that is not a file but is diffed like one (a registry key rendered as
// text).
type DocEvent struct {
	Path       string
	TargetType string // e.g. "registry"
	// Content is the rendered document; nil means it no longer exists.
	Content  []byte
	ModTime  time.Time
	Actor    *pb.ActorContext
	Ancestry []limiter.Process
	// Attribution names how Actor was determined (reported as metadata).
	Attribution string
}

// Parent returns the containing document path ('\'-separated for registry keys,
// '/'-separated for the virtual documents the surgical watchers render).
func (d DocEvent) Parent() string {
	if i := strings.LastIndexByte(d.Path, '\\'); i > 0 {
		return d.Path[:i]
	}
	if i := strings.LastIndexByte(d.Path, '/'); i > 1 {
		return d.Path[:i]
	}
	return d.Path
}

// HandleDoc processes one virtual document observation.
func (e *Engine) HandleDoc(ctx context.Context, de DocEvent) error {
	now := e.now()
	dec := e.classifyDoc(de.Path, de.TargetType, de.Ancestry, now)
	if dec.Drop {
		return nil
	}
	v := e.Breaker.Allow(now, limiter.StormEvent{Dir: de.Parent(), PID: de.Actor.GetPid(), Level: dec.Level})
	if v.Throttled {
		out, _ := e.Debouncer.AddSuppressed(now, de.Ancestry, de.Actor, 1)
		return e.Spool.Append(ctx, out...)
	}
	ch, err := e.Tracker.ObserveContent(ctx, de.Path, de.Content, de.ModTime, modeFor(dec))
	if err != nil {
		return fmt.Errorf("engine: observe %s: %w", de.Path, err)
	}
	if ch == nil {
		return nil
	}
	ev, err := e.buildEvent(ch, dec, FileEvent{Path: de.Path, Actor: de.Actor, Ancestry: de.Ancestry, Attribution: de.Attribution}, now)
	if err != nil {
		return err
	}
	if de.TargetType != "" {
		ev.Target.TargetType = de.TargetType
	}
	out := e.Debouncer.Add(now, debouncer.Input{Event: ev, Ancestry: de.Ancestry})
	return e.Spool.Append(ctx, out...)
}

// SeedDoc records a virtual document's baseline state without an event.
func (e *Engine) SeedDoc(ctx context.Context, path string, content []byte, modTime time.Time) error {
	return e.SeedDocOfType(ctx, path, "", content, modTime)
}

// SeedDocOfType is SeedDoc with the document's target type, so a granular rule
// scoped to that type decides whether the baseline keeps full content (a text
// diff is possible) or only metadata and a hash.
func (e *Engine) SeedDocOfType(ctx context.Context, path, targetType string, content []byte, modTime time.Time) error {
	if e.Classifier.Blacklisted(path) {
		return nil
	}
	mode := modeFor(e.Classifier.Classify(limiter.Candidate{Path: path, TargetType: targetType}))
	return e.Tracker.SeedContent(ctx, path, content, modTime, mode)
}

// Event is a non-file collector notification (service state change,
// package install/upgrade/remove, ...).
type Event struct {
	Category pb.Category
	Action   pb.Action
	Summary  string
	Target   *pb.TargetResource
	Actor    *pb.ActorContext
	// Ancestry groups the event into a transaction; package collectors pass
	// a synthetic PID-less ancestry such as [{Name: "dpkg"}].
	Ancestry []limiter.Process
	Metadata map[string]string
	// Correlate attaches an event without a grouping ancestry to the open
	// transaction, if any (e.g. a service restarted by a package script).
	Correlate bool
	// Time is when the change happened; zero means now.
	Time time.Time
}

// HandleEvent processes one non-file event.
func (e *Engine) HandleEvent(ctx context.Context, in Event) error {
	now := e.now()
	cand := limiter.Candidate{Category: in.Category, Now: now}
	_, tool, grouped := limiter.GroupingRoot(in.Ancestry)
	if grouped {
		cand.Tool = &tool
	}
	dec := e.Classifier.Classify(cand)
	if dec.Drop {
		return nil
	}

	scope := strings.ToLower(strings.TrimPrefix(in.Category.String(), "CATEGORY_")) + ":" + in.Target.GetPathOrKey()
	if v := e.Breaker.Allow(now, limiter.StormEvent{Dir: scope, PID: in.Actor.GetPid(), Level: dec.Level}); v.Throttled {
		out, _ := e.Debouncer.AddSuppressed(now, in.Ancestry, in.Actor, 1)
		return e.Spool.Append(ctx, out...)
	}

	at := in.Time
	if at.IsZero() {
		at = now
	}
	md := map[string]string{"classification": dec.Reason}
	for k, v := range in.Metadata {
		md[k] = v
	}
	applyRuleMetadata(md, dec)
	ev := &pb.MutationEvent{
		EventId:          e.newID(),
		HostId:           e.HostID,
		AgentTimestampMs: at.UnixMilli(),
		Level:            dec.Level,
		Category:         dec.Category,
		Action:           in.Action,
		Summary:          in.Summary,
		Actor:            in.Actor,
		Target:           in.Target,
		Metadata:         md,
	}
	if !grouped && in.Correlate {
		out, attached := e.Debouncer.AttachToOpen(now, ev)
		if attached {
			ev.Level = pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED
			md["classification"] = "grouped:open_transaction"
		}
		return e.Spool.Append(ctx, append(out, ev)...)
	}
	out := e.Debouncer.Add(now, debouncer.Input{Event: ev, Ancestry: in.Ancestry})
	return e.Spool.Append(ctx, out...)
}

// Tick confirms pending deletions, emits storm summaries and closes expired
// transactions. Call it about once per second.
func (e *Engine) Tick(ctx context.Context) error {
	now := e.now()
	var out []*pb.MutationEvent

	dels, err := e.Tracker.ConfirmDeletes(ctx, func(p string) shadow.Mode { return e.Policy().Mode(p) })
	if err != nil {
		return fmt.Errorf("engine: confirm deletes: %w", err)
	}
	for _, ch := range dels {
		e.mu.Lock()
		fe := e.pendingDeletes[ch.Path]
		delete(e.pendingDeletes, ch.Path)
		e.mu.Unlock()
		dec := e.classify(ch.Path, fe.Ancestry, now)
		ev, err := e.buildEvent(ch, dec, fe, now)
		if err != nil {
			return err
		}
		out = append(out, e.Debouncer.Add(now, debouncer.Input{Event: ev, Ancestry: fe.Ancestry})...)
	}

	for _, s := range e.Breaker.Sweep(now) {
		out = append(out, e.stormEvent(s))
	}
	out = append(out, e.Debouncer.Flush(now)...)
	return e.Spool.Append(ctx, out...)
}

// Shutdown flushes open transactions to the spool.
func (e *Engine) Shutdown(ctx context.Context) error {
	return e.Spool.Append(ctx, e.Debouncer.FlushAll()...)
}

func (e *Engine) buildEvent(ch *shadow.Change, dec limiter.Decision, fe FileEvent, now time.Time) (*pb.MutationEvent, error) {
	t := &pb.TargetResource{TargetType: "file", PathOrKey: ch.Path}
	if b := ch.Before; b != nil {
		t.HashBefore, t.SizeBefore = b.Hash, b.Size
	}
	if a := ch.After; a != nil {
		t.HashAfter, t.SizeAfter = a.Hash, a.Size
	}
	md := map[string]string{"content": ch.Content.String(), "classification": dec.Reason}
	if ch.DiffSkipped != "" {
		md["diff_skipped"] = ch.DiffSkipped
	}
	if fe.Attribution != "" {
		md["attribution"] = fe.Attribution
	}
	applyRuleMetadata(md, dec)
	if ch.Content != limiter.ContentText && ch.Action == pb.Action_ACTION_MODIFIED {
		md["event_type"] = "BINARY_MODIFIED"
	}
	if ch.ModeChanged {
		md["mode_before"] = ch.Before.Mode.String()
		md["mode_after"] = ch.After.Mode.String()
	}

	ev := &pb.MutationEvent{
		EventId:          e.newID(),
		HostId:           e.HostID,
		AgentTimestampMs: now.UnixMilli(),
		Level:            dec.Level,
		Category:         dec.Category,
		Action:           ch.Action,
		Summary:          summarize(ch),
		Actor:            fe.Actor,
		Target:           t,
		Metadata:         md,
	}
	if ch.Diff != "" {
		z, err := diff.CompressString(ch.Diff)
		if err != nil {
			return nil, fmt.Errorf("engine: compress diff: %w", err)
		}
		ev.UnifiedDiffZstd = z
	}
	return ev, nil
}

// applyRuleMetadata attaches the granular policy rule that decided the
// verdict, if any, so the console can surface the "Rule: <name>" badge.
func applyRuleMetadata(md map[string]string, dec limiter.Decision) {
	if dec.RuleName != "" {
		md["rule_name"] = dec.RuleName
	}
	if dec.RuleTags != "" {
		md["rule_tags"] = dec.RuleTags
	}
}

func (e *Engine) stormEvent(s limiter.StormSummary) *pb.MutationEvent {
	target := &pb.TargetResource{TargetType: "directory", PathOrKey: s.Scope}
	category, where := pb.Category_CATEGORY_CONFIG, "under "+s.Scope
	if s.Kind == limiter.ScopePID {
		target = &pb.TargetResource{TargetType: "process", PathOrKey: "pid:" + s.Scope}
		category, where = pb.Category_CATEGORY_PROCESS, "by pid "+s.Scope
	}
	level := s.Level
	if level == pb.ImpactLevel_IMPACT_LEVEL_UNSPECIFIED {
		level = pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT
	}
	return &pb.MutationEvent{
		EventId:          e.newID(),
		HostId:           e.HostID,
		AgentTimestampMs: s.Since.UnixMilli(),
		Level:            level,
		Category:         category,
		Action:           pb.Action_ACTION_THROTTLED,
		Summary: fmt.Sprintf("Change storm: %d mutations %s throttled for %s",
			s.Suppressed, where, s.Until.Sub(s.Since).Round(time.Second)),
		Target: target,
		Metadata: map[string]string{
			"event_type":     "CHANGE_STORM_THROTTLED",
			"storm_scope":    s.Scope,
			"mutation_count": strconv.Itoa(s.Suppressed),
			"since_ms":       strconv.FormatInt(s.Since.UnixMilli(), 10),
			"until_ms":       strconv.FormatInt(s.Until.UnixMilli(), 10),
		},
	}
}

func summarize(ch *shadow.Change) string {
	verb := map[pb.Action]string{
		pb.Action_ACTION_CREATED:  "Created",
		pb.Action_ACTION_MODIFIED: "Modified",
		pb.Action_ACTION_DELETED:  "Deleted",
	}[ch.Action]
	s := verb + " " + ch.Path
	switch {
	case ch.Diff != "":
		add, del := diffStat(ch.Diff)
		s += fmt.Sprintf(" (+%d -%d)", add, del)
	case ch.ModeChanged && ch.Before != nil && ch.Before.Hash == ch.After.Hash:
		s += fmt.Sprintf(" (mode %s -> %s)", ch.Before.Mode, ch.After.Mode)
	case ch.Content == limiter.ContentBinary:
		s += " (binary)"
	case ch.Content == limiter.ContentTooLarge:
		s += " (> 1 MB, hash only)"
	}
	return s
}

func diffStat(d string) (add, del int) {
	for _, l := range strings.Split(d, "\n") {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
		case strings.HasPrefix(l, "+"):
			add++
		case strings.HasPrefix(l, "-"):
			del++
		}
	}
	return add, del
}
