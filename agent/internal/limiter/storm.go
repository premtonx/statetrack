package limiter

import (
	"strconv"
	"sync"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// BreakerConfig configures the change-storm circuit breaker.
type BreakerConfig struct {
	// Burst events are allowed per scope per Window before tripping.
	Burst  int
	Window time.Duration
	// Cooldown is how long individual diffing stays paused once tripped.
	Cooldown time.Duration
	// IdleTTL drops state for scopes that have been quiet this long.
	IdleTTL time.Duration
	// MaxScopes bounds memory; new scopes beyond it are not rate limited.
	MaxScopes int
}

// DefaultBreakerConfig is the spec's 50 events / 10 s, 30 s pause.
func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{Burst: 50, Window: 10 * time.Second, Cooldown: 30 * time.Second,
		IdleTTL: 2 * time.Minute, MaxScopes: 4096}
}

// ScopeKind identifies what a storm scope is keyed by.
type ScopeKind int

const (
	ScopeDirectory ScopeKind = iota + 1
	ScopePID
)

// StormEvent is the input to the breaker.
type StormEvent struct {
	Dir   string
	PID   uint32 // 0 = unknown, PID scope is skipped
	Level pb.ImpactLevel
}

// Verdict is the breaker decision for one event.
type Verdict struct {
	Throttled bool
	// Tripped is set on the event that opened the circuit.
	Tripped bool
	Kind    ScopeKind
	Scope   string
}

// StormSummary is emitted once per tripped scope after its cooldown, as a
// single CHANGE_STORM_THROTTLED event.
type StormSummary struct {
	Kind  ScopeKind
	Scope string // directory path or decimal PID
	Since time.Time
	Until time.Time
	// Suppressed is the number of mutations that were not processed
	// individually while the circuit was open.
	Suppressed int
	// Level is the most severe impact level among suppressed events.
	Level pb.ImpactLevel
}

type scope struct {
	tokens     float64
	last       time.Time
	open       bool
	since      time.Time
	until      time.Time
	suppressed int
	level      pb.ImpactLevel
}

// Breaker is a per-directory / per-PID token-bucket storm breaker.
// It is safe for concurrent use.
type Breaker struct {
	mu      sync.Mutex
	cfg     BreakerConfig
	rate    float64 // tokens per second
	scopes  map[string]*scope
	pending []StormSummary
}

// NewBreaker creates a breaker; zero config fields take defaults.
func NewBreaker(cfg BreakerConfig) *Breaker {
	def := DefaultBreakerConfig()
	if cfg.Burst <= 0 {
		cfg.Burst = def.Burst
	}
	if cfg.Window <= 0 {
		cfg.Window = def.Window
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = def.Cooldown
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = def.IdleTTL
	}
	if cfg.MaxScopes <= 0 {
		cfg.MaxScopes = def.MaxScopes
	}
	return &Breaker{
		cfg:    cfg,
		rate:   float64(cfg.Burst) / cfg.Window.Seconds(),
		scopes: make(map[string]*scope),
	}
}

// Allow charges one event against its directory and PID scopes.
func (b *Breaker) Allow(now time.Time, ev StormEvent) Verdict {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ev.Dir != "" {
		if v := b.charge(now, ScopeDirectory, ev.Dir, ev.Level); v.Throttled {
			return v
		}
	}
	if ev.PID != 0 {
		if v := b.charge(now, ScopePID, strconv.FormatUint(uint64(ev.PID), 10), ev.Level); v.Throttled {
			return v
		}
	}
	return Verdict{}
}

func (b *Breaker) charge(now time.Time, kind ScopeKind, name string, level pb.ImpactLevel) Verdict {
	key := scopeKey(kind, name)
	s := b.scopes[key]
	if s == nil {
		if len(b.scopes) >= b.cfg.MaxScopes {
			b.evictIdle(now)
			if len(b.scopes) >= b.cfg.MaxScopes {
				return Verdict{}
			}
		}
		s = &scope{tokens: float64(b.cfg.Burst), last: now}
		b.scopes[key] = s
	}

	if elapsed := now.Sub(s.last).Seconds(); elapsed > 0 {
		s.tokens = min(float64(b.cfg.Burst), s.tokens+elapsed*b.rate)
	}
	s.last = now

	if s.open {
		if now.Before(s.until) {
			s.suppressed++
			s.level = moreSevere(s.level, level)
			return Verdict{Throttled: true, Kind: kind, Scope: name}
		}
		b.close(kind, name, s)
	}

	if s.tokens >= 1 {
		s.tokens--
		return Verdict{}
	}
	s.open, s.since, s.until = true, now, now.Add(b.cfg.Cooldown)
	s.suppressed, s.level = 1, level
	return Verdict{Throttled: true, Tripped: true, Kind: kind, Scope: name}
}

func (b *Breaker) close(kind ScopeKind, name string, s *scope) {
	b.pending = append(b.pending, StormSummary{Kind: kind, Scope: name, Since: s.since, Until: s.until,
		Suppressed: s.suppressed, Level: s.level})
	s.open, s.suppressed, s.level = false, 0, pb.ImpactLevel_IMPACT_LEVEL_UNSPECIFIED
}

// Sweep returns summaries for circuits whose cooldown has ended and drops
// idle scope state. Call it periodically (e.g. every second).
func (b *Breaker) Sweep(now time.Time) []StormSummary {
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, s := range b.scopes {
		if s.open && !now.Before(s.until) {
			kind, name := splitScopeKey(key)
			b.close(kind, name, s)
		}
	}
	b.evictIdle(now)
	out := b.pending
	b.pending = nil
	return out
}

// Throttled reports whether a scope currently has an open circuit.
func (b *Breaker) Throttled(now time.Time, kind ScopeKind, name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.scopes[scopeKey(kind, name)]
	return s != nil && s.open && now.Before(s.until)
}

func (b *Breaker) evictIdle(now time.Time) {
	for key, s := range b.scopes {
		if !s.open && now.Sub(s.last) >= b.cfg.IdleTTL {
			delete(b.scopes, key)
		}
	}
}

func scopeKey(kind ScopeKind, name string) string {
	if kind == ScopePID {
		return "p:" + name
	}
	return "d:" + name
}

func splitScopeKey(key string) (ScopeKind, string) {
	if key[0] == 'p' {
		return ScopePID, key[2:]
	}
	return ScopeDirectory, key[2:]
}

// moreSevere returns the more critical level (lower number, unspecified last).
func moreSevere(a, b pb.ImpactLevel) pb.ImpactLevel {
	switch {
	case a == pb.ImpactLevel_IMPACT_LEVEL_UNSPECIFIED:
		return b
	case b == pb.ImpactLevel_IMPACT_LEVEL_UNSPECIFIED:
		return a
	case b < a:
		return b
	}
	return a
}
