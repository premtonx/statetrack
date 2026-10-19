package config

import (
	"context"
	"log/slog"
	"reflect"
	"time"
)

// Reloader re-reads the configuration periodically. Polling (rather than
// file notifications) survives editors' atomic saves and config management
// tools replacing the file.
type Reloader struct {
	Path   string // "" = default resolution as in Load
	GOOS   string
	Env    func(string) (string, bool)
	Logger *slog.Logger
	// OnChange is called with the previous and new configuration whenever
	// the loaded configuration differs. Invalid files are logged and the
	// previous configuration stays in effect.
	OnChange func(old, cur Config)
	// OnTick is called on every poll with the current configuration (used
	// to re-expand watch globs such as /home/*/.ssh).
	OnTick func(cur Config)
}

// Run polls until ctx is done, starting from current.
func (r *Reloader) Run(ctx context.Context, current Config) {
	for {
		interval := current.ReloadInterval.D()
		if interval <= 0 {
			interval = 30 * time.Second
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		current = r.Poll(current)
	}
}

// Poll performs one reload check and returns the configuration in effect.
func (r *Reloader) Poll(current Config) Config {
	cur, _, err := LoadFor(r.GOOS, r.Path, r.Env)
	if err != nil {
		r.logger().Error("config reload failed; keeping previous configuration", "err", err)
	} else if !reflect.DeepEqual(cur, current) {
		if restart := RestartRequired(current, cur); len(restart) > 0 {
			r.logger().Warn("config changes require an agent restart", "settings", restart)
		}
		if r.OnChange != nil {
			r.OnChange(current, cur)
		}
		current = cur
	}
	if r.OnTick != nil {
		r.OnTick(current)
	}
	return current
}

func (r *Reloader) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}
