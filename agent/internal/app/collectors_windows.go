//go:build windows

package app

import (
	"context"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/collectors/windows"
	"github.com/statetrack/statetrack/agent/internal/config"
)

type winPlatform struct {
	fs    *windows.FS
	notes *windows.Notes
}

func (p *winPlatform) SetRoots(roots []string) { p.fs.SetRoots(roots) }
func (p *winPlatform) Tick()                   { p.notes.Sweep(time.Now()) }

func startPlatform(ctx context.Context, wg *sync.WaitGroup, a *Agent, roots []string) (platform, map[string]string, error) {
	log := a.Logger
	cfg := a.Config
	wcfg := cfg.Windows

	notes := &windows.Notes{TTL: windows.DefaultNoteTTL}
	attrib := windows.Attributor{Notes: notes, Resolve: windows.ResolveAccount}

	fs, err := windows.NewFS(windows.FSOptions{
		Roots:      roots,
		SelfFiles:  a.selfFiles,
		Classifier: a.Classifier,
		Attrib:     attrib,
		Handle:     a.Engine.HandleFile,
		Known: func(ctx context.Context, dir string) []string {
			paths, _ := a.Store.PathsUnder(ctx, dir, '\\')
			return paths
		},
		Logger: log,
	})
	if err != nil {
		return nil, nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := fs.Run(ctx); err != nil {
			log.Error("filesystem collector stopped", "err", err)
		}
	}()

	info := map[string]string{
		"fs":             "fsnotify",
		"registry":       "disabled",
		"services":       "disabled",
		"msi":            "disabled",
		"security_audit": "disabled",
	}

	if wcfg.Registry.Enabled {
		info["registry"] = "enabled"
		reg := windows.NewRegistry(windows.RegistryOptions{
			Keys:       wcfg.Registry.Keys,
			Classifier: a.Classifier,
			Attrib:     attrib,
			Handle:     a.Engine.HandleDoc,
			Seed:       a.Engine.SeedDoc,
			Known: func(ctx context.Context, key string) []string {
				paths, _ := a.Store.PathsUnder(ctx, key, '\\')
				return paths
			},
			Logger: log,
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := reg.Run(ctx); err != nil {
				log.Error("registry collector stopped", "err", err)
			}
		}()
	}

	if wcfg.Services.Enabled || wcfg.MSI.Enabled || wcfg.SecurityAudit.Enabled {
		info["services"] = serviceSource(wcfg.Services)
		info["msi"] = boolStr(wcfg.MSI.Enabled)
		info["security_audit"] = boolStr(wcfg.SecurityAudit.Enabled)

		ccs, _ := windows.CurrentControlSet()
		mon := windows.NewMonitor(windows.MonitorOptions{
			SCMQuery:     pick(wcfg.Services.Enabled, windows.SCMQuery),
			MSIQuery:     pick(wcfg.MSI.Enabled, windows.MSIQuery),
			AuditQuery:   pick(wcfg.SecurityAudit.Enabled, windows.AuditQuery),
			CCS:          ccs,
			Notes:        notes,
			PollSCM:      wcfg.Services.Enabled && (wcfg.Services.Source == "poll" || wcfg.Services.Source == "auto"),
			PollInterval: wcfg.Services.PollInterval.D(),
			Scrub:        a.scrubber.Line,
			Resolve:      windows.ResolveAccount,
			Emit:         a.Engine.HandleEvent,
			Logger:       log,
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mon.Run(ctx); err != nil {
				log.Error("monitor collector stopped", "err", err)
			}
		}()
	}

	return &winPlatform{fs: fs, notes: notes}, info, nil
}

func pick(on bool, s string) string {
	if on {
		return s
	}
	return ""
}

func boolStr(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

func serviceSource(s config.WinServices) string {
	if !s.Enabled {
		return "disabled"
	}
	switch s.Source {
	case "poll", "eventlog":
		return s.Source
	case "auto":
		return "auto"
	}
	return "auto"
}
