//go:build linux

package app

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"github.com/statetrack/statetrack/agent/internal/collectors/linux"
	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

type linuxPlatform struct {
	fs  *linux.FS
	res *linux.Resolver
}

func (p *linuxPlatform) SetRoots(roots []string) { p.fs.SetRoots(roots) }
func (p *linuxPlatform) Tick()                   { p.res.Sweep() }

func startPlatform(ctx context.Context, wg *sync.WaitGroup, a *Agent, roots []string) (platform, map[string]string, error) {
	log := a.Logger
	cfg := a.Config
	res := linux.NewResolver(linux.ResolverOptions{ProcRoot: a.o.ProcRoot, PasswdPath: a.o.PasswdPath, Scrub: a.scrubber.Line})
	kst := linux.StartAttribution(ctx, wg, res, log)

	fsc, err := linux.NewFS(linux.FSOptions{
		Roots:      roots,
		SelfFiles:  a.selfFiles,
		Classifier: a.Classifier,
		Resolver:   res,
		Handle:     a.Engine.HandleFile,
		Known: func(ctx context.Context, dir string) []string {
			paths, _ := a.Store.PathsUnder(ctx, dir, '/')
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
		if err := fsc.Run(ctx); err != nil {
			log.Error("filesystem collector stopped", "err", err)
		}
	}()

	info := map[string]string{
		"fs":             "inotify",
		"fanotify":       strconv.FormatBool(fsc.Status().Fanotify),
		"audit":          strconv.FormatBool(kst.Audit),
		"proc_connector": strconv.FormatBool(kst.Connector),
		"systemd":        "disabled",
		"packages":       "disabled",
	}

	if cfg.Systemd.Enabled {
		info["systemd"] = "enabled"
		sd := linux.NewSystemd(linux.SystemdOptions{Units: cfg.Systemd.Units, Logger: log,
			Emit: func(ctx context.Context, c linux.ServiceChange) {
				if err := a.Engine.HandleEvent(ctx, serviceEvent(c)); err != nil {
					log.Error("service event", "unit", c.Unit, "err", err)
				}
			}})
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sd.Run(ctx); errors.Is(err, linux.ErrNoSystemd) {
				log.Info("systemd collector disabled: no D-Bus or systemctl on this host")
			} else if err != nil {
				log.Error("systemd collector stopped", "err", err)
			}
		}()
	}

	if p := cfg.Packages; p.Enabled {
		info["packages"] = "enabled"
		pk := linux.NewPackages(linux.PackagesOptions{DpkgLog: p.DpkgLog, DnfLog: p.DnfLog, YumLog: p.YumLog,
			ApkLog: p.ApkLog, ApkDB: p.ApkDB, Logger: log,
			Emit: func(ctx context.Context, c linux.PackageChange) {
				if err := a.Engine.HandleEvent(ctx, packageEvent(c)); err != nil {
					log.Error("package event", "package", c.Name, "err", err)
				}
			}})
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pk.Run(ctx); err != nil {
				log.Error("package collector stopped", "err", err)
			}
		}()
	}
	return &linuxPlatform{fs: fsc, res: res}, info, nil
}

func serviceEvent(c linux.ServiceChange) engine.Event {
	target := &pb.TargetResource{TargetType: "service", PathOrKey: c.Unit}
	if c.DaemonReload {
		target.TargetType = "service_manager"
	}
	return engine.Event{
		Category: pb.Category_CATEGORY_SERVICE,
		Action:   c.Action,
		Summary:  c.Summary(),
		Target:   target,
		Metadata: c.Metadata(),
		// Restarts by package scripts belong to the package transaction;
		// crashes are never folded into one.
		Correlate: !c.Crashed && !c.DaemonReload,
		Time:      c.At,
	}
}

func packageEvent(c linux.PackageChange) engine.Event {
	return engine.Event{
		Category: pb.Category_CATEGORY_PACKAGE,
		Action:   c.Action(),
		Summary:  c.Summary(),
		Target:   c.Target(),
		Metadata: c.Metadata(),
		// Synthetic ancestry: package logs carry no PID; the debouncer joins
		// this to the package manager's open transaction.
		Ancestry: []limiter.Process{{Name: c.Manager}},
		Time:     c.At,
	}
}
