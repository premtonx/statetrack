//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/statetrack/statetrack/agent/internal/app"
)

// run starts the agent either as a Windows service (ServerHistoryAgent.exe
// equivalent, registered under StateTrackAgent) or, when launched from a
// console, in the foreground until Ctrl+C.
func run(opts app.Options) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isSvc {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return app.Run(ctx, opts)
	}
	return svc.Run("StateTrackAgent", &agentService{opts: opts})
}

// agentService adapts the agent to the SCM lifecycle. svc.Stop, svc.Shutdown
// and svc.Interrogate are handled here and routed into the same context
// cancellation that tears the engine down.
type agentService struct {
	opts app.Options
}

func (s *agentService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmds = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, s.opts) }()

	changes <- svc.Status{State: svc.Running, Accepts: cmds}
	for {
		select {
		case err := <-done:
			// The agent exited on its own (fatal error or context loss).
			cancel()
			changes <- svc.Status{State: svc.Stopped}
			if err != nil {
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}
