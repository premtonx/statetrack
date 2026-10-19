//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/statetrack/statetrack/agent/internal/app"
)

// run starts the agent in the foreground, shutting it down on SIGINT or
// SIGTERM (routing through the same engine teardown path).
func run(opts app.Options) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, opts)
}
