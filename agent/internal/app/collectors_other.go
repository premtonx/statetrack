//go:build !linux && !windows

package app

import (
	"context"
	"sync"
)

type noPlatform struct{}

func (noPlatform) SetRoots([]string) {}
func (noPlatform) Tick()             {}

// No collectors exist for this OS; the agent runs the pipeline (baseline,
// offline reconciliation, spool) without live collectors.
func startPlatform(_ context.Context, _ *sync.WaitGroup, a *Agent, _ []string) (platform, map[string]string, error) {
	a.Logger.Warn("no live collectors for this OS yet")
	return noPlatform{}, map[string]string{"collectors": "none"}, nil
}
