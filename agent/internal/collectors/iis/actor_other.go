//go:build !windows

package iis

import (
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// DefaultActorWindow mirrors the Windows constant so callers can pass one value
// on every platform.
const DefaultActorWindow = 20 * time.Second

// AttributeRecentManager has no cross-platform implementation: it enumerates
// the Windows process table. Tests inject their own Attribute function.
func AttributeRecentManager(time.Time, time.Duration) (*pb.ActorContext, string) {
	return nil, ""
}
