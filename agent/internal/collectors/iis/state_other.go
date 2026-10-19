//go:build !windows

package iis

import (
	"context"
	"errors"
)

// errNotWindows is returned when the runtime query is attempted on a host that
// has no IIS. The collector treats it as "state unknown" rather than an error,
// so a config file copied from a Windows host still parses on Linux (which is
// what the parser tests rely on).
var errNotWindows = errors.New("iis: runtime state is only available on Windows")

// queryStates has no cross-platform implementation: IIS exists only on Windows.
func queryStates(context.Context) (map[string]string, error) { return nil, errNotWindows }
