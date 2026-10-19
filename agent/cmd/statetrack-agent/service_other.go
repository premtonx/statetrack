//go:build !windows

package main

import "errors"

// serviceCommand reports that native service management is only available on
// Windows. On Linux the agent runs under systemd (see deploy/linux/ and
// deploy/install.sh); the binary itself has no service subcommands there.
func serviceCommand(args []string) error {
	return errors.New("`service` subcommands are Windows-only; use the systemd unit (deploy/install.sh) on Linux")
}
