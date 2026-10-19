//go:build !windows

package discovery

// windowsRegistryTargets enumerates the registry keys and services a catalog
// target names. Off Windows there is no registry, so this is a no-op: the
// catalog entry simply contributes nothing to a Linux host's discovery result.
func windowsRegistryTargets(Target) []scanDoc { return nil }

// scheduledTaskTargets enumerates Task Scheduler definitions. Windows-only.
func scheduledTaskTargets(Target) []scanDoc { return nil }
