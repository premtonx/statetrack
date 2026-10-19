//go:build !linux && !windows

package discovery

// platformProbers returns no probes for unhandled operating systems; the
// scanner still runs and simply reports an empty workload set.
func platformProbers() []Prober { return nil }
