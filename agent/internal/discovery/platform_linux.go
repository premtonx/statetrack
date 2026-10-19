//go:build linux

package discovery

// platformProbers returns the discovery probes for the host OS. Linux hosts
// probe the web servers, database services and container runtime.
func platformProbers() []Prober {
	return linuxProbers()
}
