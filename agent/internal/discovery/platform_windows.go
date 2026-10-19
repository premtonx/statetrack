//go:build windows

package discovery

// platformProbers returns the discovery probes for the host OS. Windows hosts
// probe IIS and SQL Server.
func platformProbers() []Prober {
	return windowsProbers()
}
