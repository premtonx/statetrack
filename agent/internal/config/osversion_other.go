//go:build !windows

package config

import (
	"os"
	"strings"
)

// OSVersion returns a short, human-readable OS version for host
// registration, or "" when it cannot be determined. The goos argument is
// accepted for testability and ignored on non-Windows platforms.
func OSVersion(_ string) string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}
