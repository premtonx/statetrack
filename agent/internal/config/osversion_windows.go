package config

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// OSVersion returns a short, human-readable OS version for host
// registration, or "" when it cannot be determined. The goos argument is
// accepted for testability and ignored on Windows.
func OSVersion(_ string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	name, _, err := k.GetStringValue("ProductName")
	if err != nil {
		name = "Windows"
	}
	maj, _, _ := k.GetIntegerValue("CurrentMajorVersionNumber")
	min, _, _ := k.GetIntegerValue("CurrentMinorVersionNumber")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	return fmt.Sprintf("%s %d.%d.%s", name, maj, min, build)
}
