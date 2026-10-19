package config

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// machineGUID is the per-installation identifier Windows generates at setup.
func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(v))
}
