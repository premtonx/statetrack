//go:build windows

package windows

import (
	"golang.org/x/sys/windows/svc/mgr"
)

// ListServices snapshots the current SCM service states (name, state, PID).
func ListServices() ([]ServiceStatus, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	out := make([]ServiceStatus, 0, len(names))
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		st, err := s.Query()
		s.Close()
		if err != nil {
			continue
		}
		out = append(out, ServiceStatus{Name: name, State: uint32(st.State), PID: st.ProcessId})
	}
	return out, nil
}
