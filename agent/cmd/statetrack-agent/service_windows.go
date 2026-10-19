//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceName is the Windows service name (also used by run_windows.go).
const serviceName = "StateTrackAgent"

// serviceConfigPath is the default agent configuration the service is
// started with; installers write it to C:\ProgramData\StateTrack\agent.yaml.
const serviceConfigPath = `C:\ProgramData\StateTrack\agent.yaml`

// serviceCommand implements `statetrack-agent service <install|start|stop|uninstall>`.
func serviceCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: statetrack-agent service <install|start|stop|uninstall>")
	}
	switch args[0] {
	case "install":
		return installService()
	case "start":
		return withService("start", func(s *mgr.Service) error { return s.Start() })
	case "stop":
		return withService("stop", stopService)
	case "uninstall":
		return uninstallService()
	default:
		return fmt.Errorf("unknown service command %q (want install|start|stop|uninstall)", args[0])
	}
}

// withService opens the named service and applies fn, mapping "service not
// found" to a friendly error.
func withService(action string, fn func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed (run `statetrack-agent service install`): %w", serviceName, err)
	}
	defer s.Close()
	if err := fn(s); err != nil {
		return fmt.Errorf("%s service %q: %w", action, serviceName, err)
	}
	fmt.Printf("%s: %s\n", action, serviceName)
	return nil
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists (run `statetrack-agent service uninstall` first)", serviceName)
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "StateTrack Agent",
		Description: "StateTrack infrastructure change-intelligence agent",
		StartType:   mgr.StartAutomatic,
	}, "-config", serviceConfigPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	s.Close()

	// Register an event-log source so the SCM records service lifecycle
	// messages under this service's name (best effort; non-fatal).
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Info|eventlog.Warning|eventlog.Error)

	fmt.Printf("installed service %q (%s)\n", serviceName, exe)
	fmt.Printf("  config: %s\n", serviceConfigPath)
	fmt.Printf("  start it with: statetrack-agent service start\n")
	return nil
}

func stopService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil // already stopped
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	// Wait (bounded) for the service to actually reach the stopped state.
	deadline := time.Now().Add(20 * time.Second)
	for {
		status, err = s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for the service to stop")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", serviceName, err)
	}
	defer s.Close()

	// Best effort: stop before removing.
	status, _ := s.Query()
	if status.State == svc.Running {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(20 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			status, _ = s.Query()
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	_ = eventlog.Remove(serviceName)
	fmt.Printf("uninstalled service %q\n", serviceName)
	return nil
}
