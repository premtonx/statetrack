// Command statetrack-agent is the StateTrack host agent.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/statetrack/statetrack/agent/internal/app"
)

var version = "dev"

// memoryLimit is the soft Go heap limit (spec: < 25 MB RSS).
const memoryLimit = 25 * 1024 * 1024

func main() {
	// `statetrack-agent service ...` manages the native service (Windows SCM
	// on Windows; a clear error elsewhere). Handled before flag parsing so
	// service admins never need to know the agent's runtime flags.
	if len(os.Args) > 1 && os.Args[1] == "service" {
		if err := serviceCommand(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "service:", err)
			os.Exit(1)
		}
		return
	}

	configPath := flag.String("config", "", "path to agent.yaml (default: STATETRACK_CONFIG or the OS default)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("statetrack-agent", version)
		return
	}

	debug.SetMemoryLimit(memoryLimit)
	level := new(slog.LevelVar)
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})).With("version", version)
	slog.SetDefault(log)

	// run is OS-specific: a Windows service wrapper on Windows, a
	// SIGINT/SIGTERM handler elsewhere (run_windows.go / run_other.go).
	if err := run(app.Options{ConfigPath: *configPath, Logger: log, LogLevel: level, AgentVersion: version}); err != nil {
		log.Error("agent failed", "err", err)
		os.Exit(1)
	}
}
