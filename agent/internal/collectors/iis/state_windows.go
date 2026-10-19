//go:build windows

package iis

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// appcmdPath is IIS's administrative CLI. It ships in %WINDIR%\System32\inetsrv
// and is on PATH for an elevated process, but the absolute path is used anyway:
// a service account's PATH is not the operator's PATH, and a security product
// that shadows `appcmd` must not be able to redirect the query.
const appcmdPath = `C:\Windows\System32\inetsrv\appcmd.exe`

// queryStates enumerates application pools and sites and asks the runtime for
// each one's state.
//
// This is a read-only query: `list` never mutates configuration. The two calls
// are also the only way to see a pool that has *stopped* — the state is held in
// the WAS process, not in applicationHost.config — which is the whole reason
// this collector exists.
func queryStates(ctx context.Context) (map[string]string, error) {
	out := make(map[string]string)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if names, err := listNames(ctx, "list", "apppool"); err == nil {
		for _, name := range names {
			if state := poolState(ctx, name); state != "" {
				out[name] = state
			}
		}
	} else {
		return nil, err
	}

	// Site state is best-effort: a host may watch pools only, and a failing
	// site query must not discard the pool states already collected.
	if names, err := listNames(ctx, "list", "site"); err == nil {
		for _, name := range names {
			if state := siteState(ctx, name); state != "" {
				out[name] = state
			}
		}
	}
	return out, nil
}

// listNames parses `appcmd list apppool` / `list site` output.
//
// The format is "APPPOOL \"name\" (state,...)" / "SITE \"name\" (state,...)".
// Only the quoted name is needed; the parenthesised tail is parsed separately
// by the state queries, so a future appcmd version adding fields cannot break
// the name extraction.
func listNames(ctx context.Context, args ...string) ([]string, error) {
	raw, err := runAppcmd(ctx, args...)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if name, ok := quoted(strings.TrimSpace(line)); ok {
			out = append(out, name)
		}
	}
	return out, nil
}

// poolState reads one pool's runtime state.
func poolState(ctx context.Context, name string) string {
	raw, err := runAppcmd(ctx, "list", "apppool", name)
	if err != nil {
		return ""
	}
	return stateFromLine(raw)
}

// siteState reads one site's runtime state.
func siteState(ctx context.Context, name string) string {
	raw, err := runAppcmd(ctx, "list", "site", name)
	if err != nil {
		return ""
	}
	return stateFromLine(raw)
}

// stateFromLine extracts the first known state word from an appcmd line.
//
// Matching against a closed set rather than "the first token in parentheses" is
// what keeps a pool named "Started" or a message like "(config invalid)" from
// being reported as a valid state.
func stateFromLine(raw string) string {
	for _, state := range []string{"Started", "Stopped", "Starting", "Stopping", "Unknown"} {
		if strings.Contains(raw, state) {
			return state
		}
	}
	return ""
}

// quoted returns the first double-quoted substring on a line.
func quoted(line string) (string, bool) {
	start := strings.IndexByte(line, '"')
	if start < 0 {
		return "", false
	}
	rest := line[start+1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// runAppcmd executes appcmd and returns its stdout.
func runAppcmd(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, appcmdPath, args...)
	// appcmd writes its listing to stdout and its errors to stderr; combining
	// them keeps a failure visible in the returned string when the exit code is
	// ignored by a caller that only wants a state word.
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return string(raw), err
	}
	return string(raw), nil
}
