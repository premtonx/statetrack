package discovery

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// maxConfigBytes bounds how much of a config file a probe will read, so a
// stray multi-gigabyte file can never stall the scanner.
const maxConfigBytes = 4 << 20 // 4 MiB

// maxWalkDepth bounds how deep a probe walks a config root.
const maxWalkDepth = 4

// readFileLimited reads at most maxConfigBytes of path. A missing or
// unreadable file returns (nil, false) rather than an error: discovery is
// best-effort.
func readFileLimited(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes))
	if err != nil && len(b) == 0 {
		return nil, false
	}
	return b, true
}

// dirExists reports whether path is an existing directory.
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// fileExists reports whether path is an existing regular file.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// globFiles expands one glob pattern, tolerating a malformed pattern.
func globFiles(pattern string) []string {
	m, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return m
}

// walkConfigFiles walks root collecting files matching one of the extensions,
// bounded by depth and max files, skipping obvious noise directories. An empty
// extension list collects every regular file.
//
// The file cap is enforced during the walk rather than after it: a probe must
// never stat fifty thousand files on a busy volume just to discard 49,970 of
// them, because discovery shares the host with the collection pipeline.
func walkConfigFiles(root string, depth int, exts []string, maxFiles int) []string {
	root = strings.TrimSpace(root)
	if root == "" || !dirExists(root) {
		return nil
	}
	if depth <= 0 || depth > maxWalkDepth {
		depth = 1
	}
	if maxFiles <= 0 {
		maxFiles = defaultWalkFiles
	}
	var out []string
	base := strings.Count(filepath.Clean(root), string(filepath.Separator))
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if len(out) >= maxFiles {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p != root && strings.Count(filepath.Clean(p), string(filepath.Separator))-base >= depth {
				return filepath.SkipDir
			}
			switch d.Name() {
			case ".git", "node_modules", "cache", "Cache", "logs", "Logs", "tmp", "temp", "packages":
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(exts) > 0 && !hasExt(p, exts) {
			return nil
		}
		out = append(out, p)
		return nil
	})
	sort.Strings(out)
	return out
}

// hasExt reports whether p has one of the extensions (case-insensitive).
func hasExt(p string, exts []string) bool {
	got := filepath.Ext(p)
	for _, e := range exts {
		if strings.EqualFold(got, e) {
			return true
		}
	}
	return false
}

// expandVars expands %WINDIR%-style placeholders plus Go's $VAR / ${VAR} forms,
// leaving an unset variable's placeholder in place so the pattern matches
// nothing rather than matching a bare "\System32\...".
//
// Leaving an unset variable inert (rather than collapsing it to "") is
// deliberate: "%RABBITMQ_BASE%\advanced.config" must not become
// "\advanced.config", a relative path that could match an unrelated file.
func expandVars(p string) string {
	if !strings.ContainsAny(p, "%$") {
		return p
	}
	parts := strings.Split(p, "%")
	if len(parts) > 2 {
		var b strings.Builder
		b.WriteString(parts[0])
		for i := 1; i < len(parts); i++ {
			if i%2 == 1 {
				if v := os.Getenv(parts[i]); v != "" {
					b.WriteString(v)
				} else {
					// Unset: keep the placeholder so the glob is inert.
					b.WriteString("%" + parts[i] + "%")
				}
			} else {
				b.WriteString(parts[i])
			}
		}
		p = b.String()
	}
	return os.ExpandEnv(p)
}

// parseListenPort extracts a TCP port from an nginx/apache listen argument
// such as "443", "443 ssl", "[::]:443", "127.0.0.1:8080" or "*:80".
func parseListenPort(arg string) int {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return 0
	}
	// Drop trailing protocol flags ("default_server", "ssl", ...).
	if i := strings.IndexByte(arg, ' '); i >= 0 {
		arg = arg[:i]
	}
	// Strip an IPv6 bracket or host prefix, leaving the port.
	if i := strings.LastIndexByte(arg, ':'); i >= 0 {
		arg = arg[i+1:]
	}
	p, err := strconv.Atoi(strings.TrimSpace(arg))
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}
