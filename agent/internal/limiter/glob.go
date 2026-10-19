package limiter

import (
	"fmt"
	"path"
	"strings"
)

// Matcher matches file paths and registry keys against glob patterns.
//
// Patterns use '/' as separator ('\' is accepted and normalised), support
// the path.Match syntax within a segment and "**" for any number of
// segments. A pattern without a separator (e.g. "*.log") matches the base
// name anywhere. Windows-style patterns and paths (drive letters, UNC paths,
// registry hives) and base-name patterns are matched case-insensitively.
type Matcher struct {
	rules []globRule
}

type globRule struct {
	pattern   string
	segs      []string // as written; used for Unix paths
	lowerSegs []string // used for Windows-style paths
	nameOnly  bool
	winOnly   bool // anchored Windows pattern; never matches Unix paths
}

// NewMatcher compiles patterns, rejecting malformed ones.
func NewMatcher(patterns ...string) (*Matcher, error) {
	m := &Matcher{}
	for _, p := range patterns {
		norm := strings.ReplaceAll(p, `\`, "/")
		r := globRule{pattern: p, winOnly: isWindowsStyle(norm)}
		if !strings.Contains(norm, "/") {
			r.nameOnly = true
			r.segs = []string{strings.ToLower(norm)}
		} else {
			r.segs = strings.Split(norm, "/")
		}
		r.lowerSegs = strings.Split(strings.ToLower(strings.Join(r.segs, "/")), "/")
		for _, s := range r.segs {
			if s == "**" {
				continue
			}
			if _, err := path.Match(s, ""); err != nil {
				return nil, fmt.Errorf("pattern %q: %w", p, err)
			}
		}
		m.rules = append(m.rules, r)
	}
	return m, nil
}

// MustMatcher is NewMatcher for static pattern lists.
func MustMatcher(patterns ...string) *Matcher {
	m, err := NewMatcher(patterns...)
	if err != nil {
		panic(err)
	}
	return m
}

// Match reports whether p matches any pattern.
func (m *Matcher) Match(p string) bool {
	_, ok := m.MatchPattern(p)
	return ok
}

// MatchPattern returns the first pattern matching p.
func (m *Matcher) MatchPattern(p string) (string, bool) {
	if m == nil || p == "" {
		return "", false
	}
	norm := strings.ReplaceAll(p, `\`, "/")
	win := isWindowsStyle(norm)
	if win {
		norm = strings.ToLower(norm)
	}
	segs := strings.Split(norm, "/")
	base := strings.ToLower(segs[len(segs)-1])
	for _, r := range m.rules {
		switch {
		case r.nameOnly:
			if ok, _ := path.Match(r.segs[0], base); ok {
				return r.pattern, true
			}
		case win:
			if matchSegs(r.lowerSegs, segs) {
				return r.pattern, true
			}
		case !r.winOnly:
			if matchSegs(r.segs, segs) {
				return r.pattern, true
			}
		}
	}
	return "", false
}

func matchSegs(pat, p []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			pat = pat[1:]
			if len(pat) == 0 {
				return true
			}
			for i := 0; i <= len(p); i++ {
				if matchSegs(pat, p[i:]) {
					return true
				}
			}
			return false
		}
		if len(p) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], p[0]); !ok {
			return false
		}
		pat, p = pat[1:], p[1:]
	}
	return len(p) == 0
}

// isWindowsStyle reports drive-letter paths, UNC paths and registry keys.
// Backslashes are normalised to forward slashes first so callers can pass
// either separator form.
func isWindowsStyle(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) >= 2 && p[1] == ':' && (p[0]|0x20) >= 'a' && (p[0]|0x20) <= 'z' {
		return true
	}
	if strings.HasPrefix(p, "//") {
		return true
	}
	up := strings.ToUpper(p)
	return strings.HasPrefix(up, "HKLM/") || strings.HasPrefix(up, "HKCU/") ||
		strings.HasPrefix(up, "HKU/") || strings.HasPrefix(up, "HKCR/") || strings.HasPrefix(up, "HKEY_")
}
