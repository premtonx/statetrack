// Package redact implements StateTrack's deterministic secret scrubber.
//
// Detected secret values are replaced in place with a stub of the form
// [REDACTED:sha256:<8 hex>], derived from an HMAC-SHA256 of the secret under a
// per-installation salt. The same secret always yields the same stub, so a
// reviewer can see that a credential changed (or did not) without the
// credential ever leaving the host. Everything around the secret (keys,
// separators, quotes, comments, line endings and the number of lines) is
// preserved so diffs stay readable.
//
// Prefer scrubbing file contents with [Scrubber.Text] before diffing; this
// lets multi-line secrets such as PEM private keys be recognised as a block.
// [Scrubber.UnifiedDiff] is available for diffs that were produced elsewhere.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
)

const stubPrefix = "[REDACTED:sha256:"

// keywords that mark the following assignment value as a secret.
const keywords = `password|passwd|secret|api[_-]?key|token|private[_-]?key`

var (
	// KEY = value / KEY: value / "key": "value" / key := value.
	// The unquoted form runs to the next delimiter, comment or end of line so
	// that space-separated passphrases are covered entirely.
	keyValueRe = regexp.MustCompile(
		`(?i)([\w.-]*(?:` + keywords + `)[\w.-]*["']?\s*(?::=|[:=])\s*)` +
			`(?:"([^"]*)"|'([^']*)'|([^\s"',;&]+(?:[ \t]+[^\s"',;&#]+)*))`)

	// <add key="DbPassword" value="..."/> (web.config / app.config appSettings).
	xmlKeyValueRe = regexp.MustCompile(
		`(?i)(\bkey\s*=\s*"[^"]*(?:` + keywords + `)[^"]*"\s+value\s*=\s*")([^"]*)"`)

	// scheme://user:password@host
	urlCredsRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)@`)

	// Authorization: Bearer <token>
	bearerRe = regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._~+/-]{8,}=*)`)

	// AWS access key IDs.
	awsKeyIDRe = regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`)

	// OpenSSH public keys are high entropy but not secret.
	sshPublicKeyRe = regexp.MustCompile(`(?:^|\s)(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+@openssh\.com)\s+AAAA`)

	pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	pemEndRe   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
)

const (
	entropyMinLen    = 24
	entropyThreshold = 4.0 // bits per character
)

type rule struct {
	re *regexp.Regexp
	// submatch indexes that may hold the secret; the first one that
	// participated in the match is redacted.
	groups []int
	// cheap substring prefilter on the line and its lower-cased form; the
	// regexp only runs when it returns true.
	hint func(line, lower string) bool
	// optional veto for a match (m holds submatch indexes into line).
	reject func(line string, m []int) bool
}

// sudoers tags (NOPASSWD:, PASSWD:) and nsswitch.conf's "passwd:" database
// are not credentials.
func isPasswdDirective(line string, m []int) bool {
	prefix := line[m[2]:m[3]]
	key := strings.ToLower(strings.TrimRight(prefix, " \t:\"'"))
	return strings.Contains(prefix, ":") && !strings.Contains(prefix, "=") &&
		(key == "passwd" || key == "nopasswd")
}

var lineRules = []rule{
	{re: xmlKeyValueRe, groups: []int{2}, hint: func(_, l string) bool {
		return strings.Contains(l, "value") && hasKeyword(l)
	}},
	{re: keyValueRe, groups: []int{2, 3, 4}, hint: func(_, l string) bool { return hasKeyword(l) }, reject: isPasswdDirective},
	{re: urlCredsRe, groups: []int{2}, hint: func(line, _ string) bool { return strings.Contains(line, "://") }},
	{re: bearerRe, groups: []int{2}, hint: func(_, l string) bool { return strings.Contains(l, "bearer") }},
	{re: awsKeyIDRe, groups: []int{1}, hint: func(line, _ string) bool {
		return strings.Contains(line, "AKIA") || strings.Contains(line, "ASIA") ||
			strings.Contains(line, "ABIA") || strings.Contains(line, "ACCA")
	}},
}

// hasKeyword is a superset prefilter for the keywords pattern.
func hasKeyword(lower string) bool {
	return strings.Contains(lower, "passw") || strings.Contains(lower, "secret") ||
		strings.Contains(lower, "api") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "private")
}

// Scrubber replaces secrets with salted, deterministic stubs.
// It is safe for concurrent use.
type Scrubber struct {
	salt []byte
}

// New returns a Scrubber keyed by salt. Use a stable, per-installation random
// salt: the same salt must be used everywhere stubs are compared.
func New(salt []byte) *Scrubber {
	return &Scrubber{salt: append([]byte(nil), salt...)}
}

// Stub returns the redaction marker for secret.
func (s *Scrubber) Stub(secret string) string {
	mac := hmac.New(sha256.New, s.salt)
	mac.Write([]byte(secret))
	sum := mac.Sum(nil)
	return stubPrefix + hex.EncodeToString(sum[:4]) + "]"
}

// IsStub reports whether v is a redaction marker produced by a Scrubber.
func IsStub(v string) bool {
	return len(v) == len(stubPrefix)+9 && strings.HasPrefix(v, stubPrefix) && v[len(v)-1] == ']'
}

// Line scrubs a single line (without multi-line PEM detection).
func (s *Scrubber) Line(line string) string {
	lower := strings.ToLower(line)
	for _, r := range lineRules {
		if r.hint(line, lower) {
			line = s.apply(line, r)
		}
	}
	if !strings.Contains(line, " AAAA") || !sshPublicKeyRe.MatchString(line) {
		line = s.redactHighEntropy(line)
	}
	return line
}

// Text scrubs file content, preserving line count and line endings.
func (s *Scrubber) Text(text string) string {
	return s.scrubLines(text, false)
}

// UnifiedDiff scrubs a unified diff. Diff markers ('+', '-', ' ') are kept and
// file/hunk header lines are left untouched.
func (s *Scrubber) UnifiedDiff(diff string) string {
	return s.scrubLines(diff, true)
}

func (s *Scrubber) scrubLines(text string, diffMode bool) string {
	if text == "" {
		return text
	}
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	type parsed struct {
		marker, body, eol string
		header            bool
	}
	ps := make([]parsed, len(lines))
	for i, l := range lines {
		var p parsed
		p.body, p.eol = splitEOL(l)
		if diffMode {
			switch {
			case strings.HasPrefix(p.body, "--- "), strings.HasPrefix(p.body, "+++ "),
				strings.HasPrefix(p.body, "@@"), strings.HasPrefix(p.body, `\`):
				p.header = true
			case p.body != "" && strings.ContainsRune("+- ", rune(p.body[0])):
				p.marker, p.body = p.body[:1], p.body[1:]
			}
		}
		ps[i] = p
	}

	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(ps); i++ {
		p := ps[i]
		if p.header {
			b.WriteString(p.body + p.eol)
			continue
		}
		if pemBeginRe.MatchString(p.body) {
			// Collect the key body up to the END line (or the end of input,
			// for truncated blocks) and give every body line the stub of the
			// whole block, keeping the line count intact.
			end := i + 1
			var block strings.Builder
			for ; end < len(ps) && !pemEndRe.MatchString(ps[end].body); end++ {
				if !ps[end].header {
					block.WriteString(strings.TrimSpace(ps[end].body))
				}
			}
			stub := s.Stub(block.String())
			b.WriteString(p.marker + p.body + p.eol)
			for j := i + 1; j < end; j++ {
				q := ps[j]
				if q.header {
					b.WriteString(q.body + q.eol)
					continue
				}
				indent := q.body[:len(q.body)-len(strings.TrimLeft(q.body, " \t"))]
				b.WriteString(q.marker + indent + stub + q.eol)
			}
			if end < len(ps) {
				b.WriteString(ps[end].marker + ps[end].body + ps[end].eol)
			}
			i = end
			continue
		}
		b.WriteString(p.marker + s.Line(p.body) + p.eol)
	}
	return b.String()
}

func (s *Scrubber) apply(line string, r rule) string {
	matches := r.re.FindAllStringSubmatchIndex(line, -1)
	if matches == nil {
		return line
	}
	var b strings.Builder
	last, changed := 0, false
	for _, m := range matches {
		if r.reject != nil && r.reject(line, m) {
			continue
		}
		for _, g := range r.groups {
			start, end := m[2*g], m[2*g+1]
			if start < 0 || start == end {
				continue
			}
			secret := line[start:end]
			if strings.HasPrefix(secret, stubPrefix) {
				break
			}
			b.WriteString(line[last:start])
			b.WriteString(s.Stub(secret))
			last, changed = end, true
			break
		}
	}
	if !changed {
		return line
	}
	b.WriteString(line[last:])
	return b.String()
}

// redactHighEntropy replaces random-looking runs of base64/base64url
// characters (plus up to two '=' padding characters).
func (s *Scrubber) redactHighEntropy(line string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(line); {
		if !isTokenChar(line[i]) {
			i++
			continue
		}
		start := i
		for i < len(line) && isTokenChar(line[i]) {
			i++
		}
		end := i
		for pad := 0; pad < 2 && end < len(line) && line[end] == '='; pad++ {
			end++
		}
		if tok := line[start:end]; isHighEntropySecret(tok) {
			if b.Len() == 0 {
				b.Grow(len(line))
			}
			b.WriteString(line[last:start])
			b.WriteString(s.Stub(tok))
			last = end
		}
		i = end
	}
	if last == 0 {
		return line
	}
	b.WriteString(line[last:])
	return b.String()
}

func isTokenChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '_' || c == '-'
}

func splitEOL(l string) (body, eol string) {
	switch {
	case strings.HasSuffix(l, "\r\n"):
		return l[:len(l)-2], "\r\n"
	case strings.HasSuffix(l, "\n"):
		return l[:len(l)-1], "\n"
	}
	return l, ""
}

// isHighEntropySecret flags long tokens that mix upper case, lower case and
// digits and look random. Pure hex (checksums) and single-case identifiers
// are deliberately not matched.
func isHighEntropySecret(tok string) bool {
	tok = strings.TrimRight(tok, "=")
	if len(tok) < entropyMinLen {
		return false
	}
	var upper, lower, digit bool
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit && shannonEntropy(tok) >= entropyThreshold
}

func shannonEntropy(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
