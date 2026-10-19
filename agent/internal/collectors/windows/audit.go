package windows

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Security log event IDs used for attribution. They are only logged when
// object-access auditing is enabled (auditpol "Registry" / "File System")
// and the objects carry auditing SACLs.
const (
	SecurityProvider    = "Microsoft-Windows-Security-Auditing"
	EventRegistryValue  = 4657 // a registry value was modified
	EventObjectAccess   = 4663 // an attempt was made to access an object
	accessWriteDataMask = 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000
)

// AuditNote is who touched an object, from a Security audit record. The
// record's old/new values are deliberately not kept: they may be secrets.
type AuditNote struct {
	Kind    string // "registry" or "file"
	Path    string // HKLM\... or C:\...
	Value   string // registry value name (4657)
	SID     string
	Account string // DOMAIN\user as logged
	LogonID string
	PID     uint32
	Process string // full image path
	At      time.Time
}

// ParseAudit decodes 4657/4663 records. ccs is the CurrentControlSet number
// (HKLM\SYSTEM\Select\Current) used to map ControlSet00N keys.
func ParseAudit(ev Event, ccs int) (AuditNote, bool) {
	if ev.Provider != SecurityProvider {
		return AuditNote{}, false
	}
	d := ev.Data
	n := AuditNote{SID: d["SubjectUserSid"], LogonID: d["SubjectLogonId"], Process: d["ProcessName"],
		At: ev.When(time.Now())}
	if u := d["SubjectUserName"]; u != "" {
		n.Account = u
		if dom := d["SubjectDomainName"]; dom != "" {
			n.Account = dom + `\` + u
		}
	}
	if pid, err := strconv.ParseUint(strings.TrimSpace(d["ProcessId"]), 0, 32); err == nil {
		n.PID = uint32(pid)
	}
	switch ev.ID {
	case EventRegistryValue:
		p, ok := NormalizeKernelKey(d["ObjectName"], ccs)
		if !ok {
			return AuditNote{}, false
		}
		n.Kind, n.Path, n.Value = "registry", p, d["ObjectValueName"]
	case EventObjectAccess:
		switch d["ObjectType"] {
		case "Key":
			p, ok := NormalizeKernelKey(d["ObjectName"], ccs)
			if !ok {
				return AuditNote{}, false
			}
			n.Kind, n.Path = "registry", p
		case "File":
			name := d["ObjectName"]
			if len(name) < 3 || name[1] != ':' {
				return AuditNote{}, false // \Device\... paths are not mapped
			}
			if mask, err := strconv.ParseUint(strings.TrimSpace(d["AccessMask"]), 0, 32); err == nil && mask&accessWriteDataMask == 0 {
				return AuditNote{}, false // read access
			}
			n.Kind, n.Path = "file", name
		default:
			return AuditNote{}, false
		}
	default:
		return AuditNote{}, false
	}
	return n, true
}

// NormalizeKernelKey maps \REGISTRY\MACHINE\... to HKLM\... and
// \REGISTRY\USER\<sid>\... to HKU\<sid>\..., with ControlSet00<ccs>
// shown as CurrentControlSet.
func NormalizeKernelKey(name string, ccs int) (string, bool) {
	up := strings.ToUpper(name)
	var p string
	switch {
	case strings.HasPrefix(up, `\REGISTRY\MACHINE\`):
		p = `HKLM\` + name[len(`\REGISTRY\MACHINE\`):]
	case strings.HasPrefix(up, `\REGISTRY\USER\`):
		p = `HKU\` + name[len(`\REGISTRY\USER\`):]
	default:
		return "", false
	}
	if ccs > 0 {
		cs := `HKLM\SYSTEM\ControlSet` + leftPad(strconv.Itoa(ccs), 3) + `\`
		if strings.HasPrefix(strings.ToUpper(p), strings.ToUpper(cs)) {
			p = `HKLM\SYSTEM\CurrentControlSet\` + p[len(cs):]
		}
	}
	return strings.TrimSuffix(p, `\`), true
}

func leftPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

// DefaultNoteTTL is how long an audit note may attribute a later change.
const DefaultNoteTTL = 10 * time.Second

// Notes keeps recent audit notes by object path. Safe for concurrent use.
type Notes struct {
	TTL time.Duration

	mu sync.Mutex
	m  map[string]AuditNote
}

func noteKey(p string) string { return strings.ToLower(strings.TrimSuffix(p, `\`)) }

// Add records n, replacing older notes for the same path.
func (s *Notes) Add(n AuditNote) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string]AuditNote)
	}
	s.m[noteKey(n.Path)] = n
}

// Lookup returns the latest note for path younger than TTL at now.
func (s *Notes) Lookup(path string, now time.Time) (AuditNote, bool) {
	ttl := s.TTL
	if ttl <= 0 {
		ttl = DefaultNoteTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[noteKey(path)]
	if !ok || now.Sub(n.At) > ttl || n.At.Sub(now) > ttl {
		return AuditNote{}, false
	}
	return n, true
}

// Sweep drops expired notes.
func (s *Notes) Sweep(now time.Time) {
	ttl := s.TTL
	if ttl <= 0 {
		ttl = DefaultNoteTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, n := range s.m {
		if now.Sub(n.At) > ttl {
			delete(s.m, k)
		}
	}
}

// Len reports the number of notes.
func (s *Notes) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
