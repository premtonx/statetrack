package linux

import (
	"encoding/binary"
	"encoding/hex"
	"path"
	"strconv"
	"strings"
)

// Audit record types (linux/audit.h).
const (
	auditSyscall = 1300
	auditPath    = 1302
	auditCwd     = 1307
	auditExecve  = 1309
	auditEOE     = 1320
)

// AuditEvent is one assembled audit event (all records sharing a serial).
type AuditEvent struct {
	Serial  string
	Syscall int
	Success bool
	PID     uint32
	PPID    uint32
	UID     uint32 // euid
	AUID    uint32 // loginuid
	Comm    string
	Exe     string
	Args    []string
	Cwd     string
	// Paths are the absolute non-parent paths touched by the syscall.
	Paths []string
}

// ProcInfo converts the event to a resolver snapshot.
func (e *AuditEvent) ProcInfo() ProcInfo {
	return ProcInfo{PID: e.PID, PPID: e.PPID, UID: e.UID, LoginUID: e.AUID, Name: e.Comm, Exe: e.Exe,
		Args: e.Args, Cwd: e.Cwd, Source: "audit"}
}

// AuditAssembler groups audit records into events. Records of one event
// arrive consecutively and end with an EOE record; a record with a new
// serial also completes the previous event.
type AuditAssembler struct {
	cur   *AuditEvent
	paths []auditPathRec
}

type auditPathRec struct {
	name, nametype string
}

// Feed adds one record and returns any completed event.
func (a *AuditAssembler) Feed(typ uint16, data []byte) *AuditEvent {
	serial, body, ok := splitAuditHeader(string(data))
	if !ok {
		return nil
	}
	var done *AuditEvent
	if a.cur != nil && a.cur.Serial != serial {
		done = a.finish()
	}
	if typ == auditEOE {
		if a.cur != nil && a.cur.Serial == serial {
			return a.finish()
		}
		return done
	}
	if a.cur == nil {
		a.cur = &AuditEvent{Serial: serial, AUID: NoLoginUID}
	}
	kv := parseAuditFields(body)
	e := a.cur
	switch typ {
	case auditSyscall:
		e.Syscall, _ = strconv.Atoi(kv["syscall"])
		e.Success = kv["success"] == "yes"
		e.PID = parseUint32(kv["pid"])
		e.PPID = parseUint32(kv["ppid"])
		e.UID = parseUint32(kv["euid"])
		if v, ok := kv["auid"]; ok {
			e.AUID = parseUint32(v)
		}
		e.Comm = auditString(kv["comm"])
		e.Exe = auditString(kv["exe"])
	case auditExecve:
		n, _ := strconv.Atoi(kv["argc"])
		if n > 256 {
			n = 256
		}
		e.Args = e.Args[:0]
		for i := 0; i < n; i++ {
			v, ok := kv["a"+strconv.Itoa(i)]
			if !ok {
				break
			}
			e.Args = append(e.Args, auditString(v))
		}
	case auditCwd:
		e.Cwd = auditString(kv["cwd"])
	case auditPath:
		a.paths = append(a.paths, auditPathRec{name: auditString(kv["name"]), nametype: kv["nametype"]})
	}
	return done
}

func (a *AuditAssembler) finish() *AuditEvent {
	e := a.cur
	for _, p := range a.paths {
		if p.name == "" || p.nametype == "PARENT" {
			continue
		}
		name := p.name
		if !strings.HasPrefix(name, "/") {
			if e.Cwd == "" {
				continue
			}
			name = path.Join(e.Cwd, name)
		}
		e.Paths = append(e.Paths, path.Clean(name))
	}
	a.cur, a.paths = nil, nil
	return e
}

// splitAuditHeader splits "audit(1700000000.123:456): body".
func splitAuditHeader(s string) (serial, body string, ok bool) {
	s = strings.TrimRight(s, "\x00\n")
	if !strings.HasPrefix(s, "audit(") {
		return "", "", false
	}
	end := strings.Index(s, "):")
	if end < 0 {
		return "", "", false
	}
	stamp := s[len("audit("):end]
	_, serial, ok = strings.Cut(stamp, ":")
	return serial, strings.TrimSpace(s[end+2:]), ok
}

// parseAuditFields parses space-separated key=value pairs, where values may
// be double-quoted (and contain spaces).
func parseAuditFields(s string) map[string]string {
	m := make(map[string]string)
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			break
		}
		key := s[:eq]
		s = s[eq+1:]
		var val string
		if strings.HasPrefix(s, `"`) {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				val, s = s, ""
			} else {
				val, s = s[:end+2], s[end+2:]
			}
		} else if sp := strings.IndexByte(s, ' '); sp >= 0 {
			val, s = s[:sp], s[sp:]
		} else {
			val, s = s, ""
		}
		m[key] = val
	}
	return m
}

// auditString decodes an audit string value: "quoted", hex-encoded (used
// when the value contains spaces or control characters) or (null).
func auditString(v string) string {
	switch {
	case v == "" || v == "(null)":
		return ""
	case strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) && len(v) >= 2:
		return v[1 : len(v)-1]
	case len(v)%2 == 0:
		if b, err := hex.DecodeString(v); err == nil {
			return string(b)
		}
	}
	return v
}

func parseUint32(v string) uint32 {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return NoLoginUID
	}
	return uint32(n)
}

// Proc connector (linux/cn_proc.h) event types.
const (
	procEventExec = 0x00000002
	procEventExit = 0x80000000
)

// ConnectorEvent is a decoded proc connector notification.
type ConnectorEvent struct {
	Exec, Exit bool
	PID        uint32 // thread group ID (the process)
}

// ParseConnector decodes the cn_msg payload of one netlink message:
// struct cn_msg (20 bytes) followed by struct proc_event.
func ParseConnector(payload []byte) (ConnectorEvent, bool) {
	const cnMsgLen = 20
	// proc_event: what(4) cpu(4) timestamp(8) then the event union.
	if len(payload) < cnMsgLen+16+8 {
		return ConnectorEvent{}, false
	}
	ev := payload[cnMsgLen:]
	what := binary.NativeEndian.Uint32(ev[0:4])
	data := ev[16:]
	switch what {
	case procEventExec:
		// process_pid, process_tgid
		return ConnectorEvent{Exec: true, PID: binary.NativeEndian.Uint32(data[4:8])}, true
	case procEventExit:
		pid, tgid := binary.NativeEndian.Uint32(data[0:4]), binary.NativeEndian.Uint32(data[4:8])
		// Only the thread group leader's exit ends the process.
		return ConnectorEvent{Exit: pid == tgid, PID: tgid}, pid == tgid
	}
	return ConnectorEvent{}, false
}
