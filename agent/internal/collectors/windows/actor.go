package windows

import (
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// Attribution methods reported in event metadata.
const (
	AttrUnattributed  = "unattributed"
	AttrSecurityAudit = "security_audit"
	AttrEventLog      = "eventlog"
)

// Account is a resolved Windows identity.
type Account struct {
	SID      string
	Username string // DOMAIN\user, NT AUTHORITY\SYSTEM, ...
}

// ActorContext builds the actor for a change from a resolved account.
// procName and pid are optional; pid 0 means unknown. Windows has no
// separate "original human before sudo" concept: the account behind the
// change (subject SID) is itself the login identity.
func ActorContext(a Account, procName string, pid uint32) *pb.ActorContext {
	if a.SID == "" && a.Username == "" {
		return nil
	}
	u := a.Username
	if u == "" {
		u = a.SID
	}
	return &pb.ActorContext{
		Username:      u,
		UidOrSid:      a.SID,
		LoginUid:      a.SID,
		LoginUsername: u,
		Pid:           pid,
		ProcessName:   procName,
	}
}

// ActorFromSID resolves a SID into an actor; unknown SIDs are surfaced as
// the raw SID so the event is still attributable.
func ActorFromSID(sid string, resolve func(string) (Account, bool), procName string, pid uint32) *pb.ActorContext {
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return nil
	}
	a := Account{SID: sid}
	if resolve != nil {
		if r, ok := resolve(sid); ok {
			a = r
		}
	}
	return ActorContext(a, procName, pid)
}

// Attributor attributes file and registry changes from Security audit notes
// (4663 object access, 4657 registry value change).
type Attributor struct {
	Notes   *Notes
	Resolve func(string) (Account, bool)
}

// Attribute returns the actor for a path from the most recent audit note.
func (a Attributor) Attribute(path string, now time.Time) (*pb.ActorContext, string) {
	if a.Notes == nil {
		return nil, AttrUnattributed
	}
	n, ok := a.Notes.Lookup(path, now)
	if !ok {
		return nil, AttrUnattributed
	}
	acct := Account{SID: n.SID, Username: n.Account}
	if acct.Username == "" && acct.SID != "" && a.Resolve != nil {
		if r, ok := a.Resolve(n.SID); ok {
			acct.Username = r.Username
		}
	}
	return ActorContext(acct, procBase(n.Process), n.PID), AttrSecurityAudit
}

// procBase returns the file name of an image path ("C:\Windows\regedit.exe"
// -> "regedit.exe").
//
// The separator is split by hand rather than with filepath.Base: the collectors
// are Windows-only in production, but their tests run on the Linux CI runners,
// where filepath.Base treats `\` as an ordinary character and returns the whole
// `C:\Windows\notepad.exe`. That made the suite pass on Windows and fail in CI.
func procBase(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
