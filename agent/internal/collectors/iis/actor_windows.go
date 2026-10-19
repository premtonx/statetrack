//go:build windows

package iis

import (
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// DefaultActorWindow is how recently a management process must have started for
// it to be attributed as the author of a detected change.
//
// Fifteen seconds is deliberate. IIS configuration edits are detected by polling
// on the next tick, so the window has to be a little wider than the interval's
// *latency*, not its period: a pool stopped two minutes ago by an operator who
// has since closed IIS Manager should not be attributed to whatever short-lived
// process happens to start now.
const DefaultActorWindow = 20 * time.Second

// managerImages are the binaries that change IIS configuration in practice.
//
// Ordered by specificity: InetMgr and appcmd are unambiguous, powershell is not
// but is how a change is scripted, and notepad is how applicationHost.config is
// hand-edited on a host where nobody installed the management console.
var managerImages = []struct {
	exe   string
	label string
}{
	{"appcmd.exe", "appcmd.exe"},
	{"inetsrv\\appcmd.exe", "appcmd.exe"},
	{"inetsrv\\wmsvc.exe", "wmsvc.exe"},
	{"inetmgr.exe", "InetMgr.exe"},
	{"mmc.exe", "InetMgr.exe"},
	{"powershell.exe", "powershell.exe"},
	{"pwsh.exe", "pwsh.exe"},
	{"notepad.exe", "notepad.exe"},
}

// AttributeRecentManager names the actor behind an IIS change from the most
// recently started management process.
//
// Windows has no equivalent of Linux's audit connector for a configuration file
// that a GUI tool rewrites, and the Security log's 4663 records only exist where
// an operator has configured object-access auditing on applicationHost.config —
// which is the exception, not the rule. Process start times are the one signal
// that is always available, and they are enough for the question the timeline
// answers: "did a human do this in IIS Manager, or did a script?"
//
// The returned method string is reported as event metadata so a reviewer can
// see how the attribution was made.
func AttributeRecentManager(now time.Time, window time.Duration) (*pb.ActorContext, string) {
	if window <= 0 {
		window = DefaultActorWindow
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, ""
	}
	defer windows.CloseHandle(snap)

	self := uint32(windows.GetCurrentProcessId())
	entry := windows.ProcessEntry32{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	var (
		best      *pb.ActorContext
		bestStart time.Time
	)
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if entry.ProcessID == 0 || entry.ProcessID == self {
			continue
		}
		exe := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		label := ""
		for _, m := range managerImages {
			if exe == m.exe || strings.HasSuffix(exe, "\\"+m.exe) {
				label = m.label
				break
			}
		}
		if label == "" {
			continue
		}
		started, ok := processStart(entry.ProcessID)
		if !ok || now.Sub(started) > window || started.After(now) {
			continue
		}
		if best == nil || started.After(bestStart) {
			bestStart = started
			best = &pb.ActorContext{
				Pid:         entry.ProcessID,
				Ppid:        entry.ParentProcessID,
				ProcessName: label,
				Cmdline:     windows.UTF16ToString(entry.ExeFile[:]),
			}
		}
	}
	if best == nil {
		return nil, ""
	}
	// The account running the process is the acting identity; resolving it via
	// the token is what turns "appcmd.exe" into "CORP\Administrator (appcmd.exe)".
	if user, sid, ok := processOwner(best.Pid); ok {
		best.Username = user
		best.UidOrSid = sid
		best.LoginUsername = user
		best.LoginUid = sid
	}
	return best, "iis_management_process"
}

// processStart reads a process's creation time.
func processStart(pid uint32) (time.Time, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}, false
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, creation.Nanoseconds()), true
}

// processOwner resolves the account a process runs as.
func processOwner(pid uint32) (user, sid string, ok bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", "", false
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", "", false
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil || tu == nil || tu.User.Sid == nil {
		return "", "", false
	}
	sid = tu.User.Sid.String()
	name, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil || name == "" {
		return "", sid, true
	}
	if domain != "" {
		name = domain + `\` + name
	}
	return name, sid, true
}
