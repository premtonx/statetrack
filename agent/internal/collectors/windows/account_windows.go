//go:build windows

package windows

import (
	"golang.org/x/sys/windows"
)

// ResolveAccount resolves a SID string to DOMAIN\user via LookupAccountSid.
// Well-known SIDs resolve to their canonical names (S-1-5-18 -> NT
// AUTHORITY\SYSTEM).
func ResolveAccount(sid string) (Account, bool) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return Account{}, false
	}
	user, domain, _, err := s.LookupAccount("")
	if err != nil {
		return Account{}, false
	}
	if domain != "" {
		user = domain + `\` + user
	}
	return Account{SID: sid, Username: user}, true
}
