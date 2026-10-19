package windows

import (
	"testing"
	"time"
)

func TestActorContext(t *testing.T) {
	a := ActorContext(Account{SID: "S-1-5-18", Username: `NT AUTHORITY\SYSTEM`}, "svchost.exe", 900)
	if a == nil {
		t.Fatal("ActorContext returned nil")
	}
	if a.Username != `NT AUTHORITY\SYSTEM` || a.UidOrSid != "S-1-5-18" {
		t.Fatalf("actor = %+v", a)
	}
	if a.LoginUsername != a.Username || a.LoginUid != a.UidOrSid {
		t.Fatalf("login fields not mirrored: %+v", a)
	}
	if a.ProcessName != "svchost.exe" || a.Pid != 900 {
		t.Fatalf("actor = %+v", a)
	}
}

func TestActorContextEmpty(t *testing.T) {
	if ActorContext(Account{}, "", 0) != nil {
		t.Fatal("empty account should yield nil actor")
	}
}

func TestActorFromSID(t *testing.T) {
	resolve := func(sid string) (Account, bool) {
		if sid == "S-1-5-21-100" {
			return Account{SID: sid, Username: `CORP\alice`}, true
		}
		return Account{}, false
	}
	a := ActorFromSID("S-1-5-21-100", resolve, "", 0)
	if a.Username != `CORP\alice` || a.UidOrSid != "S-1-5-21-100" {
		t.Fatalf("actor = %+v", a)
	}

	// Unknown SID falls back to the raw SID string.
	b := ActorFromSID("S-1-5-21-999", resolve, "", 0)
	if b.Username != "S-1-5-21-999" || b.UidOrSid != "S-1-5-21-999" {
		t.Fatalf("actor = %+v", b)
	}

	if ActorFromSID("", resolve, "", 0) != nil {
		t.Fatal("empty SID should yield nil actor")
	}
}

func TestAttributorAttribute(t *testing.T) {
	notes := &Notes{TTL: 10 * time.Second}
	now := time.Now()
	notes.Add(AuditNote{
		Kind: "file", Path: `C:\etc\app.conf`, SID: "S-1-5-21-100", Account: `CORP\alice`,
		Process: `C:\Windows\notepad.exe`, PID: 4242, At: now,
	})
	attr := Attributor{Notes: notes}

	actor, method := attr.Attribute(`C:\etc\app.conf`, now.Add(time.Second))
	if actor == nil || actor.Username != `CORP\alice` || actor.ProcessName != "notepad.exe" || actor.Pid != 4242 {
		t.Fatalf("actor = %+v", actor)
	}
	if method != AttrSecurityAudit {
		t.Fatalf("method = %q", method)
	}

	if _, m := attr.Attribute(`C:\etc\other.conf`, now.Add(time.Second)); m != AttrUnattributed {
		t.Fatalf("unattributed method = %q", m)
	}
}

func TestAttributorResolvesSIDWhenNoAccount(t *testing.T) {
	notes := &Notes{TTL: 10 * time.Second}
	now := time.Now()
	notes.Add(AuditNote{Kind: "registry", Path: `HKLM\SOFTWARE\Foo`, SID: "S-1-5-21-100", At: now})
	attr := Attributor{Notes: notes, Resolve: func(sid string) (Account, bool) {
		return Account{SID: sid, Username: `CORP\alice`}, true
	}}
	actor, _ := attr.Attribute(`HKLM\SOFTWARE\Foo`, now.Add(time.Second))
	if actor == nil || actor.Username != `CORP\alice` {
		t.Fatalf("actor = %+v", actor)
	}
}
