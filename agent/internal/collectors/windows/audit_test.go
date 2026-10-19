package windows

import (
	"testing"
	"time"
)

func TestParseAuditRegistry4657(t *testing.T) {
	ev := parseXML(t, "Microsoft-Windows-Security-Auditing", 4657, "",
		`<Data Name="SubjectUserSid">S-1-5-21-1-2-3</Data>`+
			`<Data Name="SubjectUserName">alice</Data>`+
			`<Data Name="SubjectDomainName">CORP</Data>`+
			`<Data Name="SubjectLogonId">0x1234</Data>`+
			`<Data Name="ProcessId">0x1a2</Data>`+
			`<Data Name="ProcessName">C:\Windows\regedit.exe</Data>`+
			`<Data Name="ObjectName">\REGISTRY\MACHINE\SOFTWARE\Foo\Bar</Data>`+
			`<Data Name="ObjectValueName">Password</Data>`+
			`<Data Name="OldValueType">REG_SZ</Data>`+
			`<Data Name="NewValueType">REG_SZ</Data>`)
	n, ok := ParseAudit(ev, 1)
	if !ok {
		t.Fatal("ParseAudit returned not-ok")
	}
	if n.Kind != "registry" || n.Path != `HKLM\SOFTWARE\Foo\Bar` || n.Value != "Password" {
		t.Fatalf("note = %+v", n)
	}
	if n.SID != "S-1-5-21-1-2-3" || n.Account != `CORP\alice` || n.PID != 0x1a2 {
		t.Fatalf("note = %+v", n)
	}
}

func TestParseAuditObjectAccessFile(t *testing.T) {
	write := parseXML(t, "Microsoft-Windows-Security-Auditing", 4663, "",
		`<Data Name="ObjectType">File</Data>`+
			`<Data Name="ObjectName">C:\Windows\System32\inetsrv\config\applicationHost.config</Data>`+
			`<Data Name="AccessMask">0x2</Data>`+
			`<Data Name="SubjectUserSid">S-1-5-21-1-2-3</Data>`)
	if n, ok := ParseAudit(write, 1); !ok || n.Kind != "file" {
		t.Fatalf("write note = %+v, ok=%v", n, ok)
	}

	read := parseXML(t, "Microsoft-Windows-Security-Auditing", 4663, "",
		`<Data Name="ObjectType">File</Data>`+
			`<Data Name="ObjectName">C:\Windows\System32\inetsrv\config\applicationHost.config</Data>`+
			`<Data Name="AccessMask">0x1</Data>`+
			`<Data Name="SubjectUserSid">S-1-5-21-1-2-3</Data>`)
	if _, ok := ParseAudit(read, 1); ok {
		t.Fatal("read-only access should be ignored")
	}
}

func TestNormalizeKernelKey(t *testing.T) {
	got, ok := NormalizeKernelKey(`\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\BITS`, 1)
	if !ok || got != `HKLM\SYSTEM\CurrentControlSet\Services\BITS` {
		t.Fatalf("NormalizeKernelKey = %q, ok=%v", got, ok)
	}
	if got, ok := NormalizeKernelKey(`\REGISTRY\MACHINE\SOFTWARE\Foo`, 1); !ok || got != `HKLM\SOFTWARE\Foo` {
		t.Fatalf("NormalizeKernelKey = %q", got)
	}
	if _, ok := NormalizeKernelKey(`\Device\HarddiskVolume1\foo`, 1); ok {
		t.Fatal("device paths should not normalize")
	}
}

func TestNotesLookupTTL(t *testing.T) {
	s := &Notes{TTL: 2 * time.Second}
	now := time.Now()
	s.Add(AuditNote{Path: `HKLM\SOFTWARE\Foo`, Account: `CORP\alice`, At: now})

	if n, ok := s.Lookup(`HKLM\SOFTWARE\Foo`, now.Add(time.Second)); !ok || n.Account != `CORP\alice` {
		t.Fatalf("lookup within TTL = %+v, ok=%v", n, ok)
	}
	if _, ok := s.Lookup(`HKLM\SOFTWARE\Foo`, now.Add(3*time.Second)); ok {
		t.Fatal("lookup after TTL should fail")
	}
	s.Add(AuditNote{Path: `HKLM\SOFTWARE\Foo`, At: now})
	s.Sweep(now.Add(3 * time.Second))
	if s.Len() != 0 {
		t.Fatalf("sweep left %d notes", s.Len())
	}
}
