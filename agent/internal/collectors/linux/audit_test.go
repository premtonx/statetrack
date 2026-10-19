package linux

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestAuditAssemblerSedRename(t *testing.T) {
	var a AuditAssembler
	recs := []struct {
		typ  uint16
		data string
	}{
		{auditSyscall, `audit(1760389316.120:4711): arch=c000003e syscall=82 success=yes exit=0 a0=7ffd a1=7ffe items=4 ppid=300 pid=600 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="sed" exe="/usr/bin/sed" key="statetrack"`},
		{auditExecve, `audit(1760389316.120:4711): argc=4 a0="sed" a1="-i" a2=732F38302F383038302F a3="default"`},
		{auditCwd, `audit(1760389316.120:4711): cwd="/etc/nginx/sites-enabled"`},
		{auditPath, `audit(1760389316.120:4711): item=0 name="/etc/nginx/sites-enabled/" inode=12 dev=fd:01 mode=040755 nametype=PARENT`},
		{auditPath, `audit(1760389316.120:4711): item=2 name="sedAb12Cd" inode=99 nametype=DELETE`},
		{auditPath, `audit(1760389316.120:4711): item=3 name="default" inode=99 nametype=CREATE`},
		{auditPath, `audit(1760389316.120:4711): item=4 name=(null) nametype=UNKNOWN`},
	}
	for _, r := range recs {
		if ev := a.Feed(r.typ, []byte(r.data)); ev != nil {
			t.Fatalf("event completed early: %+v", ev)
		}
	}
	ev := a.Feed(auditEOE, []byte("audit(1760389316.120:4711): \x00"))
	if ev == nil {
		t.Fatal("EOE did not complete the event")
	}
	want := &AuditEvent{
		Serial: "4711", Syscall: 82, Success: true, PID: 600, PPID: 300, UID: 0, AUID: 1000,
		Comm: "sed", Exe: "/usr/bin/sed", Args: []string{"sed", "-i", "s/80/8080/", "default"},
		Cwd:   "/etc/nginx/sites-enabled",
		Paths: []string{"/etc/nginx/sites-enabled/sedAb12Cd", "/etc/nginx/sites-enabled/default"},
	}
	if !reflect.DeepEqual(ev, want) {
		t.Fatalf("got  %+v\nwant %+v", ev, want)
	}
	pi := ev.ProcInfo()
	if pi.LoginUID != 1000 || pi.Source != "audit" || pi.Cwd != want.Cwd {
		t.Fatalf("ProcInfo %+v", pi)
	}
}

func TestAuditAssemblerNewSerialCompletesPrevious(t *testing.T) {
	var a AuditAssembler
	a.Feed(auditSyscall, []byte(`audit(1.0:1): syscall=59 success=yes pid=10 ppid=1 auid=4294967295 euid=0 comm="true" exe="/bin/true"`))
	ev := a.Feed(auditSyscall, []byte(`audit(1.0:2): syscall=59 success=yes pid=11 ppid=1 auid=0 euid=0 comm="ls" exe="/bin/ls"`))
	if ev == nil || ev.Serial != "1" || ev.PID != 10 || ev.AUID != NoLoginUID {
		t.Fatalf("got %+v", ev)
	}
	if ev := a.Feed(auditEOE, []byte(`audit(1.0:2): `)); ev == nil || ev.PID != 11 || ev.AUID != 0 {
		t.Fatalf("second: %+v", ev)
	}
	if a.Feed(auditSyscall, []byte("not an audit record")) != nil {
		t.Fatal("garbage produced an event")
	}
}

func TestAuditString(t *testing.T) {
	cases := map[string]string{
		`"plain"`:                "plain",
		"2F657463202F686F737473": "/etc /hosts",
		"(null)":                 "",
		"abc":                    "abc",
		"zz":                     "zz",
	}
	for in, want := range cases {
		if got := auditString(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestParseConnector(t *testing.T) {
	msg := func(what uint32, a, b uint32) []byte {
		buf := make([]byte, 20+16+16)
		binary.NativeEndian.PutUint32(buf[20:], what)
		binary.NativeEndian.PutUint32(buf[36:], a)
		binary.NativeEndian.PutUint32(buf[40:], b)
		return buf
	}
	if ev, ok := ParseConnector(msg(procEventExec, 4242, 4242)); !ok || !ev.Exec || ev.PID != 4242 {
		t.Fatalf("exec: %+v %v", ev, ok)
	}
	if ev, ok := ParseConnector(msg(procEventExit, 4242, 4242)); !ok || !ev.Exit || ev.PID != 4242 {
		t.Fatalf("exit: %+v %v", ev, ok)
	}
	if _, ok := ParseConnector(msg(procEventExit, 4243, 4242)); ok {
		t.Fatal("thread exit must be ignored")
	}
	if _, ok := ParseConnector(msg(0x1, 1, 2)); ok {
		t.Fatal("fork must be ignored")
	}
	if _, ok := ParseConnector([]byte{1, 2, 3}); ok {
		t.Fatal("short message accepted")
	}
}
