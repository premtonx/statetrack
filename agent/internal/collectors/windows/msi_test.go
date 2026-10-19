package windows

import (
	"encoding/hex"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

func TestParseMsiInstall(t *testing.T) {
	code := "{12345678-ABCD-EF01-2345-6789ABCDEF01}"
	ev := parseXML(t, "MsiInstaller", 1033, "S-1-5-21-1-2-3",
		`<Data>Acme Widget</Data><Data>1.2.3</Data><Data>1033</Data><Data>0</Data><Data>Acme Inc</Data>`+
			`<Binary>`+hex.EncodeToString(utf16le(code))+`</Binary>`)
	c, ok := ParseMsi(ev)
	if !ok {
		t.Fatal("ParseMsi returned not-ok")
	}
	if c.Product != "Acme Widget" || c.Version != "1.2.3" || c.Op != "install" {
		t.Fatalf("change = %+v", c)
	}
	if c.ProductCode != code {
		t.Fatalf("ProductCode = %q", c.ProductCode)
	}
	if c.Action() != pb.Action_ACTION_CREATED || c.Failed() {
		t.Fatalf("action/failed = %v/%v", c.Action(), c.Failed())
	}
	if c.Target().GetVersionAfter() != "1.2.3" {
		t.Fatalf("target = %+v", c.Target())
	}
}

func TestParseMsiRemove(t *testing.T) {
	ev := parseXML(t, "MsiInstaller", 1034, "S-1-5-18",
		`<Data>Acme Widget</Data><Data>1.2.2</Data><Data>1033</Data><Data>0</Data><Data>(NULL)</Data>`)
	c, ok := ParseMsi(ev)
	if !ok || c.Op != "remove" {
		t.Fatalf("change = %+v, ok=%v", c, ok)
	}
	if c.Action() != pb.Action_ACTION_DELETED {
		t.Fatalf("action = %v, want DELETED", c.Action())
	}
	if c.Manufacturer != "" {
		t.Fatalf("Manufacturer = %q, want empty for (NULL)", c.Manufacturer)
	}
}

func TestParseMsiFailed(t *testing.T) {
	ev := parseXML(t, "MsiInstaller", 1033, "",
		`<Data>Acme Widget</Data><Data>1.2.3</Data><Data>1033</Data><Data>1603</Data><Data>Acme Inc</Data>`)
	c, ok := ParseMsi(ev)
	if !ok || !c.Failed() {
		t.Fatalf("change = %+v", c)
	}
	if c.EventType() != "PACKAGE_INSTALLED_FAILED" {
		t.Fatalf("EventType = %q", c.EventType())
	}
}

func TestMsiPairerUpgrade(t *testing.T) {
	var p MsiPairer
	now := time.Now()
	rem := MsiChange{Product: "Acme Widget 1.2.2", Version: "1.2.2", Op: "remove", At: now}
	inst := MsiChange{Product: "Acme Widget 1.2.3", Version: "1.2.3", Op: "install", At: now.Add(time.Second)}

	if got := p.Add(now, rem); len(got) != 0 {
		t.Fatalf("remove should be held, got %+v", got)
	}
	got := p.Add(now.Add(time.Second), inst)
	if len(got) != 1 {
		t.Fatalf("pair: got %d changes, want 1", len(got))
	}
	if got[0].Op != "upgrade" || got[0].Before != "1.2.2" || got[0].Version != "1.2.3" {
		t.Fatalf("upgrade = %+v", got[0])
	}
	if got[0].Action() != pb.Action_ACTION_UPGRADED {
		t.Fatalf("action = %v", got[0].Action())
	}
}

func TestMsiPairerFlushesOnTimeout(t *testing.T) {
	var p MsiPairer
	now := time.Now()
	p.Add(now, MsiChange{Product: "Acme Widget 1.2.2", Version: "1.2.2", Op: "remove", At: now})
	got := p.Tick(now.Add(DefaultMsiHold + time.Second))
	if len(got) != 1 || got[0].Op != "remove" {
		t.Fatalf("flush = %+v", got)
	}
}
