package windows

import (
	"fmt"
	"testing"
)

// parseXML builds and parses a Windows Event Log (EvtRender) record.
func parseXML(t *testing.T, provider string, id uint32, userSID, eventData string) Event {
	t.Helper()
	doc := fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>`+
		`<Provider Name="%s"/><EventID>%d</EventID>`+
		`<TimeCreated SystemTime="2026-10-14T00:00:00.000000000Z"/><EventRecordID>42</EventRecordID>`+
		`<Execution ProcessID="1234"/><Channel>System</Channel><Computer>WIN-TEST</Computer>`+
		`<Security UserID="%s"/></System><EventData>%s</EventData></Event>`,
		provider, id, userSID, eventData)
	ev, err := ParseEvent(doc)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	return ev
}

func TestParseEvent(t *testing.T) {
	ev := parseXML(t, "MsiInstaller", 1033, "S-1-5-21-1-2-3",
		`<Data>Acme Widget</Data><Data>1.2.3</Data><Data>1033</Data><Data>0</Data><Data>Acme Inc</Data><Binary>7B36...</Binary>`)

	if ev.Provider != "MsiInstaller" || ev.ID != 1033 {
		t.Fatalf("provider/id = %q/%d, want MsiInstaller/1033", ev.Provider, ev.ID)
	}
	if ev.UserSID != "S-1-5-21-1-2-3" || ev.ProcessID != 1234 || ev.RecordID != 42 {
		t.Fatalf("sid/pid/rec = %q/%d/%d", ev.UserSID, ev.ProcessID, ev.RecordID)
	}
	if got := ev.Param(0); got != "Acme Widget" {
		t.Fatalf("Param(0) = %q", got)
	}
	if len(ev.Params) != 5 {
		t.Fatalf("Params = %v, want 5 positional values", ev.Params)
	}
	if ev.Time.IsZero() {
		t.Fatalf("Time is zero, want parsed timestamp")
	}
}

func TestParseEventMissingEventID(t *testing.T) {
	_, err := ParseEvent(`<Event><System><Provider Name="X"/></System></Event>`)
	if err == nil {
		t.Fatal("expected error for missing EventID")
	}
}

func TestUTF16String(t *testing.T) {
	// "W32TimeSrv" encoded as UTF-16LE.
	got := utf16String([]byte("W\x003\x002\x00T\x00i\x00m\x00e\x00S\x00r\x00v\x00\x00"))
	if got != "W32TimeSrv" {
		t.Fatalf("utf16String = %q", got)
	}
}
