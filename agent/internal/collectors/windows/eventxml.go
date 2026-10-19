// Package windows implements the Windows collectors: a ReadDirectoryChangesW
// filesystem watcher, a registry watcher that diffs keys as text documents,
// Service Control Manager monitoring (System log and SCM snapshots), MSI
// installs (Application log) and actor attribution from Security audit
// records and SID lookups.
//
// Files without a _windows suffix hold the portable parsing and mapping
// logic so it can be tested on any OS.
package windows

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// Event is a parsed Windows Event Log record (EvtRender XML).
type Event struct {
	Provider string
	ID       uint32
	RecordID uint64
	Channel  string
	Computer string
	Time     time.Time
	// UserSID is System/Security/@UserID: the account the event was
	// logged on behalf of (e.g. who installed an MSI or a service).
	UserSID string
	// ProcessID is System/Execution/@ProcessID: the logging process.
	ProcessID uint32
	// Data holds named <Data Name="..."> values; Params all <Data> values
	// in document order (MsiInstaller uses unnamed data).
	Data   map[string]string
	Params []string
	Binary []byte
}

type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Execution     struct {
			ProcessID uint32 `xml:"ProcessID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
		Binary string `xml:"Binary"`
	} `xml:"EventData"`
}

// ParseEvent parses one rendered event.
func ParseEvent(doc string) (Event, error) {
	var x xmlEvent
	if err := xml.Unmarshal([]byte(doc), &x); err != nil {
		return Event{}, fmt.Errorf("event xml: %w", err)
	}
	var id uint32
	if _, err := fmt.Sscan(strings.TrimSpace(x.System.EventID), &id); err != nil {
		return Event{}, fmt.Errorf("event xml: EventID %q", x.System.EventID)
	}
	ev := Event{
		Provider:  x.System.Provider.Name,
		ID:        id,
		RecordID:  x.System.EventRecordID,
		Channel:   x.System.Channel,
		Computer:  x.System.Computer,
		UserSID:   x.System.Security.UserID,
		ProcessID: x.System.Execution.ProcessID,
		Data:      make(map[string]string, len(x.EventData.Data)),
	}
	if t, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime); err == nil {
		ev.Time = t
	}
	for _, d := range x.EventData.Data {
		v := strings.TrimSpace(d.Value)
		ev.Params = append(ev.Params, v)
		if d.Name != "" {
			ev.Data[d.Name] = v
		}
	}
	if b := strings.TrimSpace(x.EventData.Binary); b != "" {
		ev.Binary, _ = hex.DecodeString(b)
	}
	return ev, nil
}

// Param returns the i-th <Data> value, or "".
func (e Event) Param(i int) string {
	if i < len(e.Params) {
		return e.Params[i]
	}
	return ""
}

// When returns the event time, or fallback when the record had none.
func (e Event) When(fallback time.Time) time.Time {
	if e.Time.IsZero() {
		return fallback
	}
	return e.Time
}

// utf16String decodes little-endian UTF-16 up to the first NUL.
func utf16String(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
