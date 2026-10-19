package windows

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// MsiInstaller event IDs (Application log).
const (
	MsiProvider     = "MsiInstaller"
	EventMsiInstall = 1033 // Windows Installer installed the product
	EventMsiRemove  = 1034 // Windows Installer removed the product
)

// MsiChange is a normalized MSI product installation or removal.
type MsiChange struct {
	Product      string
	Version      string // installed version (removed version for removals)
	Before       string // previous version for upgrades/downgrades
	Language     string
	Manufacturer string
	ProductCode  string
	Status       int    // Windows Installer result; 0 is success
	Op           string // "install", "remove", "upgrade", "downgrade"
	At           time.Time
	UserSID      string
	PID          uint32 // msiexec process that logged the record
	RecordID     uint64
}

var productCodeRe = regexp.MustCompile(`\{[0-9A-Fa-f-]{36}\}`)

// ParseMsi decodes a MsiInstaller 1033/1034 record. Its data is positional:
// product name, version, language, status, manufacturer; the binary
// payload starts with the ProductCode.
func ParseMsi(ev Event) (MsiChange, bool) {
	if ev.Provider != MsiProvider || (ev.ID != EventMsiInstall && ev.ID != EventMsiRemove) {
		return MsiChange{}, false
	}
	c := MsiChange{Product: ev.Param(0), Version: ev.Param(1), Language: ev.Param(2),
		Manufacturer: ev.Param(4), At: ev.When(time.Now()), UserSID: ev.UserSID, PID: ev.ProcessID, RecordID: ev.RecordID,
		Op: "install"}
	if ev.ID == EventMsiRemove {
		c.Op = "remove"
	}
	if c.Manufacturer == "(NULL)" {
		c.Manufacturer = ""
	}
	c.Status, _ = strconv.Atoi(ev.Param(3))
	c.ProductCode = strings.ToUpper(productCodeRe.FindString(string(ev.Binary)))
	if c.ProductCode == "" {
		// The product code is usually UTF-16LE in the binary payload.
		c.ProductCode = strings.ToUpper(productCodeRe.FindString(utf16String(ev.Binary)))
	}
	if c.Product == "" {
		return MsiChange{}, false
	}
	return c, true
}

// Failed reports a non-zero installer status.
func (c MsiChange) Failed() bool { return c.Status != 0 }

// Action maps the operation onto the proto actions.
func (c MsiChange) Action() pb.Action {
	switch c.Op {
	case "remove":
		return pb.Action_ACTION_DELETED
	case "upgrade", "downgrade":
		return pb.Action_ACTION_UPGRADED
	}
	return pb.Action_ACTION_CREATED
}

// EventType is the metadata event_type.
func (c MsiChange) EventType() string {
	t := map[string]string{"install": "PACKAGE_INSTALLED", "remove": "PACKAGE_REMOVED",
		"upgrade": "PACKAGE_UPGRADED", "downgrade": "PACKAGE_DOWNGRADED"}[c.Op]
	if c.Failed() {
		t += "_FAILED"
	}
	return t
}

// Summary is the human-readable event summary.
func (c MsiChange) Summary() string {
	var s string
	switch c.Op {
	case "remove":
		s = fmt.Sprintf("MSI removed %s %s", c.Product, c.Version)
	case "upgrade", "downgrade":
		s = fmt.Sprintf("MSI %sd %s %s -> %s", c.Op, c.Product, c.Before, c.Version)
	default:
		s = fmt.Sprintf("MSI installed %s %s", c.Product, c.Version)
	}
	if c.Failed() {
		s += fmt.Sprintf(" (failed, status %d)", c.Status)
	}
	return s
}

// Metadata is the event metadata.
func (c MsiChange) Metadata() map[string]string {
	md := map[string]string{
		"event_type":      c.EventType(),
		"package_action":  c.Op,
		"package_manager": "msi",
		"source":          "eventlog:MsiInstaller",
		"status":          strconv.Itoa(c.Status),
	}
	for k, v := range map[string]string{"manufacturer": c.Manufacturer, "product_code": c.ProductCode, "language": c.Language} {
		if v != "" {
			md[k] = v
		}
	}
	return md
}

// Target is the event target.
func (c MsiChange) Target() *pb.TargetResource {
	t := &pb.TargetResource{TargetType: "package", PathOrKey: c.Product}
	switch c.Op {
	case "remove":
		t.VersionBefore = c.Version
	case "install":
		t.VersionAfter = c.Version
	default:
		t.VersionBefore, t.VersionAfter = c.Before, c.Version
	}
	return t
}

// versionToken matches version-like words ("1.27.0", "go1.27.0", "v2.1").
var versionToken = regexp.MustCompile(`(?i)\b[a-z]*\d+(?:\.\d+)+[a-z0-9-]*\b`)

// productFamily identifies a product across versions: many products embed
// the version in their name ("Go Programming Language amd64 go1.27.0").
func productFamily(c MsiChange) string {
	name := versionToken.ReplaceAllString(strings.ToLower(c.Product), "")
	return strings.ToLower(c.Manufacturer) + "|" + strings.Join(strings.Fields(name), " ")
}

// compareVersions compares dotted numeric versions.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// DefaultMsiHold is how long MSI records wait for their counterpart: a
// major upgrade logs a removal of the old version and an install of the
// new one, in either order.
const DefaultMsiHold = 10 * time.Second

// MsiPairer merges removal+install pairs of the same product family into
// one upgrade (or downgrade). Not safe for concurrent use.
type MsiPairer struct {
	Hold time.Duration
	held []heldMsi
}

type heldMsi struct {
	c     MsiChange
	since time.Time
}

// Add queues c and returns changes that are ready.
func (p *MsiPairer) Add(now time.Time, c MsiChange) []MsiChange {
	if !c.Failed() {
		fam := productFamily(c)
		for i, h := range p.held {
			o := h.c
			if o.Failed() || o.Op == c.Op || productFamily(o) != fam || o.Version == c.Version {
				continue
			}
			inst, rem := c, o
			if c.Op == "remove" {
				inst, rem = o, c
			}
			up := inst
			up.Before = rem.Version
			up.Op = "upgrade"
			if compareVersions(inst.Version, rem.Version) < 0 {
				up.Op = "downgrade"
			}
			p.held = append(p.held[:i], p.held[i+1:]...)
			return append([]MsiChange{up}, p.Tick(now)...)
		}
	}
	p.held = append(p.held, heldMsi{c, now})
	return p.Tick(now)
}

// Tick releases records held longer than Hold.
func (p *MsiPairer) Tick(now time.Time) []MsiChange {
	hold := p.Hold
	if hold <= 0 {
		hold = DefaultMsiHold
	}
	var out []MsiChange
	keep := p.held[:0]
	for _, h := range p.held {
		if now.Sub(h.since) >= hold {
			out = append(out, h.c)
		} else {
			keep = append(keep, h)
		}
	}
	p.held = keep
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Flush releases everything (shutdown).
func (p *MsiPairer) Flush() []MsiChange {
	out := make([]MsiChange, 0, len(p.held))
	for _, h := range p.held {
		out = append(out, h.c)
	}
	p.held = nil
	return out
}
