package windows

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf16"
)

// Registry value types.
const (
	RegNone                     = 0
	RegSz                       = 1
	RegExpandSz                 = 2
	RegBinary                   = 3
	RegDword                    = 4
	RegDwordBigEndian           = 5
	RegLink                     = 6
	RegMultiSz                  = 7
	RegResourceList             = 8
	RegFullResourceDescriptor   = 9
	RegResourceRequirementsList = 10
	RegQword                    = 11
)

var regTypeNames = map[uint32]string{
	RegNone: "REG_NONE", RegSz: "REG_SZ", RegExpandSz: "REG_EXPAND_SZ", RegBinary: "REG_BINARY",
	RegDword: "REG_DWORD", RegDwordBigEndian: "REG_DWORD_BIG_ENDIAN", RegLink: "REG_LINK",
	RegMultiSz: "REG_MULTI_SZ", RegResourceList: "REG_RESOURCE_LIST",
	RegFullResourceDescriptor: "REG_FULL_RESOURCE_DESCRIPTOR", RegResourceRequirementsList: "REG_RESOURCE_REQUIREMENTS_LIST",
	RegQword: "REG_QWORD",
}

// RegValue is one raw registry value.
type RegValue struct {
	Name string
	Type uint32
	Data []byte
}

// maxInlineBinary is the largest binary value rendered in full; larger ones
// are summarised by size and hash.
const maxInlineBinary = 256

// RenderKey renders a key's values as a stable text document, one line per
// value (one per element for REG_MULTI_SZ), sorted by name:
//
//	"ImagePath" = "C:\svc\svc.exe -k netsvcs"  ; REG_EXPAND_SZ
//	"Start" = 2  ; REG_DWORD 0x00000002
//
// The `"Name" = value` shape lets the secret scrubber redact values of
// password/token/secret-like names. Volatile values (DHCP lease times)
// are left out so they do not register as configuration changes.
func RenderKey(keyPath string, values []RegValue) []byte {
	vals := make([]RegValue, 0, len(values))
	for _, v := range values {
		if !volatileValue(keyPath, v.Name) {
			vals = append(vals, v)
		}
	}
	sort.Slice(vals, func(i, j int) bool {
		a, b := strings.ToLower(vals[i].Name), strings.ToLower(vals[j].Name)
		if a != b {
			return a < b
		}
		return vals[i].Name < vals[j].Name
	})
	var b strings.Builder
	for _, v := range vals {
		renderValue(&b, v)
	}
	return []byte(b.String())
}

func renderValue(b *strings.Builder, v RegValue) {
	name := quote(v.Name)
	if v.Name == "" {
		name = "@" // the key's default value
	}
	typ := regTypeNames[v.Type]
	if typ == "" {
		typ = fmt.Sprintf("REG_TYPE_%d", v.Type)
	}
	switch v.Type {
	case RegSz, RegExpandSz, RegLink:
		fmt.Fprintf(b, "%s = %s  ; %s\n", name, quote(utf16String(v.Data)), typ)
	case RegMultiSz:
		items := multiString(v.Data)
		if len(items) == 0 {
			fmt.Fprintf(b, "%s = (empty)  ; %s\n", name, typ)
		}
		for i, s := range items {
			fmt.Fprintf(b, "%s = %s  ; %s[%d]\n", name, quote(s), typ, i)
		}
	case RegDword, RegDwordBigEndian:
		if len(v.Data) >= 4 {
			n := binary.LittleEndian.Uint32(v.Data)
			if v.Type == RegDwordBigEndian {
				n = binary.BigEndian.Uint32(v.Data)
			}
			fmt.Fprintf(b, "%s = %d  ; %s 0x%08x\n", name, n, typ, n)
			return
		}
		fmt.Fprintf(b, "%s = %s  ; %s\n", name, binValue(v.Data), typ)
	case RegQword:
		if len(v.Data) >= 8 {
			n := binary.LittleEndian.Uint64(v.Data)
			fmt.Fprintf(b, "%s = %d  ; %s 0x%016x\n", name, n, typ, n)
			return
		}
		fmt.Fprintf(b, "%s = %s  ; %s\n", name, binValue(v.Data), typ)
	default:
		fmt.Fprintf(b, "%s = %s  ; %s\n", name, binValue(v.Data), typ)
	}
}

// binValue renders bytes as one unbroken token so a scrubber that redacts
// a value redacts all of it.
func binValue(d []byte) string {
	if len(d) <= maxInlineBinary {
		return "hex:" + hex.EncodeToString(d)
	}
	sum := sha256.Sum256(d)
	return fmt.Sprintf("hex[%dbytes,sha256:%s]", len(d), hex.EncodeToString(sum[:8]))
}

func multiString(d []byte) []string {
	u := make([]uint16, 0, len(d)/2)
	for i := 0; i+1 < len(d); i += 2 {
		u = append(u, uint16(d[i])|uint16(d[i+1])<<8)
	}
	var out []string
	for _, part := range splitUTF16(u) {
		out = append(out, string(utf16.Decode(part)))
	}
	return out
}

// splitUTF16 splits a NUL-separated, double-NUL-terminated list.
func splitUTF16(u []uint16) [][]uint16 {
	var out [][]uint16
	start := 0
	for i, c := range u {
		if c != 0 {
			continue
		}
		if i == start {
			break // empty element: end of list
		}
		out = append(out, u[start:i])
		start = i + 1
	}
	if start < len(u) && u[len(u)-1] != 0 {
		out = append(out, u[start:])
	}
	return out
}

// quote double-quotes s, escaping quotes and control characters but not
// backslashes (paths stay readable).
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// volatileValues are values rewritten by the system on its own schedule.
var volatileValues = []struct{ key, value string }{
	{`hklm\system\currentcontrolset\services\tcpip\parameters\interfaces\*`, "lease*"},
	{`hklm\system\currentcontrolset\services\tcpip\parameters\interfaces\*`, "t1"},
	{`hklm\system\currentcontrolset\services\tcpip\parameters\interfaces\*`, "t2"},
	{`hklm\system\currentcontrolset\services\tcpip6\parameters\interfaces\*`, "lease*"},
	{`hklm\system\currentcontrolset\services\tcpip6\parameters\interfaces\*`, "t1"},
	{`hklm\system\currentcontrolset\services\tcpip6\parameters\interfaces\*`, "t2"},
	{`hklm\system\currentcontrolset\services\*`, "dynamicinfo*"},
}

func volatileValue(keyPath, name string) bool {
	k := strings.ReplaceAll(strings.ToLower(keyPath), `\`, "/")
	n := strings.ToLower(name)
	for _, v := range volatileValues {
		if ok, _ := path.Match(strings.ReplaceAll(v.key, `\`, "/"), k); !ok {
			continue
		}
		if ok, _ := path.Match(v.value, n); ok {
			return true
		}
	}
	return false
}
