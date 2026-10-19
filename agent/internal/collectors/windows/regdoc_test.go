package windows

import (
	"strings"
	"testing"
	"unicode/utf16"
)

// utf16le encodes s as little-endian UTF-16 for registry value data.
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func TestRenderKey(t *testing.T) {
	doc := string(RenderKey(`HKLM\SYSTEM\CurrentControlSet\Services\Fake`, []RegValue{
		{Name: "ImagePath", Type: RegExpandSz, Data: utf16le(`C:\svc\fake.exe -k netsvcs`)},
		{Name: "Start", Type: RegDword, Data: []byte{2, 0, 0, 0}},
		{Name: "DependOnService", Type: RegMultiSz, Data: append(append(utf16le("RPCSS"), 0, 0), utf16le("EventLog")...)},
	}))
	for _, want := range []string{
		`"Start" = 2  ; REG_DWORD 0x00000002`,
		`"ImagePath" = "C:\svc\fake.exe -k netsvcs"  ; REG_EXPAND_SZ`,
		`"DependOnService" = "RPCSS"  ; REG_MULTI_SZ[0]`,
		`"DependOnService" = "EventLog"  ; REG_MULTI_SZ[1]`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("render missing %q in:\n%s", want, doc)
		}
	}
	// Sorted by name: DependOnService, ImagePath, Start.
	iD := strings.Index(doc, `"DependOnService"`)
	iI := strings.Index(doc, `"ImagePath"`)
	iS := strings.Index(doc, `"Start"`)
	if !(iD < iI && iI < iS) {
		t.Errorf("values not sorted:\n%s", doc)
	}
}

func TestRenderKeyDefaultValue(t *testing.T) {
	doc := string(RenderKey(`HKLM\X`, []RegValue{{Name: "", Type: RegSz, Data: utf16le("default")}}))
	if !strings.Contains(doc, `@ = "default"  ; REG_SZ`) {
		t.Fatalf("default value render:\n%s", doc)
	}
}

func TestRenderKeyBinaryHashesLargeValues(t *testing.T) {
	big := make([]byte, 300)
	for i := range big {
		big[i] = byte(i)
	}
	doc := string(RenderKey(`HKLM\X`, []RegValue{{Name: "Big", Type: RegBinary, Data: big}}))
	if !strings.Contains(doc, `hex[300bytes,sha256:`) {
		t.Fatalf("large binary should be summarised:\n%s", doc)
	}
}

func TestRenderKeySkipsVolatile(t *testing.T) {
	doc := string(RenderKey(`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`, []RegValue{
		{Name: "LeaseObtainedTime", Type: RegDword, Data: []byte{1, 0, 0, 0}},
		{Name: "EnableDHCP", Type: RegDword, Data: []byte{1, 0, 0, 0}},
	}))
	if strings.Contains(doc, "LeaseObtainedTime") {
		t.Fatalf("volatile value should be skipped:\n%s", doc)
	}
	if !strings.Contains(doc, "EnableDHCP") {
		t.Fatalf("non-volatile value should be kept:\n%s", doc)
	}
}

func TestQuote(t *testing.T) {
	if got := quote(`a"b\c`); got != `"a\"b\c"` {
		t.Fatalf("quote = %s", got)
	}
	if got := quote("line\nbreak"); got != `"line\nbreak"` {
		t.Fatalf("quote newline = %s", got)
	}
}
