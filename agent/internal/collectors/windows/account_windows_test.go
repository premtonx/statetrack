//go:build windows

package windows

import (
	"testing"
)

func TestResolveAccountSystem(t *testing.T) {
	a, ok := ResolveAccount("S-1-5-18")
	if !ok {
		t.Fatal("S-1-5-18 should resolve")
	}
	if a.Username != `NT AUTHORITY\SYSTEM` {
		t.Fatalf("username = %q, want NT AUTHORITY\\SYSTEM", a.Username)
	}
	if a.SID != "S-1-5-18" {
		t.Fatalf("sid = %q", a.SID)
	}
}

func TestResolveAccountInvalid(t *testing.T) {
	if _, ok := ResolveAccount("not-a-sid"); ok {
		t.Fatal("invalid SID should not resolve")
	}
	if _, ok := ResolveAccount(""); ok {
		t.Fatal("empty SID should not resolve")
	}
}

func TestCurrentControlSet(t *testing.T) {
	n, err := CurrentControlSet()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("CurrentControlSet = %d, want >= 1", n)
	}
}
