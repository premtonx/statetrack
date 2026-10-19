package api

import (
	"strings"
	"testing"
	"time"
)

func TestParseSummaryWindowDefaults(t *testing.T) {
	d, label, err := parseSummaryWindow("")
	if err != nil {
		t.Fatalf("empty window: %v", err)
	}
	if d != DefaultSummaryWindow {
		t.Fatalf("duration = %s, want %s", d, DefaultSummaryWindow)
	}
	if label != "15m" {
		t.Fatalf("label = %q, want 15m", label)
	}
}

func TestParseSummaryWindowAccepted(t *testing.T) {
	cases := []struct {
		in    string
		want  time.Duration
		label string
	}{
		{"90s", 90 * time.Second, "90s"},
		{"15m", 15 * time.Minute, "15m"},
		{"1h", time.Hour, "1h"},
		{"24h", 24 * time.Hour, "1d"},
		{"7d", 7 * 24 * time.Hour, "7d"},
		{"1d", 24 * time.Hour, "1d"},
		// Exactly at the cap: accepted, not clamped.
		{"720h", MaxSummaryWindow, "30d"},
	}
	for _, c := range cases {
		d, label, err := parseSummaryWindow(c.in)
		if err != nil {
			t.Fatalf("window %q: unexpected error %v", c.in, err)
		}
		if d != c.want {
			t.Errorf("window %q: duration = %s, want %s", c.in, d, c.want)
		}
		if label != c.label {
			t.Errorf("window %q: label = %q, want %q", c.in, label, c.label)
		}
	}
}

// A poller must never be able to turn one scrape into an unbounded scan of the
// partitioned events table.
func TestParseSummaryWindowClampsAboveMax(t *testing.T) {
	for _, in := range []string{"31d", "8760h", "365d"} {
		d, label, err := parseSummaryWindow(in)
		if err != nil {
			t.Fatalf("window %q: unexpected error %v", in, err)
		}
		if d != MaxSummaryWindow {
			t.Errorf("window %q: duration = %s, want clamp to %s", in, d, MaxSummaryWindow)
		}
		if label != "30d" {
			t.Errorf("window %q: label = %q, want 30d", in, label)
		}
	}
}

func TestParseSummaryWindowRejects(t *testing.T) {
	for _, in := range []string{"soon", "15 minutes", "-5m", "0s", "d", "5x", ""} {
		if in == "" {
			continue // covered by the default test
		}
		if _, _, err := parseSummaryWindow(in); err == nil {
			t.Errorf("window %q: expected an error", in)
		}
	}
}

// Zero and negative windows would grow the scan unboundedly (from = now), so
// they must be rejected rather than silently accepted.
func TestParseSummaryWindowRejectsNonPositive(t *testing.T) {
	for _, in := range []string{"0s", "-1m", "-1d", "0d"} {
		_, _, err := parseSummaryWindow(in)
		if err == nil {
			t.Errorf("window %q: expected an error", in)
			continue
		}
		if !strings.Contains(err.Error(), "positive") {
			t.Errorf("window %q: error = %v, want a 'must be positive' message", in, err)
		}
	}
}

func TestCanonicalWindow(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Second:   "30s",
		45 * time.Second:   "45s",
		90 * time.Second:   "90s",
		5 * time.Minute:    "5m",
		15 * time.Minute:   "15m",
		90 * time.Minute:   "90m",
		2 * time.Hour:      "2h",
		48 * time.Hour:     "2d",
		7 * 24 * time.Hour: "7d",
		0:                  "0s",
	}
	for d, want := range cases {
		if got := canonicalWindow(d); got != want {
			t.Errorf("canonicalWindow(%s) = %q, want %q", d, got, want)
		}
	}
}
