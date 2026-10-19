package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/statetrack/statetrack/server/internal/storage"
)

// DefaultSummaryWindow is the change window a poller gets when it does not ask
// for one. It matches the freshest range the console dashboard offers.
const DefaultSummaryWindow = 15 * time.Minute

// MaxSummaryWindow caps the window so a poller cannot force an unbounded scan
// of the partitioned events table on every scrape.
const MaxSummaryWindow = 30 * 24 * time.Hour

// hostSummary serves the unified poller rollup. It accepts either a hostname
// (how Checkmk/Zabbix inventory a host) or a host id in the path, so an
// operator can wire up whichever identifier their tool already knows:
//
//	GET /api/v1/hosts/prod-web-01/summary?window=15m
//	GET /api/v1/hosts/9f1c…-…/summary?window=1h
//
// The response is a flat, self-contained document (see storage.HostSummary) so
// a monitoring check can render its state from a single HTTP call.
func (s *Server) hostSummary(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.PathValue("hostname"))
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hostname or host id is required"})
		return
	}

	window, label, err := parseSummaryWindow(r.URL.Query().Get("window"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	summary, err := s.Store.HostSummary(r.Context(), s.OrgID, key, time.Now().Add(-window))
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host not found", "host": key})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	summary.Window = label

	// The API layer owns the console base URL, so it fills in the deep link
	// (the storage layer deliberately stays presentation-free). Point it at the
	// diff tab: a monitoring alert is only actionable if it lands the operator
	// on the change itself rather than a menu.
	if summary.LatestCritical != nil {
		summary.LatestCritical.DeepLink = fmt.Sprintf(
			"%s/events/%s?tab=diff", strings.TrimRight(s.UIBaseURL, "/"), summary.LatestCritical.ID)
	}

	writeJSON(w, http.StatusOK, summary)
}

// parseSummaryWindow resolves the `window` query parameter into a duration and
// the canonical label echoed back in the response. An empty value falls back to
// DefaultSummaryWindow; anything above MaxSummaryWindow is clamped.
//
// Supported forms are Go durations ("90s", "15m", "2h") plus a "d" suffix for
// days ("7d"), since monitoring tools commonly express windows in days.
func parseSummaryWindow(raw string) (time.Duration, string, error) {
	if raw == "" {
		return DefaultSummaryWindow, "15m", nil
	}
	d, err := parseWindowDuration(raw)
	if err != nil {
		return 0, "", err
	}
	if d <= 0 {
		return 0, "", fmt.Errorf("window must be positive, got %q", raw)
	}
	if d > MaxSummaryWindow {
		return MaxSummaryWindow, "30d", nil
	}
	return d, canonicalWindow(d), nil
}

// parseWindowDuration accepts Go durations and a trailing-day shorthand.
func parseWindowDuration(raw string) (time.Duration, error) {
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid window %q", raw)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid window %q: use forms like 15m, 1h or 7d", raw)
	}
	return d, nil
}

// canonicalWindow renders a duration back into the compact label pollers see.
func canonicalWindow(d time.Duration) string {
	switch {
	case d <= 0:
		// Zero is divisible by every unit below, so it would otherwise render
		// as the largest one ("0d").
		return "0s"
	case d%(24*time.Hour) == 0:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	case d%time.Hour == 0:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	case d%time.Minute == 0:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	default:
		return strconv.Itoa(int(d/time.Second)) + "s"
	}
}
