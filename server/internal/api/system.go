package api

import (
	"net/http"
	"runtime"
	"time"
)

// systemInfo is the read-only build and runtime posture the console's General
// settings tab renders.
//
// It exists so the console stops hardcoding a version string and a build date in
// TypeScript: those drift from the binary within one release, and "which build
// is this?" is the first question a support ticket asks. Everything here is
// non-secret: no DSN, no bucket credentials, no session key.
type systemInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	UptimeSec int64  `json:"uptime_sec"`

	// DemoMode reflects the same switch the heartbeat and auto-login use, so an
	// operator can confirm which posture the process is actually in.
	DemoMode bool `json:"demo_mode"`
	// EmbeddedUI reports whether this binary carries the console. A `go build`
	// from source does not; the release image does.
	EmbeddedUI bool `json:"embedded_ui"`
	// AuthDisabled is surfaced (never defaulted) because a deployment running
	// with authentication bypassed should say so loudly.
	AuthDisabled bool `json:"auth_disabled"`
	// Storage describes where diffs go: "s3" or "inline".
	Storage string `json:"storage"`
	// Database is the server version string, resolved on demand.
	Database string `json:"database"`
}

// system serves the build/runtime posture of this process.
//
//	GET /api/v1/system
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(r); !ok {
		writeUnauthorized(w)
		return
	}

	info := systemInfo{
		Version:      s.Version,
		Commit:       s.Commit,
		BuildDate:    s.BuildDate,
		GoVersion:    runtime.Version(),
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		DemoMode:     demoMode(),
		EmbeddedUI:   s.EmbeddedUI,
		AuthDisabled: authDisabled(),
		Storage:      "inline",
	}
	if s.StartedAt != 0 {
		info.UptimeSec = int64(time.Since(time.Unix(s.StartedAt, 0)).Seconds())
	}
	if s.Store != nil {
		if s.Store.HasBlobStore() {
			info.Storage = "s3"
		}
		if v, err := s.Store.DatabaseVersion(r.Context()); err == nil {
			info.Database = v
		}
	}
	writeJSON(w, http.StatusOK, info)
}
