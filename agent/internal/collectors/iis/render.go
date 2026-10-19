package iis

import (
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// stubValue is the marker written into a rendered document in place of a
// credential when no scrubber is available.
//
// It is deliberately not a plausible password and not empty: an empty value
// would render as `password: ""` and read as "the password was cleared", which
// is a different (and alarming) statement than "it is not reported here". The
// real scrubber replaces it with a salted stub, so a rotation still shows up as
// a changed line.
const stubValue = "[REDACTED]"

// renderPool builds the canonical YAML document for one pool.
//
// Every field is written explicitly, including the ones whose value equals
// IIS's default. That is the point of a canonical document: a diff must show
// "autoStart: true -> false", and a renderer that omitted defaults would make
// the same change invisible. Field order is fixed by the struct, so two polls
// of an unchanged pool produce byte-identical documents and no event.
func renderPool(p Pool, scrub func(string) string) []byte {
	doc := poolDoc{
		Kind:                  "iis_apppool",
		Name:                  p.Name,
		State:                 orDefault(p.State, stateUnknown),
		AutoStart:             p.AutoStart,
		ManagedRuntimeVersion: p.ManagedRuntimeVersion,
		ManagedPipelineMode:   orDefault(p.ManagedPipelineMode, "Integrated"),
		Enable32BitAppOnWin64: p.Enable32BitAppOnWin64,
		QueueLength:           p.QueueLength,
		StartMode:             p.StartMode,
		Identities:            poolIdentity(p, scrub),
		ProcessModel:          poolProcessModel(p.ProcessModel),
		RapidFailProtection:   poolFailure(p.RapidFailProtection),
		Recycling:             poolRecycling(p.Recycling),
	}
	return marshal(doc)
}

func poolIdentity(p Pool, scrub func(string) string) identityDoc {
	id := identityDoc{
		Type:         orDefault(p.ProcessModel.IdentityType, "ApplicationPoolIdentity"),
		UserName:     p.ProcessModel.UserName,
		IdleTimeout:  p.ProcessModel.IdleTimeout,
		MaxProcesses: p.ProcessModel.MaxProcesses,
	}
	// Only a configured password is rendered, and only as a stub. Writing a
	// marker for an empty password would read as "a credential is set", which is
	// the opposite of the truth for a pool on ApplicationPoolIdentity.
	if p.ProcessModel.Password != "" {
		id.Password = stubValue
		if scrub != nil {
			id.Password = scrub(p.ProcessModel.Password)
		}
	}
	return id
}

func poolProcessModel(pm ProcessModel) processModelDoc {
	return processModelDoc{
		LoadUserProfile:       pm.LoadUserProfile,
		PingingEnabled:        pm.PingingEnabled,
		PingInterval:          pm.PingInterval,
		PingResponseTime:      pm.PingResponseTime,
		StartupTimeLimit:      pm.StartupTimeLimit,
		ShutdownTimeLimit:     pm.ShutdownTimeLimit,
		ManualGroupMembership: pm.ManualGroupMembership,
	}
}

func poolFailure(f RapidFailProtection) rapidFailDoc {
	return rapidFailDoc{
		Enabled:           f.Enabled,
		FailureInterval:   f.FailureInterval,
		MaximumFailures:   f.MaximumFailures,
		ShutdownTimeLimit: f.ShutdownTimeLimit,
	}
}

func poolRecycling(r Recycling) recyclingDoc {
	schedule := r.Schedule
	if schedule == nil {
		schedule = []string{}
	}
	return recyclingDoc{
		DisallowOverlappingRotation: r.DisallowOverlappingRotation,
		LogEventOnRecycle:           r.LogEventOnRecycle,
		PeriodicRestart:             r.PeriodicRestart,
		Schedule:                    schedule,
		PrivateMemoryLimitKB:        r.PrivateMemoryLimitKB,
		RequestLimit:                r.RequestLimit,
		VirtualMemoryLimitKB:        r.VirtualMemoryLimitKB,
	}
}

// renderSite builds the canonical YAML document for one site.
func renderSite(s Site) []byte {
	bindings := make([]bindingDoc, 0, len(s.Bindings))
	for _, b := range s.Bindings {
		bindings = append(bindings, bindingDoc{
			Protocol:      orDefault(b.Protocol, "http"),
			IP:            orDefault(b.IP, "*"),
			Port:          b.Port,
			HostHeader:    b.HostHeader,
			SSLThumbprint: b.SSLThumbprint,
			SSLStore:      b.SSLStore,
			SSLFlags:      b.SSLFlags,
		})
	}
	apps := make([]applicationDoc, 0, len(s.Applications))
	for _, a := range s.Applications {
		apps = append(apps, applicationDoc{
			Path:             orDefault(a.Path, "/"),
			ApplicationPool:  a.ApplicationPool,
			EnabledProtocols: a.EnabledProtocols,
			PhysicalPath:     a.PhysicalPath,
		})
	}
	vdirs := make([]vdirDoc, 0, len(s.VirtualDirs))
	for _, v := range s.VirtualDirs {
		vdirs = append(vdirs, vdirDoc{Path: v.Path, PhysicalPath: v.PhysicalPath})
	}
	return marshal(siteDoc{
		Kind:            "iis_site",
		Name:            s.Name,
		ID:              s.ID,
		State:           orDefault(s.State, stateUnknown),
		ServerAutoStart: s.ServerAutoStart,
		Bindings:        bindings,
		Applications:    apps,
		VirtualDirs:     vdirs,
		LogDirectory:    s.LogDirectory,
	})
}

// ---------------------------------------------------------------------------
// YAML document shapes
//
// These exist so the document is a stable, reviewable schema rather than a dump
// of Go field names: an operator reading a diff sees `rapid_fail_protection:`
// and `max_processes:`, not `RapidFailProtection.MaximumFailures`.
// ---------------------------------------------------------------------------

type poolDoc struct {
	Kind                  string          `yaml:"kind"`
	Name                  string          `yaml:"name"`
	State                 string          `yaml:"state"`
	AutoStart             bool            `yaml:"auto_start"`
	ManagedRuntimeVersion string          `yaml:"managed_runtime_version"`
	ManagedPipelineMode   string          `yaml:"managed_pipeline_mode"`
	Enable32BitAppOnWin64 bool            `yaml:"enable_32bit_app_on_win64"`
	QueueLength           int             `yaml:"queue_length"`
	StartMode             string          `yaml:"start_mode"`
	Identities            identityDoc     `yaml:"process_model"`
	ProcessModel          processModelDoc `yaml:"process_lifetime"`
	RapidFailProtection   rapidFailDoc    `yaml:"rapid_fail_protection"`
	Recycling             recyclingDoc    `yaml:"recycling"`
}

type identityDoc struct {
	Type     string `yaml:"identity_type"`
	UserName string `yaml:"user_name"`
	// Password is omitted entirely when the pool has none, so a document does
	// not claim a credential is configured for an ApplicationPoolIdentity pool.
	Password     string `yaml:"password,omitempty"`
	IdleTimeout  string `yaml:"idle_timeout"`
	MaxProcesses int    `yaml:"max_processes"`
}

type processModelDoc struct {
	LoadUserProfile       bool   `yaml:"load_user_profile"`
	PingingEnabled        bool   `yaml:"pinging_enabled"`
	PingInterval          string `yaml:"ping_interval"`
	PingResponseTime      string `yaml:"ping_response_time"`
	StartupTimeLimit      string `yaml:"startup_time_limit"`
	ShutdownTimeLimit     string `yaml:"shutdown_time_limit"`
	ManualGroupMembership bool   `yaml:"manual_group_membership"`
}

type rapidFailDoc struct {
	Enabled           bool   `yaml:"enabled"`
	FailureInterval   string `yaml:"failure_interval"`
	MaximumFailures   int    `yaml:"maximum_failures"`
	ShutdownTimeLimit string `yaml:"shutdown_time_limit"`
}

type recyclingDoc struct {
	DisallowOverlappingRotation bool     `yaml:"disallow_overlapping_rotation"`
	LogEventOnRecycle           string   `yaml:"log_event_on_recycle"`
	PeriodicRestart             string   `yaml:"periodic_restart"`
	Schedule                    []string `yaml:"schedule"`
	PrivateMemoryLimitKB        int      `yaml:"private_memory_limit_kb"`
	RequestLimit                int      `yaml:"request_limit"`
	VirtualMemoryLimitKB        int      `yaml:"virtual_memory_limit_kb"`
}

type siteDoc struct {
	Kind            string           `yaml:"kind"`
	Name            string           `yaml:"name"`
	ID              string           `yaml:"id"`
	State           string           `yaml:"state"`
	ServerAutoStart bool             `yaml:"server_auto_start"`
	Bindings        []bindingDoc     `yaml:"bindings"`
	Applications    []applicationDoc `yaml:"applications"`
	VirtualDirs     []vdirDoc        `yaml:"virtual_directories"`
	LogDirectory    string           `yaml:"log_directory"`
}

type bindingDoc struct {
	Protocol      string `yaml:"protocol"`
	IP            string `yaml:"ip"`
	Port          int    `yaml:"port"`
	HostHeader    string `yaml:"host_header"`
	SSLThumbprint string `yaml:"ssl_thumbprint"`
	SSLStore      string `yaml:"ssl_store"`
	SSLFlags      string `yaml:"ssl_flags"`
}

type applicationDoc struct {
	Path             string `yaml:"path"`
	ApplicationPool  string `yaml:"application_pool"`
	EnabledProtocols string `yaml:"enabled_protocols"`
	PhysicalPath     string `yaml:"physical_path"`
}

type vdirDoc struct {
	Path         string `yaml:"path"`
	PhysicalPath string `yaml:"physical_path"`
}

func marshal(v any) []byte {
	b, err := yaml.Marshal(v)
	if err != nil {
		// A struct of strings, ints and bools cannot fail to marshal; a panic
		// here would take the whole agent down over one document, so the
		// fallback is an empty body, which the tracker reports as a deletion
		// rather than a crash.
		return nil
	}
	return b
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// PoolChangedToStopped reports whether a transition between two rendered pool
// documents is a pool stopping. The watcher uses it to raise the event summary
// an operator actually reads in the timeline ("Application pool stopped")
// rather than a generic "Modified iis://apppool/...".
func PoolChangedToStopped(before, after Pool) bool {
	return !strings.EqualFold(before.State, "Stopped") && strings.EqualFold(after.State, "Stopped")
}

// PoolIdentityChanged reports whether the worker-process identity changed, in
// type or in user. It is the second-highest-signal pool change after a stop: a
// pool silently running as a domain account is how a credential ends up where
// nobody expects it.
func PoolIdentityChanged(before, after Pool) bool {
	return !strings.EqualFold(before.ProcessModel.IdentityType, after.ProcessModel.IdentityType) ||
		!strings.EqualFold(before.ProcessModel.UserName, after.ProcessModel.UserName)
}

// PoolSummary renders the one-line summary for a pool change.
func PoolSummary(path string, before, after Pool) string {
	name := after.Name
	switch {
	case PoolChangedToStopped(before, after):
		return "Application pool " + name + " stopped (Started -> Stopped)"
	case strings.EqualFold(before.State, "Stopped") && strings.EqualFold(after.State, "Started"):
		return "Application pool " + name + " started (Stopped -> Started)"
	case PoolIdentityChanged(before, after):
		from := before.ProcessModel.IdentityType
		if before.ProcessModel.UserName != "" {
			from += " (" + before.ProcessModel.UserName + ")"
		}
		to := after.ProcessModel.IdentityType
		if after.ProcessModel.UserName != "" {
			to += " (" + after.ProcessModel.UserName + ")"
		}
		return "Application pool " + name + " identity changed (" + from + " -> " + to + ")"
	}
	return "Modified " + path
}

// SiteSummary renders the one-line summary for a site change.
func SiteSummary(path, before, after string) string {
	if before != after {
		return "Site state changed (" + before + " -> " + after + ")"
	}
	return "Modified " + path
}

// modTimeOrNow keeps a zero timestamp out of the shadow store, which would
// otherwise make every poll look like a change.
func modTimeOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}
