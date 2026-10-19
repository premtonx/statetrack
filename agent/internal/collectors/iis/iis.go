// Package iis watches IIS Application Pools and Sites as canonical YAML
// documents.
//
// The motivation is narrow and real: on a Windows web server W3SVC can stay
// green while one application pool has stopped, or has quietly been switched
// from ApplicationPoolIdentity to a hard-coded service account. Watching
// applicationHost.config alone catches the second case but never the first —
// the file is identical whether the pool is running or stopped — so this
// collector combines two sources:
//
//   - the configuration in applicationHost.config (process model, recycling,
//     rapid-fail protection, bindings, physical paths), and
//   - the live pool state from the IIS runtime (Started / Stopped / Starting /
//     Stopping).
//
// Both are folded into one deterministic YAML document per pool or site, so the
// existing shadow store, diff engine and classifier treat an app pool exactly
// like a file: a change is a diff, a stopped pool is a line that flipped from
// Started to Stopped.
//
// Credentials are scrubbed before rendering is handed to the engine: a
// processModel password never reaches the shadow store, the diff or the
// transport in cleartext.
package iis

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Document path prefixes. These are URI-shaped rather than filesystem-shaped so
// a rule authored in the console reads as the thing an operator named
// ("iis://apppool/CheckoutAppPool"), and so the classifier's `iis://**`
// critical pattern can cover them.
const (
	PoolScheme = "iis://apppool/"
	SiteScheme = "iis://site/"
	PoolRoot   = "iis://apppool"
	SiteRoot   = "iis://site"
)

// Target types reported on events and matched by granular policy rules.
const (
	TargetPool = "iis_apppool"
	TargetSite = "iis_site"
)

// DefaultApplicationHost is IIS's central configuration file.
const DefaultApplicationHost = `C:\Windows\System32\inetsrv\config\applicationHost.config`

// stateUnknown is the state reported when the runtime query is unavailable.
// It is deliberately not "Stopped": a monitoring system must never claim a pool
// is down because its own query failed.
const stateUnknown = "Unknown"

// Pool is one application pool, configuration plus live state.
type Pool struct {
	Name                    string
	State                   string
	AutoStart               bool
	ManagedRuntimeVersion   string
	ManagedPipelineMode     string
	Enable32BitAppOnWin64   bool
	QueueLength             int
	StartMode               string
	CPULimit                int
	ProcessModel            ProcessModel
	RapidFailProtection     RapidFailProtection
	Recycling               Recycling
	ConfigSource            string
	ConfigurationModifiedAt time.Time
}

// ProcessModel is the pool's worker-process identity and lifetime settings.
type ProcessModel struct {
	IdentityType          string
	UserName              string
	Password              string
	IdleTimeout           string
	MaxProcesses          int
	LoadUserProfile       bool
	PingingEnabled        bool
	PingInterval          string
	PingResponseTime      string
	StartupTimeLimit      string
	ShutdownTimeLimit     string
	ManualGroupMembership bool
}

// RapidFailProtection is the "stop flapping pools" guard.
type RapidFailProtection struct {
	Enabled           bool
	FailureInterval   string
	MaximumFailures   int
	ShutdownTimeLimit string
}

// Recycling is the pool's restart policy.
type Recycling struct {
	DisallowOverlappingRotation bool
	LogEventOnRecycle           string
	PeriodicRestart             string
	Schedule                    []string
	PrivateMemoryLimitKB        int
	RequestLimit                int
	TimeLimit                   string
	VirtualMemoryLimitKB        int
}

// Site is one IIS site, configuration plus live state.
type Site struct {
	Name            string
	ID              string
	State           string
	ServerAutoStart bool
	Bindings        []Binding
	Applications    []Application
	VirtualDirs     []VirtualDirectory
	LogDirectory    string
}

// Binding is one HTTP/HTTPS endpoint. bindingInformation is "ip:port:host".
type Binding struct {
	Protocol      string
	IP            string
	Port          int
	HostHeader    string
	SSLThumbprint string
	SSLStore      string
	SSLFlags      string
}

// Application is a site's application mapping.
type Application struct {
	Path             string
	ApplicationPool  string
	EnabledProtocols string
	PhysicalPath     string
}

// VirtualDirectory is a path mapping inside a site.
type VirtualDirectory struct {
	Path         string
	PhysicalPath string
}

// Config is a parsed applicationHost.config.
type Config struct {
	Pools []Pool
	Sites []Site
}

// ---------------------------------------------------------------------------
// XML model
// ---------------------------------------------------------------------------

// The structs below mirror the subset of applicationHost.config this collector
// reads. Encoding/xml matches by local name, so the `configSections` preamble
// and any namespace prefix on the sections are ignored rather than fatal: a
// server with an unusual prefix must not lose its watcher.
type applicationHost struct {
	XMLName       xml.Name      `xml:"configuration"`
	SystemAppHost systemAppHost `xml:"system.applicationHost"`
}

type systemAppHost struct {
	ApplicationPools applicationPools `xml:"applicationPools"`
	Sites            sitesSection     `xml:"sites"`
}

type applicationPools struct {
	Pools []poolXML `xml:"add"`
}

type poolXML struct {
	Name                  string          `xml:"name,attr"`
	AutoStart             *bool           `xml:"autoStart,attr"`
	ManagedRuntimeVersion string          `xml:"managedRuntimeVersion,attr"`
	ManagedPipelineMode   string          `xml:"managedPipelineMode,attr"`
	Enable32BitAppOnWin64 *bool           `xml:"enable32BitAppOnWin64,attr"`
	QueueLength           int             `xml:"queueLength,attr"`
	StartMode             string          `xml:"startMode,attr"`
	CPULimit              int             `xml:"cpuLimit,attr"`
	ProcessModel          processModelXML `xml:"processModel"`
	Recycling             recyclingXML    `xml:"recycling"`
	Failure               failureXML      `xml:"failure"`
}

type processModelXML struct {
	IdentityType          string `xml:"identityType,attr"`
	UserName              string `xml:"userName,attr"`
	Password              string `xml:"password,attr"`
	IdleTimeout           string `xml:"idleTimeout,attr"`
	MaxProcesses          int    `xml:"maxProcesses,attr"`
	LoadUserProfile       *bool  `xml:"loadUserProfile,attr"`
	PingingEnabled        *bool  `xml:"pingingEnabled,attr"`
	PingInterval          string `xml:"pingInterval,attr"`
	PingResponseTime      string `xml:"pingResponseTime,attr"`
	StartupTimeLimit      string `xml:"startupTimeLimit,attr"`
	ShutdownTimeLimit     string `xml:"shutdownTimeLimit,attr"`
	ManualGroupMembership *bool  `xml:"manualGroupMembership,attr"`
}

type recyclingXML struct {
	DisallowOverlappingRotation *bool              `xml:"disallowOverlappingRotation,attr"`
	LogEventOnRecycle           string             `xml:"logEventOnRecycle,attr"`
	PeriodicRestart             periodicRestartXML `xml:"periodicRestart"`
}

type periodicRestartXML struct {
	Time          string      `xml:"time,attr"`
	Memory        int         `xml:"memory,attr"`
	PrivateMemory int         `xml:"privateMemory,attr"`
	Requests      int         `xml:"requests,attr"`
	Schedule      scheduleXML `xml:"schedule"`
}

type scheduleXML struct {
	Adds []struct {
		Value string `xml:"value,attr"`
	} `xml:"add"`
}

type failureXML struct {
	RapidFailProtection           *bool  `xml:"rapidFailProtection,attr"`
	RapidFailProtectionInterval   string `xml:"rapidFailProtectionInterval,attr"`
	RapidFailProtectionMaxCrashes int    `xml:"rapidFailProtectionMaxCrashes,attr"`
	ShutdownTimeLimit             string `xml:"shutdownTimeLimit,attr"`
}

type sitesSection struct {
	Sites []siteXML `xml:"site"`
}

type siteXML struct {
	Name            string           `xml:"name,attr"`
	ID              string           `xml:"id,attr"`
	ServerAutoStart *bool            `xml:"serverAutoStart,attr"`
	Bindings        []bindingXML     `xml:"bindings>binding"`
	Applications    []applicationXML `xml:"application"`
	LogFile         struct {
		Directory string `xml:"directory,attr"`
	} `xml:"logFile"`
}

type bindingXML struct {
	Protocol           string `xml:"protocol,attr"`
	BindingInformation string `xml:"bindingInformation,attr"`
	SSLFlags           string `xml:"sslFlags,attr"`
	CertificateHash    string `xml:"certificateHash,attr"`
	SSLStore           string `xml:"sslStoreName,attr"`
}

type applicationXML struct {
	Path             string                `xml:"path,attr"`
	ApplicationPool  string                `xml:"applicationPool,attr"`
	EnabledProtocols string                `xml:"enabledProtocols,attr"`
	VirtualDirectory []virtualDirectoryXML `xml:"virtualDirectory"`
}

type virtualDirectoryXML struct {
	Path         string `xml:"path,attr"`
	PhysicalPath string `xml:"physicalPath,attr"`
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// ParseConfig decodes applicationHost.config into the pools and sites the
// watcher tracks.
//
// A malformed document is an error: unlike a discovery probe, a watcher that
// silently reported "no pools" would look exactly like every pool having been
// deleted, which is the loudest possible false alarm. The caller logs and skips
// the poll instead.
func ParseConfig(data []byte) (Config, error) {
	trimmed := stripBOM(data)
	if len(strings.TrimSpace(string(trimmed))) == 0 {
		return Config{}, fmt.Errorf("iis: applicationHost.config is empty")
	}
	var doc applicationHost
	if err := xml.Unmarshal(trimmed, &doc); err != nil {
		return Config{}, fmt.Errorf("iis: parse applicationHost.config: %w", err)
	}
	var cfg Config
	for _, p := range doc.SystemAppHost.ApplicationPools.Pools {
		cfg.Pools = append(cfg.Pools, convertPool(p))
	}
	for _, s := range doc.SystemAppHost.Sites.Sites {
		cfg.Sites = append(cfg.Sites, convertSite(s))
	}
	sort.Slice(cfg.Pools, func(i, j int) bool { return cfg.Pools[i].Name < cfg.Pools[j].Name })
	sort.Slice(cfg.Sites, func(i, j int) bool { return cfg.Sites[i].Name < cfg.Sites[j].Name })
	return cfg, nil
}

func convertPool(p poolXML) Pool {
	pr := p.Recycling.PeriodicRestart
	pool := Pool{
		Name:                  p.Name,
		State:                 stateUnknown,
		AutoStart:             boolOr(p.AutoStart, true),
		ManagedRuntimeVersion: p.ManagedRuntimeVersion,
		ManagedPipelineMode:   p.ManagedPipelineMode,
		Enable32BitAppOnWin64: boolOr(p.Enable32BitAppOnWin64, false),
		QueueLength:           p.QueueLength,
		StartMode:             p.StartMode,
		CPULimit:              p.CPULimit,
		ProcessModel: ProcessModel{
			IdentityType:          p.ProcessModel.IdentityType,
			UserName:              p.ProcessModel.UserName,
			Password:              p.ProcessModel.Password,
			IdleTimeout:           p.ProcessModel.IdleTimeout,
			MaxProcesses:          p.ProcessModel.MaxProcesses,
			LoadUserProfile:       boolOr(p.ProcessModel.LoadUserProfile, false),
			PingingEnabled:        boolOr(p.ProcessModel.PingingEnabled, true),
			PingInterval:          p.ProcessModel.PingInterval,
			PingResponseTime:      p.ProcessModel.PingResponseTime,
			StartupTimeLimit:      p.ProcessModel.StartupTimeLimit,
			ShutdownTimeLimit:     p.ProcessModel.ShutdownTimeLimit,
			ManualGroupMembership: boolOr(p.ProcessModel.ManualGroupMembership, false),
		},
		RapidFailProtection: RapidFailProtection{
			Enabled:           boolOr(p.Failure.RapidFailProtection, true),
			FailureInterval:   p.Failure.RapidFailProtectionInterval,
			MaximumFailures:   p.Failure.RapidFailProtectionMaxCrashes,
			ShutdownTimeLimit: p.Failure.ShutdownTimeLimit,
		},
		Recycling: Recycling{
			DisallowOverlappingRotation: boolOr(p.Recycling.DisallowOverlappingRotation, false),
			LogEventOnRecycle:           p.Recycling.LogEventOnRecycle,
			PeriodicRestart:             pr.Time,
			PrivateMemoryLimitKB:        pr.PrivateMemory,
			RequestLimit:                pr.Requests,
			TimeLimit:                   pr.Time,
			VirtualMemoryLimitKB:        pr.Memory,
			Schedule:                    scheduleValues(pr.Schedule),
		},
	}
	if pool.ManagedRuntimeVersion == "" {
		pool.ManagedRuntimeVersion = "No Managed Code"
	}
	return pool
}

// scheduleValues flattens the restart schedule. Split out because the schedule
// is an element list, not an attribute, and the zero value must stay an empty
// list rather than a list containing "".
func scheduleValues(s scheduleXML) []string {
	out := make([]string, 0, len(s.Adds))
	for _, a := range s.Adds {
		if v := strings.TrimSpace(a.Value); v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func convertSite(s siteXML) Site {
	site := Site{
		Name:            s.Name,
		ID:              s.ID,
		State:           stateUnknown,
		ServerAutoStart: boolOr(s.ServerAutoStart, true),
		LogDirectory:    s.LogFile.Directory,
	}
	for _, b := range s.Bindings {
		ip, port, host := splitBinding(b.BindingInformation)
		site.Bindings = append(site.Bindings, Binding{
			Protocol:      strings.ToLower(b.Protocol),
			IP:            ip,
			Port:          port,
			HostHeader:    host,
			SSLThumbprint: strings.ToUpper(strings.TrimSpace(b.CertificateHash)),
			SSLStore:      b.SSLStore,
			SSLFlags:      b.SSLFlags,
		})
	}
	sort.Slice(site.Bindings, func(i, j int) bool {
		a, b := site.Bindings[i], site.Bindings[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.HostHeader != b.HostHeader {
			return a.HostHeader < b.HostHeader
		}
		return a.Protocol < b.Protocol
	})
	for _, a := range s.Applications {
		app := Application{
			Path:             a.Path,
			ApplicationPool:  a.ApplicationPool,
			EnabledProtocols: a.EnabledProtocols,
		}
		for _, v := range a.VirtualDirectory {
			site.VirtualDirs = append(site.VirtualDirs, VirtualDirectory{Path: v.Path, PhysicalPath: v.PhysicalPath})
			if v.Path == "/" || app.PhysicalPath == "" {
				app.PhysicalPath = v.PhysicalPath
			}
		}
		site.Applications = append(site.Applications, app)
	}
	sort.Slice(site.Applications, func(i, j int) bool { return site.Applications[i].Path < site.Applications[j].Path })
	sort.Slice(site.VirtualDirs, func(i, j int) bool {
		a, b := site.VirtualDirs[i], site.VirtualDirs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.PhysicalPath < b.PhysicalPath
	})
	return site
}

// splitBinding parses bindingInformation ("*:443:checkout.example.com").
func splitBinding(v string) (ip string, port int, host string) {
	parts := strings.SplitN(v, ":", 3)
	if len(parts) > 0 {
		ip = parts[0]
	}
	if len(parts) > 1 {
		port = atoi(parts[1])
	}
	if len(parts) > 2 {
		host = parts[2]
	}
	return ip, port, host
}

func atoi(s string) int {
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func boolOr(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// ---------------------------------------------------------------------------
// Document paths
// ---------------------------------------------------------------------------

// PoolPath renders the tracked document path for a pool name or URI.
func PoolPath(name string) string { return PoolScheme + trimPoolURI(name) }

// SitePath renders the tracked document path for a site name or URI.
func SitePath(name string) string { return SiteScheme + trimSiteURI(name) }

// trimPoolURI accepts "CheckoutAppPool", "iis://apppool/CheckoutAppPool" and
// "apppool/CheckoutAppPool", because an operator typing a rule by hand should
// not have to guess which spelling the agent wanted.
func trimPoolURI(v string) string {
	v = strings.TrimSpace(v)
	for _, prefix := range []string{"iis://apppool/", "iis://apppool", "apppool/"} {
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(prefix)) {
			return strings.TrimPrefix(v[len(prefix):], "/")
		}
	}
	return strings.TrimPrefix(v, "/")
}

func trimSiteURI(v string) string {
	v = strings.TrimSpace(v)
	for _, prefix := range []string{"iis://site/", "iis://sites/", "iis://site", "site/", "sites/"} {
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(prefix)) {
			return strings.TrimPrefix(v[len(prefix):], "/")
		}
	}
	return strings.TrimPrefix(v, "/")
}

// IsPoolPath reports whether a tracked path belongs to an application pool.
func IsPoolPath(p string) bool { return strings.HasPrefix(p, PoolScheme) }

// IsSitePath reports whether a tracked path belongs to a site.
func IsSitePath(p string) bool { return strings.HasPrefix(p, SiteScheme) }

// NameFromPath inverts PoolPath / SitePath, so a rule pattern can be resolved
// to the object it names regardless of which form the operator used.
func NameFromPath(p string) string {
	switch {
	case IsPoolPath(p):
		return strings.TrimPrefix(p, PoolScheme)
	case IsSitePath(p):
		return strings.TrimPrefix(p, SiteScheme)
	}
	return p
}
