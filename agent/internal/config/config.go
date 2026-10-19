// Package config loads the agent configuration: built-in zero-config
// defaults, overridden by a YAML file (/etc/statetrack/agent.yaml or
// C:\ProgramData\StateTrack\agent.yaml), overridden by STATETRACK_*
// environment variables. A Reloader polls the file for hot-reloadable
// changes (watch rules, forensic TTL, log level).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/statetrack/statetrack/agent/internal/limiter"
)

// PolicyRule is a granular per-target classification override. It is an alias
// of limiter.PolicyRule so the config file, the classifier and the server all
// share one definition (and its YAML/JSON tags).
type PolicyRule = limiter.PolicyRule

// Config is the agent configuration.
type Config struct {
	// HostID identifies this host; defaults to /etc/machine-id or the hostname.
	HostID   string `yaml:"host_id"`
	StateDir string `yaml:"state_dir"`
	LogLevel string `yaml:"log_level"`

	Server   Server   `yaml:"server"`
	Watch    Watch    `yaml:"watch"`
	Spool    Spool    `yaml:"spool"`
	Baseline Baseline `yaml:"baseline"`
	Systemd  Systemd  `yaml:"systemd"`
	Packages Packages `yaml:"packages"`
	Windows  Windows  `yaml:"windows"`
	// IIS watches specific application pools and sites as canonical documents.
	// It is a targeted watcher: an empty target list means it does nothing,
	// because watching every pool on a server turns routine idle recycling into
	// a stream of Level 1 events.
	IIS IIS `yaml:"iis"`
	// Database watches selected tables, schema/privilege DDL and runtime server
	// parameters, read-only, one connection per database.
	Database Database `yaml:"database"`
	// Kubernetes enables the in-cluster configuration watcher. It is off by
	// default: a host that is not a cluster node has nothing to watch.
	Kubernetes Kubernetes `yaml:"kubernetes"`
	// Rules are granular per-target classification overrides, authored on the
	// server (from an accepted recommendation) or in the config file.
	Rules []PolicyRule `yaml:"rules"`

	// ForensicUntil enables Level 4 collection until this time (capped at
	// 15 minutes from when it is applied).
	ForensicUntil time.Time `yaml:"forensic_until"`
	// ReloadInterval is how often the config file and watch globs are
	// re-evaluated.
	ReloadInterval Duration `yaml:"reload_interval"`
}

// Server is the ingestion endpoint (used by the transport, Phase 5).
type Server struct {
	Address string `yaml:"address"`
	// Token is the per-host enrollment token. Reserved for server-side
	// authentication; it is written by the installers but not yet
	// transmitted over gRPC.
	Token string `yaml:"token"`
	// Org is the tenant the agent belongs to. Reserved for multi-tenant
	// routing; the server currently ingests into a single default org.
	Org string `yaml:"org"`
	// CAFile/CertFile/KeyFile enable mTLS when set.
	CAFile   string `yaml:"ca_file"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Watch configures filesystem collection.
type Watch struct {
	// Paths replaces the default watch roots; ExtraPaths is appended.
	// Both accept globs (e.g. /home/*/.ssh).
	Paths      []string `yaml:"paths"`
	ExtraPaths []string `yaml:"extra_paths"`
	// Exclude adds Level 0 blacklist patterns; Critical adds Level 1 patterns.
	Exclude  []string `yaml:"exclude"`
	Critical []string `yaml:"critical"`
}

// Spool configures the outbound queue.
type Spool struct {
	MaxMB int `yaml:"max_mb"`
}

// Baseline configures the Day-0 walker.
type Baseline struct {
	// Pace is slept after each file to bound CPU use.
	Pace Duration `yaml:"pace"`
}

// Systemd configures the service collector.
type Systemd struct {
	Enabled bool `yaml:"enabled"`
	// Units are glob patterns of unit names to report.
	Units []string `yaml:"units"`
}

// Packages configures the package manager collector.
type Packages struct {
	Enabled bool   `yaml:"enabled"`
	DpkgLog string `yaml:"dpkg_log"`
	DnfLog  string `yaml:"dnf_log"`
	YumLog  string `yaml:"yum_log"`
	ApkLog  string `yaml:"apk_log"`
	ApkDB   string `yaml:"apk_db"`
}

// Windows configures the Windows collectors.
type Windows struct {
	Registry Registry    `yaml:"registry"`
	Services WinServices `yaml:"services"`
	// MSI reports MsiInstaller installs/removals (Application log 1033/1034).
	MSI Toggle `yaml:"msi"`
	// SecurityAudit reads Security log 4657/4663 records to attribute
	// registry and file changes. They only exist where object-access
	// auditing and SACLs are configured.
	SecurityAudit Toggle `yaml:"security_audit"`
}

// Kubernetes configures the in-cluster configuration watcher.
//
// The watcher reads the cluster API server through the pod's service account,
// so enabling it needs no endpoint, credential or kubeconfig in the file: the
// kubelet already mounted them at /var/run/secrets/kubernetes.io/serviceaccount.
// See deploy/k8s/ for the RBAC the account needs.
type Kubernetes struct {
	Enabled bool `yaml:"enabled"`
	// Cluster is the display name used in tracked object paths
	// (/k8s/<cluster>/<namespace>/<resource>/<name>). Empty derives it from
	// the API server host.
	Cluster string `yaml:"cluster"`
	// Namespaces restricts watching to a list (empty means every namespace the
	// service account can list).
	Namespaces []string `yaml:"namespaces"`
	// ResyncInterval is the safety-net full re-list period.
	ResyncInterval Duration `yaml:"resync_interval"`
	// Endpoint/Token/CADataFile override the in-cluster service account
	// material. They exist for a host that watches a cluster it is not itself
	// running in; a pod never needs them.
	Endpoint   string `yaml:"endpoint"`
	TokenFile  string `yaml:"token_file"`
	CADataFile string `yaml:"ca_file"`
	// InsecureSkipVerify disables API server certificate verification. It is
	// for a cluster whose certificate is not signed by the mounted CA.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// Registry configures the registry collector.
type Registry struct {
	Enabled bool `yaml:"enabled"`
	// Keys are watched recursively (HKLM\... or HKCU\...); watch.exclude
	// patterns apply to keys too.
	Keys []string `yaml:"keys"`
}

// WinServices configures Service Control Manager monitoring.
type WinServices struct {
	Enabled bool `yaml:"enabled"`
	// Source of start/stop transitions: "eventlog" (System 7036), "poll"
	// (SCM snapshots) or "auto" (eventlog when this host logs 7036; recent
	// Windows 11 builds no longer do).
	Source       string   `yaml:"source"`
	PollInterval Duration `yaml:"poll_interval"`
}

// Toggle is an on/off collector setting.
type Toggle struct {
	Enabled bool `yaml:"enabled"`
}

// IIS configures the application pool and site watcher.
//
// Pools and Sites accept a name, an iis:// URI or a glob, so a config file and
// a console rule are the same spelling. They are merged with the pools and sites
// named by the operator's watched-target rules.
type IIS struct {
	// Enabled turns the watcher on even with no configured targets, which is
	// what a console-only deployment needs: the targets arrive as rules.
	Enabled bool `yaml:"enabled"`
	// ApplicationHost is applicationHost.config. Empty uses the WINDIR default.
	ApplicationHost string `yaml:"application_host"`
	// Pools and Sites are the explicit targets.
	Pools []string `yaml:"pools"`
	Sites []string `yaml:"sites"`
	// WatchAll tracks every pool and site. Off by default: IIS stops an idle
	// pool after 20 minutes, so watching everything makes routine recycling
	// look like an outage.
	WatchAll bool `yaml:"watch_all"`
	// Interval is how often the runtime state is polled.
	Interval Duration `yaml:"interval"`
}

// Database configures the read-only database watcher.
type Database struct {
	// Enabled turns the watcher on. With no connections it does nothing, so a
	// fleet-wide config file is safe to deploy.
	Enabled bool `yaml:"enabled"`
	// Connections are the databases to watch. Each needs a DSN, and the DSN is
	// a credential: it belongs in a 0600 file or the environment, never in a
	// repository.
	Connections []DBConnection `yaml:"connections"`
	// Interval is the default poll period for a connection.
	Interval Duration `yaml:"interval"`
}

// DBConnection is one watched database.
type DBConnection struct {
	// Name labels the connection in logs; it is not part of a document path.
	Name string `yaml:"name"`
	// Engine is "postgres" or "sqlserver".
	Engine string `yaml:"engine"`
	// DSN is the connection string.
	DSN string `yaml:"dsn"`
	// Database is the name used in tracked paths. Empty derives it from the DSN.
	Database string `yaml:"database"`
	// Tables are the tables to snapshot, as "schema.table" or "table".
	Tables []string `yaml:"tables"`
	// WatchSchema snapshots the table/column/privilege DDL.
	WatchSchema bool `yaml:"watch_schema"`
	// WatchServerParams snapshots the non-default runtime parameters.
	WatchServerParams bool `yaml:"watch_server_params"`
	// RowLimit bounds one table snapshot (default 500).
	RowLimit int `yaml:"row_limit"`
	// Interval overrides the default poll period.
	Interval Duration `yaml:"interval"`
}

// Duration is a time.Duration that unmarshals from strings like "250ms".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// DefaultPath is the configuration file location for goos.
func DefaultPath(goos string) string {
	if goos == "windows" {
		return `C:\ProgramData\StateTrack\agent.yaml`
	}
	return "/etc/statetrack/agent.yaml"
}

// Default returns the zero-config defaults for goos.
func Default(goos string) Config {
	c := Config{
		LogLevel:       "info",
		Spool:          Spool{MaxMB: 200},
		Baseline:       Baseline{Pace: Duration(time.Millisecond)},
		ReloadInterval: Duration(30 * time.Second),
	}
	if goos == "windows" {
		c.StateDir = `C:\ProgramData\StateTrack`
		c.Watch.Paths = []string{
			`C:\Windows\System32\inetsrv\config`,
			`C:\Windows\System32\drivers\etc`,
			`C:\Windows\System32\Tasks`,
			`C:\ProgramData`,
		}
		c.Windows = Windows{
			Registry: Registry{Enabled: true, Keys: []string{`HKLM\SOFTWARE`, `HKLM\SYSTEM\CurrentControlSet\Services`}},
			Services: WinServices{Enabled: true, Source: "auto", PollInterval: Duration(5 * time.Second)},
			MSI:      Toggle{Enabled: true}, SecurityAudit: Toggle{Enabled: true},
		}
		// The IIS watcher is on by default but has no targets, so it costs
		// nothing until an operator names a pool: its first act with an empty
		// target list is to log that and return.
		c.IIS = IIS{Enabled: true, Interval: Duration(30 * time.Second)}
		c.Database = Database{Enabled: true, Interval: Duration(60 * time.Second)}
		return c
	}
	c.StateDir = "/var/lib/statetrack"
	c.Watch.Paths = []string{
		"/etc", "/usr/local/etc", "/etc/systemd/system", "/var/spool/cron", "/root/.ssh", "/home/*/.ssh",
	}
	c.Systemd = Systemd{Enabled: true, Units: []string{"*.service", "*.timer", "*.socket"}}
	// A Linux host that runs PostgreSQL or SQL Server can watch a database
	// too, so the watcher is available on both platforms. With no connections
	// it does nothing.
	c.Database = Database{Enabled: true, Interval: Duration(60 * time.Second)}
	c.Packages = Packages{
		Enabled: true,
		DpkgLog: "/var/log/dpkg.log",
		DnfLog:  "/var/log/dnf.rpm.log",
		YumLog:  "/var/log/yum.log",
		ApkLog:  "/var/log/apk.log",
		ApkDB:   "/lib/apk/db/installed",
	}
	return c
}

// Source records where the configuration came from.
type Source struct {
	Path       string // file consulted
	FileLoaded bool   // false when the file does not exist (zero-config)
	EnvApplied []string
}

// Load builds the configuration for the running OS. path may be empty to
// use STATETRACK_CONFIG or the OS default; a missing default file is not
// an error (zero-config), a missing explicit file is.
func Load(path string) (Config, Source, error) {
	return LoadFor(runtime.GOOS, path, os.LookupEnv)
}

// LoadFor is Load with an injectable OS and environment.
func LoadFor(goos, path string, env func(string) (string, bool)) (Config, Source, error) {
	explicit := path != ""
	if p, ok := env("STATETRACK_CONFIG"); ok && !explicit && p != "" {
		path, explicit = p, true
	}
	if path == "" {
		path = DefaultPath(goos)
	}
	cfg := Default(goos)
	src := Source{Path: path}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := decode(data, &cfg); err != nil {
			return Config{}, src, fmt.Errorf("config %s: %w", path, err)
		}
		src.FileLoaded = true
	case errors.Is(err, fs.ErrNotExist) && !explicit:
	default:
		return Config{}, src, fmt.Errorf("config: %w", err)
	}

	applied, err := applyEnv(&cfg, env)
	if err != nil {
		return Config{}, src, err
	}
	src.EnvApplied = applied
	if err := cfg.Validate(); err != nil {
		return Config{}, src, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, src, nil
}

func decode(data []byte, cfg *Config) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(cfg)
}

func applyEnv(cfg *Config, env func(string) (string, bool)) ([]string, error) {
	var applied []string
	str := func(key string, dst *string) {
		if v, ok := env(key); ok {
			*dst = v
			applied = append(applied, key)
		}
	}
	list := func(key string, dst *[]string) {
		if v, ok := env(key); ok {
			*dst = splitList(v)
			applied = append(applied, key)
		}
	}
	var errs []error
	boolean := func(key string, dst *bool) {
		if v, ok := env(key); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = b
			applied = append(applied, key)
		}
	}

	str("STATETRACK_HOST_ID", &cfg.HostID)
	str("STATETRACK_STATE_DIR", &cfg.StateDir)
	str("STATETRACK_LOG_LEVEL", &cfg.LogLevel)
	str("STATETRACK_SERVER_ADDRESS", &cfg.Server.Address)
	str("STATETRACK_SERVER_TOKEN", &cfg.Server.Token)
	str("STATETRACK_SERVER_ORG", &cfg.Server.Org)
	list("STATETRACK_WATCH_PATHS", &cfg.Watch.Paths)
	list("STATETRACK_WATCH_EXTRA_PATHS", &cfg.Watch.ExtraPaths)
	list("STATETRACK_WATCH_EXCLUDE", &cfg.Watch.Exclude)
	list("STATETRACK_WATCH_CRITICAL", &cfg.Watch.Critical)
	boolean("STATETRACK_SYSTEMD_ENABLED", &cfg.Systemd.Enabled)
	boolean("STATETRACK_PACKAGES_ENABLED", &cfg.Packages.Enabled)
	str("STATETRACK_PACKAGES_DPKG_LOG", &cfg.Packages.DpkgLog)
	str("STATETRACK_PACKAGES_APK_LOG", &cfg.Packages.ApkLog)
	str("STATETRACK_PACKAGES_APK_DB", &cfg.Packages.ApkDB)
	boolean("STATETRACK_KUBERNETES_ENABLED", &cfg.Kubernetes.Enabled)
	str("STATETRACK_KUBERNETES_CLUSTER", &cfg.Kubernetes.Cluster)
	list("STATETRACK_KUBERNETES_NAMESPACES", &cfg.Kubernetes.Namespaces)
	str("STATETRACK_KUBERNETES_ENDPOINT", &cfg.Kubernetes.Endpoint)
	str("STATETRACK_KUBERNETES_TOKEN_FILE", &cfg.Kubernetes.TokenFile)
	str("STATETRACK_KUBERNETES_CA_FILE", &cfg.Kubernetes.CADataFile)
	boolean("STATETRACK_KUBERNETES_INSECURE_SKIP_VERIFY", &cfg.Kubernetes.InsecureSkipVerify)
	boolean("STATETRACK_REGISTRY_ENABLED", &cfg.Windows.Registry.Enabled)
	list("STATETRACK_REGISTRY_KEYS", &cfg.Windows.Registry.Keys)
	boolean("STATETRACK_SERVICES_ENABLED", &cfg.Windows.Services.Enabled)
	str("STATETRACK_SERVICES_SOURCE", &cfg.Windows.Services.Source)
	boolean("STATETRACK_MSI_ENABLED", &cfg.Windows.MSI.Enabled)
	boolean("STATETRACK_SECURITY_AUDIT_ENABLED", &cfg.Windows.SecurityAudit.Enabled)

	boolean("STATETRACK_IIS_ENABLED", &cfg.IIS.Enabled)
	str("STATETRACK_IIS_APPLICATION_HOST", &cfg.IIS.ApplicationHost)
	list("STATETRACK_IIS_POOLS", &cfg.IIS.Pools)
	list("STATETRACK_IIS_SITES", &cfg.IIS.Sites)
	boolean("STATETRACK_IIS_WATCH_ALL", &cfg.IIS.WatchAll)

	boolean("STATETRACK_DATABASE_ENABLED", &cfg.Database.Enabled)
	// The DSN is the only database setting that must be overridable from the
	// environment: a container or a service manager injects it as a secret, and
	// writing a production credential into a YAML file on disk is exactly what
	// an operator should be able to avoid.
	if v, ok := env("STATETRACK_DATABASE_DSN"); ok && v != "" {
		conn := primaryConnection(&cfg.Database)
		conn.DSN = v
		applied = append(applied, "STATETRACK_DATABASE_DSN")
	}
	if v, ok := env("STATETRACK_DATABASE_ENGINE"); ok && v != "" {
		conn := primaryConnection(&cfg.Database)
		conn.Engine = v
		applied = append(applied, "STATETRACK_DATABASE_ENGINE")
	}
	if v, ok := env("STATETRACK_DATABASE_NAME"); ok && v != "" {
		conn := primaryConnection(&cfg.Database)
		conn.Database = v
		applied = append(applied, "STATETRACK_DATABASE_NAME")
	}
	if v, ok := env("STATETRACK_DATABASE_TABLES"); ok {
		conn := primaryConnection(&cfg.Database)
		conn.Tables = splitList(v)
		applied = append(applied, "STATETRACK_DATABASE_TABLES")
	}

	if v, ok := env("STATETRACK_SPOOL_MAX_MB"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("STATETRACK_SPOOL_MAX_MB: %w", err))
		} else {
			cfg.Spool.MaxMB = n
			applied = append(applied, "STATETRACK_SPOOL_MAX_MB")
		}
	}
	for key, dst := range map[string]*Duration{
		"STATETRACK_RELOAD_INTERVAL": &cfg.ReloadInterval,
		"STATETRACK_BASELINE_PACE":   &cfg.Baseline.Pace,
	} {
		if v, ok := env(key); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				continue
			}
			*dst = Duration(d)
			applied = append(applied, key)
		}
	}
	if v, ok := env("STATETRACK_FORENSIC_UNTIL"); ok {
		if v == "" {
			cfg.ForensicUntil = time.Time{}
		} else if t, err := time.Parse(time.RFC3339, v); err != nil {
			errs = append(errs, fmt.Errorf("STATETRACK_FORENSIC_UNTIL: %w", err))
		} else {
			cfg.ForensicUntil = t
		}
		applied = append(applied, "STATETRACK_FORENSIC_UNTIL")
	}
	sort.Strings(applied)
	return applied, errors.Join(errs...)
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// primaryConnection returns the first connection, creating it if the
// environment configured a DSN for a database the file does not mention.
//
// One "primary" connection is deliberate: STATETRACK_DATABASE_* describes a
// single database, and a container that injects four of them would need four
// environment variables per database. A fleet that watches several databases
// configures them in agent.yaml.
func primaryConnection(db *Database) *DBConnection {
	if len(db.Connections) == 0 {
		db.Connections = []DBConnection{{Name: "primary"}}
	}
	return &db.Connections[0]
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	var errs []error
	if c.StateDir == "" {
		errs = append(errs, errors.New("state_dir must be set"))
	}
	if c.Spool.MaxMB < 1 {
		errs = append(errs, fmt.Errorf("spool.max_mb must be >= 1, got %d", c.Spool.MaxMB))
	}
	if c.ReloadInterval.D() < time.Second {
		errs = append(errs, fmt.Errorf("reload_interval must be >= 1s, got %s", c.ReloadInterval.D()))
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log_level must be debug|info|warn|error, got %q", c.LogLevel))
	}
	for _, p := range append(append([]string{}, c.Watch.Paths...), c.Watch.ExtraPaths...) {
		if !filepath.IsAbs(p) && !strings.HasPrefix(p, "/") {
			errs = append(errs, fmt.Errorf("watch path %q must be absolute", p))
		}
		if _, err := filepath.Match(p, ""); err != nil {
			errs = append(errs, fmt.Errorf("watch path %q: %w", p, err))
		}
	}
	w := c.Windows
	for _, k := range w.Registry.Keys {
		up := strings.ToUpper(k)
		if !strings.HasPrefix(up, `HKLM\`) && !strings.HasPrefix(up, `HKCU\`) {
			errs = append(errs, fmt.Errorf(`windows.registry.keys: %q must start with HKLM\ or HKCU\`, k))
		}
	}
	switch w.Services.Source {
	case "", "auto", "eventlog", "poll":
	default:
		errs = append(errs, fmt.Errorf("windows.services.source must be auto|eventlog|poll, got %q", w.Services.Source))
	}
	if w.Services.Enabled && w.Services.PollInterval.D() < time.Second {
		errs = append(errs, fmt.Errorf("windows.services.poll_interval must be >= 1s, got %s", w.Services.PollInterval.D()))
	}
	k := c.Kubernetes
	if k.Enabled {
		if k.ResyncInterval.D() < 0 {
			errs = append(errs, fmt.Errorf("kubernetes.resync_interval must not be negative, got %s", k.ResyncInterval.D()))
		}
		// An endpoint supplied without a token file would authenticate as
		// anonymous, which silently watches nothing on a locked-down cluster.
		if k.Endpoint != "" && k.TokenFile == "" {
			errs = append(errs, errors.New("kubernetes.token_file is required when kubernetes.endpoint is set"))
		}
	}
	errs = append(errs, c.validateWatchers()...)
	names := make(map[string]bool, len(c.Rules))
	for i, r := range c.Rules {
		name := r.Name
		if name == "" {
			name = r.Pattern
		}
		if name == "" {
			errs = append(errs, fmt.Errorf("rules[%d]: name or pattern is required", i))
			continue
		}
		if names[name] {
			errs = append(errs, fmt.Errorf("rules[%d]: duplicate rule name %q", i, name))
		}
		names[name] = true
		if r.Level < 0 || r.Level > 4 {
			errs = append(errs, fmt.Errorf("rules[%d] (%s): level must be 0-4, got %d", i, name, r.Level))
		}
	}
	return errors.Join(errs...)
}

// validateWatchers checks the targeted watcher sections.
//
// The checks are deliberately about *reachability* rather than about policy: a
// DSN with no database name, an unknown engine or a database path the collector
// cannot parse would all produce a watcher that connects and then reports
// nothing, which is the worst failure mode for a monitoring agent because it
// looks healthy.
func (c *Config) validateWatchers() []error {
	var errs []error
	if c.IIS.Interval.D() < 0 {
		errs = append(errs, fmt.Errorf("iis.interval must not be negative, got %s", c.IIS.Interval.D()))
	}
	if c.Database.Interval.D() < 0 {
		errs = append(errs, fmt.Errorf("database.interval must not be negative, got %s", c.Database.Interval.D()))
	}
	if !c.Database.Enabled {
		return errs
	}
	seen := make(map[string]bool, len(c.Database.Connections))
	for i, conn := range c.Database.Connections {
		label := conn.Name
		if label == "" {
			label = conn.Engine + "/" + conn.Database
		}
		engine, ok := normalizeDatabaseEngine(conn.Engine)
		if !ok {
			errs = append(errs, fmt.Errorf("database.connections[%d] (%s): engine must be postgres or sqlserver, got %q", i, label, conn.Engine))
			continue
		}
		if conn.DSN == "" {
			errs = append(errs, fmt.Errorf("database.connections[%d] (%s): dsn is required", i, label))
		}
		if conn.Database == "" && databaseNameFromDSN(conn.DSN) == "" {
			errs = append(errs, fmt.Errorf("database.connections[%d] (%s): database is required when the dsn does not name one", i, label))
		}
		if seen[label] {
			errs = append(errs, fmt.Errorf("database.connections[%d]: duplicate connection name %q", i, label))
		}
		seen[label] = true
		if conn.RowLimit < 0 {
			errs = append(errs, fmt.Errorf("database.connections[%d] (%s): row_limit must not be negative, got %d", i, label, conn.RowLimit))
		}
		_ = engine
		for _, t := range conn.Tables {
			if !validTableSpec(t) {
				errs = append(errs, fmt.Errorf("database.connections[%d] (%s): table %q must be table or schema.table", i, label, t))
			}
		}
	}
	return errs
}

// normalizeDatabaseEngine mirrors database.NormalizeEngine.
//
// It is duplicated rather than imported because config is the package every
// other package depends on: importing a collector here would make the database
// driver a dependency of the whole agent, including a Windows build that may
// never open a database.
func normalizeDatabaseEngine(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "postgres", "postgresql", "pg", "pgsql":
		return "postgres", true
	case "sqlserver", "mssql", "sql-server", "sql_server":
		return "sqlserver", true
	}
	return "", false
}

// databaseNameFromDSN extracts a database name from a connection string.
func databaseNameFromDSN(dsn string) string {
	if i := strings.Index(dsn, "://"); i >= 0 {
		rest := dsn[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			db := rest[slash+1:]
			if q := strings.IndexByte(db, '?'); q >= 0 {
				db = db[:q]
			}
			return strings.TrimSpace(db)
		}
		return ""
	}
	for _, part := range strings.Split(dsn, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "database", "initial catalog":
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

// validTableSpec accepts "table", "schema.table" and "[schema].[table]".
func validTableSpec(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	return len(strings.Split(v, ".")) <= 2 || strings.HasPrefix(v, "[")
}
func (c *Config) WatchRoots() []string {
	var dirs []string
	for _, pattern := range append(append([]string{}, c.Watch.Paths...), c.Watch.ExtraPaths...) {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				dirs = append(dirs, filepath.Clean(m))
			}
		}
	}
	sort.Strings(dirs)
	var out []string
	for _, d := range dirs {
		if len(out) > 0 && (d == out[len(out)-1] || isWithin(d, out[len(out)-1])) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func isWithin(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// RestartRequired lists changed settings that only take effect on restart.
func RestartRequired(old, cur Config) []string {
	var out []string
	if old.HostID != cur.HostID {
		out = append(out, "host_id")
	}
	if old.StateDir != cur.StateDir {
		out = append(out, "state_dir")
	}
	if old.Server != cur.Server {
		out = append(out, "server")
	}
	if old.Spool != cur.Spool {
		out = append(out, "spool")
	}
	if !reflect.DeepEqual(old.Systemd, cur.Systemd) {
		out = append(out, "systemd")
	}
	if old.Packages != cur.Packages {
		out = append(out, "packages")
	}
	if !reflect.DeepEqual(old.Windows, cur.Windows) {
		out = append(out, "windows")
	}
	if !reflect.DeepEqual(old.Kubernetes, cur.Kubernetes) {
		// A changed cluster watch is a different set of API subscriptions, not
		// a new pattern list, so it needs a restart rather than a hot reload.
		out = append(out, "kubernetes")
	}
	if !reflect.DeepEqual(old.IIS, cur.IIS) {
		// A changed pool or site list is a different set of runtime queries,
		// and the collection is already a poll: restarting the watcher would
		// re-open appcmd for every target.
		out = append(out, "iis")
	}
	if !reflect.DeepEqual(old.Database, cur.Database) {
		// A database handle is opened once per connection, so a changed DSN or
		// table list needs the process to reconnect.
		out = append(out, "database")
	}
	return out
}

// ResolveHostID returns c.HostID or a stable machine identifier.
func (c *Config) ResolveHostID() string {
	if c.HostID != "" {
		return c.HostID
	}
	if id := machineGUID(); id != "" {
		return id
	}
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	h, _ := os.Hostname()
	return h
}
