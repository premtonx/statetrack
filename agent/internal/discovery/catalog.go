// Package discovery is the agent's lightweight, non-blocking workload
// scanner. It runs once at startup and then every six hours, probing for
// production workloads a host is running (IIS sites, nginx/apache vhosts,
// database instances, container runtimes, Kubernetes objects) so the console
// can recommend onboarding them with a granular policy rule.
//
// The catalog of what to look for lives in catalog.yaml, embedded into the
// binary at build time. An air-gapped datacenter therefore gets exactly the
// same discovery coverage as a connected one: nothing is ever fetched at
// runtime.
//
// Probes only read configuration files, the Windows registry and process
// tables: they never modify host state, never block the collection pipeline,
// and every filesystem failure is treated as "not found" rather than an error.
package discovery

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// catalogYAML is the embedded Enterprise Application Knowledge Base. It is
// embedded rather than read from disk so the agent cannot be tricked into
// scanning an attacker-supplied catalog, and so a single static binary is
// self-describing in an air-gapped environment.
//
//go:embed catalog.yaml
var catalogYAML []byte

// CatalogVersion is the schema version this build understands. A manifest with
// a newer version is rejected rather than silently half-interpreted.
const CatalogVersion = 1

// Runtime environment an entry applies to. It mirrors the platform the agent
// is running as, plus "kubernetes" for cluster-side collection which is
// orthogonal to the host OS.
const (
	RuntimeLinux      = "linux"
	RuntimeWindows    = "windows"
	RuntimeDocker     = "docker"
	RuntimeKubernetes = "kubernetes"
)

// Target kinds the probe engine knows how to expand.
const (
	TargetFileGlob      = "file_glob"
	TargetDirWalk       = "dir_walk"
	TargetRegistry      = "registry"
	TargetService       = "service"
	TargetScheduledTask = "scheduled_task"
	TargetK8sResource   = "k8s_resource"
)

// defaultRiskLevel is the impact level an entry with no profile falls back to.
const defaultRiskLevel = LevelDrift

// Profile returns a profile by name, falling back to a drift-tier profile when

// Catalog is the parsed Enterprise Application Knowledge Base.
type Catalog struct {
	Version  int                `yaml:"version"`
	Profiles map[string]Profile `yaml:"profiles"`
	Entries  []Entry            `yaml:"entries"`
}

// Profile is a named, reusable risk-tiering heuristic set. Keeping the
// heuristics in data rather than in Go means a security team can review and
// amend the tiering policy in a pull request against one file.
type Profile struct {
	Description string `yaml:"description"`
	// ForceLevel, when non-zero, is applied unconditionally. It is how
	// "any live database is production" is expressed.
	ForceLevel int `yaml:"force_level"`
	// HTTPSPorts promote a web workload to Critical, and mark the workload as
	// TLS-terminating.
	HTTPSPorts []int `yaml:"https_ports"`
	// ProductionPorts promote a web workload to Critical (e.g. plain :80 on a
	// production name).
	ProductionPorts []int `yaml:"production_ports"`
	// ProductionPatterns / StagingPatterns are matched case-insensitively as
	// substrings against the workload name and its path.
	ProductionPatterns []string `yaml:"production_patterns"`
	StagingPatterns    []string `yaml:"staging_patterns"`
	CriticalLevel      int      `yaml:"critical_level"`
	StagingLevel       int      `yaml:"staging_level"`
	DefaultLevel       int      `yaml:"default_level"`
	// Diff selects full text diff capture; false means metadata + SHA-256 only.
	Diff bool `yaml:"diff"`
}

// Entry is one application or resource family in the catalog.
type Entry struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Vendor      string   `yaml:"vendor"`
	Category    string   `yaml:"category"`
	Runtime     string   `yaml:"runtime"`
	Profile     string   `yaml:"profile"`
	DevProfile  string   `yaml:"dev_profile"`
	Description string   `yaml:"description"`
	Targets     []Target `yaml:"targets"`
	// StagingNamespaces applies to Kubernetes entries: objects in these
	// namespaces are tiered with DevProfile (metadata + hash) rather than the
	// production profile.
	StagingNamespaces []string `yaml:"staging_namespaces"`
	// MaxResults bounds how many instances one entry may contribute to the
	// recommendation queue. Zero means the engine's default. It exists so a
	// broad entry (the whole HKLM\Software product table, a volume mount tree)
	// cannot drown an operator's review queue.
	MaxResults int `yaml:"max_results"`
}

// Target is one discovery mechanism for an entry.
type Target struct {
	Kind   string `yaml:"kind"`
	Parser string `yaml:"parser"`
	// Patterns are globs (file_glob, dir_walk) or literal keys/names
	// (registry, service, scheduled_task). Windows variables (%WINDIR%) and
	// globs in service names (MSSQL$*) are expanded by the probe.
	Patterns []string `yaml:"patterns"`
	// Extensions filter a dir_walk by file extension (case-insensitive).
	Extensions []string `yaml:"extensions"`
	// Depth bounds a dir_walk; 0 uses defaultWalkDepth.
	Depth int `yaml:"depth"`
	// MaxFiles bounds how many files a single dir_walk may yield, so a huge
	// volume root cannot flood the recommendation queue.
	MaxFiles int `yaml:"max_files"`
	// Resource names the Kubernetes resource type (configmaps, secrets, ...).
	Resource string `yaml:"resource"`
}

var (
	catalogOnce sync.Once
	catalogData *Catalog
	catalogErr  error
)

// Embedded returns the parsed built-in catalog. It is parsed once and cached;
// callers must not mutate the returned value.
func Embedded() (*Catalog, error) {
	catalogOnce.Do(func() {
		catalogData, catalogErr = parseCatalog(catalogYAML)
	})
	return catalogData, catalogErr
}

// MustCatalog returns the parsed catalog, panicking on a malformed manifest.
// Used by the platform probe wiring at startup, where a bad embedded file is a
// build defect rather than a runtime condition.
func MustCatalog() *Catalog {
	c, err := Embedded()
	if err != nil {
		panic(err)
	}
	return c
}

func parseCatalog(raw []byte) (*Catalog, error) {
	var c Catalog
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse embedded enterprise catalog: %w", err)
	}
	if c.Version != CatalogVersion {
		return nil, fmt.Errorf("embedded catalog version %d is not supported by this build (want %d)", c.Version, CatalogVersion)
	}
	if len(c.Entries) == 0 {
		return nil, fmt.Errorf("embedded catalog has no entries")
	}
	seen := make(map[string]bool, len(c.Entries))
	for i, e := range c.Entries {
		if e.ID == "" {
			return nil, fmt.Errorf("catalog entry %d has no id", i)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("catalog entry %q is duplicated", e.ID)
		}
		seen[e.ID] = true
		if e.Name == "" || e.Runtime == "" {
			return nil, fmt.Errorf("catalog entry %q needs a name and a runtime", e.ID)
		}
		if _, ok := c.Profiles[e.Profile]; !ok {
			return nil, fmt.Errorf("catalog entry %q references unknown profile %q", e.ID, e.Profile)
		}
		if e.DevProfile != "" {
			if _, ok := c.Profiles[e.DevProfile]; !ok {
				return nil, fmt.Errorf("catalog entry %q references unknown dev_profile %q", e.ID, e.DevProfile)
			}
		}
		if len(e.Targets) == 0 {
			return nil, fmt.Errorf("catalog entry %q has no targets", e.ID)
		}
	}
	return &c, nil
}

// Profile returns a profile by name, falling back to a drift-tier profile when
// the name is unknown so a hand-edited catalog degrades instead of panicking.
func (c *Catalog) Profile(name string) Profile {
	if p, ok := c.Profiles[name]; ok {
		return p
	}
	return Profile{DefaultLevel: defaultRiskLevel, Diff: false}
}

// Entry returns a catalog entry by id.
func (c *Catalog) Entry(id string) (Entry, bool) {
	for _, e := range c.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// EntriesFor returns the catalog entries that apply to a runtime environment,
// sorted by id so probe registration is deterministic.
func (c *Catalog) EntriesFor(runtime string) []Entry {
	return c.EntriesForRuntime(runtime)
}

// EntriesForRuntime returns the entries whose runtime is any of the given
// environments. A host scan passes both its OS runtime and the runtimes it can
// host (a Linux server also runs Docker), while a Kubernetes entry is never
// included because its objects do not live on the host.
func (c *Catalog) EntriesForRuntime(environments ...string) []Entry {
	want := make(map[string]bool, len(environments))
	for _, e := range environments {
		want[e] = true
	}
	var out []Entry
	for _, e := range c.Entries {
		if want[e.Runtime] {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Tier describes how a matched workload should be tracked. It is the output of
// the smart risk tiering heuristics and the input to a DiscoveredWorkload.
type Tier struct {
	Level  int
	Diff   bool
	Reason string
	// Signal names the heuristic that decided the tier ("https_bind",
	// "staging_name", "forced", ...). Useful in tests and in the console's
	// explanation of *why* a workload was classified as it was.
	Signal string
}

// staging reports whether a value looks like a non-production environment.
func (p Profile) staging(name, path string) bool {
	return matchesAny(p.StagingPatterns, name, path)
}

// production reports whether a value looks production-facing.
func (p Profile) production(name, path string) bool {
	return matchesAny(p.ProductionPatterns, name, path)
}

// matchesAny reports whether any pattern matches any value.
//
// Matching is token-aware rather than a raw substring test. Each value is split
// into alphanumeric tokens and a pattern matches when it equals a whole token,
// so "staging-api" is non-production ("staging") while "/opt/latest/nginx.conf"
// is not (its token is "latest", not "test"). A plain substring test would get
// the second case wrong and silently downgrade a production vhost, which is the
// dangerous direction to be wrong in: an under-tiered workload is under-watched.
//
// A pattern that itself contains a separator ("pre-prod") is also matched as a
// substring, because tokenising would otherwise split it apart.
func matchesAny(patterns []string, values ...string) bool {
	for _, pat := range patterns {
		if matchSignal(pat, values) {
			return true
		}
	}
	return false
}

// matchSignal reports whether one pattern matches any of the values.
func matchSignal(pattern string, values []string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	substring := strings.ContainsAny(pattern, "-_. ")
	for _, v := range values {
		v = strings.ToLower(v)
		if v == "" {
			continue
		}
		if substring && strings.Contains(v, pattern) {
			return true
		}
		for _, tok := range tokenize(v) {
			if tok == pattern {
				return true
			}
		}
	}
	return false
}

// tokenize splits a value into its alphanumeric tokens. Everything else (path
// separators, dots, dashes, colons) is a boundary: "C:\sites\staging-api\x.conf"
// yields "c", "sites", "staging", "api", "x", "conf".
func tokenize(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
	})
}

// portsContain reports whether any of the profile's promotion ports appear in
// the workload's bound port set.
func containsPort(ports []int, want []int) (int, bool) {
	for _, p := range ports {
		for _, w := range want {
			if p == w {
				return p, true
			}
		}
	}
	return 0, false
}

// Tier applies the smart risk tiering heuristics:
//
//  1. force_level always wins.
//  2. A staging signal (in the name or the path) downgrades — deliberately
//     before the port check, so a staging site on :443 is still staging.
//  3. An HTTPS bind, a production name, or a production port promotes.
//  4. Otherwise the profile's default applies.
//
// `ports` may be nil for resources with no notion of a listening socket (a
// database, a registry key, a Kubernetes object); the port rules then simply
// do not fire.
func (p Profile) Tier(kind, name, path string, ports []int, https bool) Tier {
	level := p.DefaultLevel
	if level == 0 {
		level = defaultRiskLevel
	}
	diff := p.Diff

	if p.ForceLevel != 0 {
		return Tier{Level: p.ForceLevel, Diff: diff, Signal: "forced",
			Reason: fmt.Sprintf("%s is always tracked at %s", displayKind(kind), levelName(p.ForceLevel))}
	}

	if p.staging(name, path) {
		lvl := p.StagingLevel
		if lvl == 0 {
			lvl = LevelDrift
		}
		return Tier{Level: lvl, Diff: diff, Signal: "staging_name",
			Reason: fmt.Sprintf("Non-production %s (%s matches a staging/dev pattern)", displayKind(kind), firstSignal(p.StagingPatterns, name, path))}
	}

	critical := p.CriticalLevel
	if critical == 0 {
		critical = LevelCritical
	}

	if port, ok := containsPort(ports, p.HTTPSPorts); ok || https {
		shown := port
		if shown == 0 {
			shown = 443
		}
		return Tier{Level: critical, Diff: diff, Signal: "https_bind",
			Reason: fmt.Sprintf("Active HTTPS production %s on port %d", displayKind(kind), shown)}
	}
	if p.production(name, path) {
		return Tier{Level: critical, Diff: diff, Signal: "production_name",
			Reason: fmt.Sprintf("Production-facing %s (%s) named for persistence monitoring", displayKind(kind), name)}
	}
	if port, ok := containsPort(ports, p.ProductionPorts); ok {
		return Tier{Level: critical, Diff: diff, Signal: "production_port",
			Reason: fmt.Sprintf("Active HTTP production %s on port %d", displayKind(kind), port)}
	}
	return Tier{Level: level, Diff: diff, Signal: "default",
		Reason: fmt.Sprintf("Discovered %s with no explicit production signal; tracked at %s", displayKind(kind), levelName(level))}
}

// firstSignal returns the pattern that matched, for the reason sentence.
func firstSignal(patterns []string, values ...string) string {
	for _, pat := range patterns {
		if matchSignal(pat, values) {
			return strings.ToLower(strings.TrimSpace(pat))
		}
	}
	return "unknown"
}

// displayKind renders a workload kind for a sentence, handling the empty case
// so a reason never reads "Discovered  with no explicit signal".
func displayKind(kind string) string {
	k := strings.TrimSpace(kind)
	if k == "" {
		return "workload"
	}
	return k
}

// StagingNamespace reports whether a namespace looks non-production under this
// profile's staging patterns. The Kubernetes collector uses it to tier an
// object without needing the whole catalog entry.
func (p Profile) StagingNamespace(ns string) bool {
	return p.staging(ns, ns)
}

// IsStagingNamespace reports whether a Kubernetes namespace is non-production
// for this entry: either explicitly listed, or matching the production
// profile's staging patterns.
func (c *Catalog) IsStagingNamespace(e Entry, ns string) bool {
	for _, s := range e.StagingNamespaces {
		if strings.EqualFold(s, ns) {
			return true
		}
	}
	if p, ok := c.Profiles[e.Profile]; ok {
		return p.staging(ns, ns)
	}
	return false
}

// ProfileForKubernetes picks the profile a Kubernetes object should be tiered
// with: the entry's dev_profile for a non-production namespace, otherwise the
// production profile. An entry without a dev_profile always uses its profile.
func (c *Catalog) ProfileForKubernetes(e Entry, namespace string) Profile {
	if e.DevProfile != "" && c.IsStagingNamespace(e, namespace) {
		return c.Profile(e.DevProfile)
	}
	return c.Profile(e.Profile)
}

// CatalogDigest returns a stable, short fingerprint of the embedded catalog
// contents. It is reported in the discovery log so an operator can confirm two
// hosts are scanning with the same knowledge base without diffing binaries.
func CatalogDigest() string {
	sum := sha256.Sum256(catalogYAML)
	return hex.EncodeToString(sum[:])[:12]
}
