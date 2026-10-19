package discovery

import (
	"path/filepath"
	"sort"
	"strings"
)

// Bounds that keep a scan reviewable. The recommendation queue is a *review*
// queue: an operator can act on dozens of rows, not on the two hundred unit
// files a distribution ships. A probe that matches more than this reports the
// first N (deterministically, by path) rather than drowning the console.
const (
	defaultWalkFiles  = 50
	defaultMaxResults = 30
)

// CatalogProbers builds one probe per catalog entry that applies to a runtime
// environment, in deterministic id order. Environment names are OR'd: a Linux
// host passes RuntimeLinux and RuntimeDocker because the container runtime it
// hosts is a Linux detection surface.
//
// Registration is entirely data-driven: adding an application to catalog.yaml is
// enough for the agent to find it. There is no Go change, no configuration and —
// critically for an air-gapped datacenter — no network access involved in
// learning how to scan a host.
func CatalogProbers(environments ...string) []Prober {
	c := MustCatalog()
	entries := c.EntriesForRuntime(environments...)
	out := make([]Prober, 0, len(entries))
	for _, e := range entries {
		e := e
		if !hasHostTarget(e) {
			continue
		}
		out = append(out, Prober{
			Name:  "catalog:" + e.ID,
			Probe: func() []DiscoveredWorkload { return c.probeEntry(e) },
		})
	}
	return out
}

// hasHostTarget reports whether an entry can be scanned from the host itself.
// A Kubernetes entry cannot: its objects live in the cluster, so the cluster
// collector consumes those entries instead (reading the same catalog, which is
// what keeps one manifest the single source of truth for both).
func hasHostTarget(e Entry) bool {
	for _, t := range e.Targets {
		if t.Kind != TargetK8sResource {
			return true
		}
	}
	return false
}

// scanDoc is one candidate document a target matched: a configuration file, a
// virtual registry key, or a scheduled-task definition.
type scanDoc struct {
	// Path is the document's identity — a file path, or a virtual path such as
	// a registry key. It is what a granular policy rule matches on.
	Path string
	// Data is the document body. Empty when the probe only needs to know the
	// document exists.
	Data []byte
}

// probeEntry expands every target of an entry and tiers whatever it matches.
// The result is deduplicated by workload identity and capped at the entry's
// max_results so one broad directory cannot monopolise the queue.
func (c *Catalog) probeEntry(e Entry) []DiscoveredWorkload {
	var pairs []docPair
	for _, t := range e.Targets {
		if !hasHostTarget(e) || t.Kind == TargetK8sResource {
			continue
		}
		for _, d := range c.expandTarget(t) {
			pairs = append(pairs, docPair{target: t, doc: d})
		}
	}
	return c.workloads(e, pairs)
}

// docPair binds a matched document to the catalog target that produced it, so
// the parser and the target's parser-kind label travel with the document
// instead of being re-derived (fallibly) from its path.
type docPair struct {
	target Target
	doc    scanDoc
}

// workloads runs the parse -> tier pipeline over an explicit set of documents.
//
// It is separated from probeEntry so the pipeline can be driven directly. The
// probes' job is expansion (globbing, registry walking, directory walking) and
// this is the transformation from a document to a tiered recommendation.
// Tests and the Kubernetes collector supply their own documents, so neither
// has to reimplement the tiering rules — which is how the two stay in sync.
func (c *Catalog) workloads(e Entry, pairs []docPair) []DiscoveredWorkload {
	prod := c.Profile(e.Profile)
	limit := e.MaxResults
	if limit <= 0 {
		limit = defaultMaxResults
	}
	seen := make(map[string]bool)
	out := make([]DiscoveredWorkload, 0, min(limit, 8))
	for _, p := range pairs {
		if len(out) >= limit {
			break
		}
		for _, r := range parseDocument(p.doc.Path, p.doc.Data, parseModeOf(p.target.Parser)) {
			path := r.Path
			if path == "" {
				path = p.doc.Path
			}
			w := c.workload(e, prod, p.target, r, path)
			if w.Name == "" || w.Type == "" || seen[w.Key()] {
				continue
			}
			seen[w.Key()] = true
			out = append(out, w)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

// workload builds a DiscoveredWorkload from one parsed document, applying the
// smart risk tiering heuristics of the entry's profile.
func (c *Catalog) workload(e Entry, p Profile, t Target, r docResult, path string) DiscoveredWorkload {
	kind := r.Kind
	if kind == "" {
		kind = workloadKind(e, t)
	}
	tier := p.Tier(kind, r.Name, path, r.Ports, r.HTTPS)
	meta := map[string]string{
		"entry_id": e.ID,
		"category": e.Category,
		"runtime":  e.Runtime,
		"parser":   t.Parser,
		"signal":   tier.Signal,
	}
	if e.Vendor != "" {
		meta["vendor"] = e.Vendor
	}
	if t.Kind != "" {
		meta["target"] = t.Kind
	}
	return DiscoveredWorkload{
		Type:           displayType(e.ID),
		Name:           r.Name,
		ConfigPath:     path,
		SuggestedLevel: tier.Level,
		SuggestedDiff:  tier.Diff,
		Reason:         tier.Reason,
		EntryID:        e.ID,
		Application:    e.Name,
		Runtime:        e.Runtime,
		Namespace:      r.Namespace,
		Meta:           meta,
	}
}

// workloadKind names the workload in the tier reason sentence ("Active HTTPS
// production nginx vhost on port 443" reads better than "... production
// configuration ..."). The entry id wins where the catalogue knows the specific
// noun; otherwise the target kind describes it well enough.
func workloadKind(e Entry, t Target) string {
	if label, ok := entryKindLabels[e.ID]; ok {
		return label
	}
	switch t.Kind {
	case TargetRegistry:
		return "registry key"
	case TargetService:
		return "service"
	case TargetScheduledTask:
		return "scheduled task"
	case TargetDirWalk:
		return "configuration directory"
	default:
		return "configuration file"
	}
}

var entryKindLabels = map[string]string{
	"nginx":                   "nginx vhost",
	"apache":                  "Apache vhost",
	"caddy":                   "Caddy site",
	"haproxy":                 "HAProxy configuration",
	"postgresql":              "PostgreSQL cluster",
	"mysql":                   "MySQL configuration",
	"redis":                   "Redis instance",
	"rabbitmq":                "RabbitMQ broker",
	"rabbitmq_windows":        "RabbitMQ broker",
	"kafka":                   "Kafka broker",
	"iis":                     "IIS site",
	"mssql":                   "SQL Server instance",
	"msmq":                    "MSMQ configuration",
	"systemd_units":           "systemd unit",
	"sysctl":                  "kernel tunable set",
	"windows_services":        "service control set",
	"windows_scheduled_tasks": "scheduled task",
}

// ---------------------------------------------------------------------------
// Target expansion
// ---------------------------------------------------------------------------

// expandTarget turns one catalog target into concrete candidate documents.
//
// Every kind is best-effort and total: a pattern that cannot be expanded (a
// Windows variable unset on this host, a root that does not exist, a registry
// hive we cannot open) yields nothing rather than an error, because a discovery
// scan must never be the reason a heartbeat is late.
func (c *Catalog) expandTarget(t Target) []scanDoc {
	var out []scanDoc
	seen := make(map[string]bool)
	add := func(path string, data []byte) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		out = append(out, scanDoc{Path: path, Data: data})
	}

	switch t.Kind {
	case TargetFileGlob:
		for _, pattern := range expandPatterns(t.Patterns) {
			for _, f := range globFiles(pattern) {
				if !fileExists(f) {
					continue
				}
				data, _ := readFileLimited(f)
				add(f, data)
			}
		}
	case TargetDirWalk:
		for _, root := range expandPatterns(t.Patterns) {
			for _, f := range walkConfigFiles(root, t.Depth, t.Extensions, t.maxFiles()) {
				data, _ := readFileLimited(f)
				add(f, data)
			}
		}
	case TargetRegistry, TargetService:
		for _, d := range windowsRegistryTargets(t) {
			add(d.Path, d.Data)
		}
	case TargetScheduledTask:
		for _, d := range scheduledTaskTargets(t) {
			add(d.Path, d.Data)
		}
	}

	// Deterministic order: with a bounded result set, "the first 30 matches"
	// must mean the same 30 on every scan, or a recommendation would flicker in
	// and out of the console between heartbeats.
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// maxFiles resolves a target's file cap.
func (t Target) maxFiles() int {
	if t.MaxFiles > 0 {
		return t.MaxFiles
	}
	return defaultWalkFiles
}

// expandPatterns expands %VAR% placeholders in every pattern. An unset variable
// leaves the pattern intact so it simply matches nothing.
func expandPatterns(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, expandVars(p))
	}
	return out
}

// nameFromPath derives a human-friendly instance name from a document path:
// the file's base name without its extension ("postgresql.conf" ->
// "postgresql", "Caddyfile" -> "Caddyfile").
func nameFromPath(path string) string {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	if ext := filepath.Ext(base); ext != "" && len(base) > len(ext) {
		return strings.TrimSuffix(base, ext)
	}
	return base
}

// lastSegment returns the final component of a '\'- or '/'-separated path.
func lastSegment(path string) string {
	p := strings.TrimRight(path, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
