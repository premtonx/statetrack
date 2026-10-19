package k8s

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/discovery"
	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"go.yaml.in/yaml/v3"
)

// DefaultResyncInterval is how often a full re-list runs as a safety net behind
// the watch stream, so a watch gap — an expired resource version, or a dropped
// connection the client did not notice — cannot hide a change indefinitely.
const DefaultResyncInterval = 10 * time.Minute

// DefaultWatchRetry is the delay before restarting a watch that failed.
const DefaultWatchRetry = 5 * time.Second

// Options configures the collector.
type Options struct {
	// Client is the cluster API client. Required.
	Client *Client
	// Resources defaults to the Kubernetes entries of the embedded catalog.
	Resources  []Resource
	Classifier *limiter.Classifier
	// Handle receives a canonicalized, redacted object change
	// (engine.HandleDoc). Required.
	Handle func(context.Context, engine.DocEvent) error
	// Seed records an object's baseline without an event (engine.SeedDoc).
	Seed func(ctx context.Context, path string, content []byte, modTime time.Time) error
	// Namespaces restricts watching to a list of namespaces. Empty watches
	// every namespace the service account can list, which is the default: a
	// cluster-scoped agent should not need a config edit when a namespace is
	// created.
	Namespaces []string
	// ResyncInterval defaults to DefaultResyncInterval.
	ResyncInterval time.Duration
	Logger         *slog.Logger
}

// Resource is one watched resource kind, projected from the enterprise catalog
// so the watched kinds and the tiering policy cannot drift apart.
type Resource struct {
	// Plural is the API resource name ("configmaps").
	Plural string
	// EntryID is the catalog entry that configures it ("k8s_configmap").
	EntryID string
	// Application is the catalog entry's display name.
	Application string
	// Secret marks a resource whose payloads are redacted at the edge.
	Secret bool
	// ProductionProfile / DevProfile / StagingNamespaces are the entry's
	// tiering inputs, used to recommend a policy rule per namespace.
	ProductionProfile discovery.Profile
	DevProfile        discovery.Profile
	StagingNamespaces []string
}

// Collector watches a cluster's configuration objects.
type Collector struct {
	o       Options
	log     *slog.Logger
	cluster string

	mu sync.Mutex
	// namespaces records the namespaces seen per resource, so the collector
	// can recommend a policy rule for each one it actually found. A cluster
	// has namespaces nobody would guess from a manifest, so the suggestions
	// have to come from observation.
	namespaces map[string]map[string]bool
}

// New builds a collector.
func New(o Options) (*Collector, error) {
	if o.Client == nil {
		return nil, errors.New("k8s: client is required")
	}
	if o.ResyncInterval <= 0 {
		o.ResyncInterval = DefaultResyncInterval
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Resources == nil {
		o.Resources = CatalogResources()
	}
	return &Collector{
		o:          o,
		log:        o.Logger.With("collector", "kubernetes"),
		cluster:    o.Client.Cluster(),
		namespaces: make(map[string]map[string]bool),
	}, nil
}

// Cluster returns the cluster's display name.
func (c *Collector) Cluster() string { return c.cluster }

// CatalogResources projects the embedded enterprise catalog's Kubernetes
// entries onto the resource kinds this collector watches.
//
// Reading the catalog rather than hard-coding a list is what makes the cluster
// watcher and the host scanners one system: adding a Kubernetes resource to
// catalog.yaml is enough for the collector to start watching it, and the risk
// tiering arrives with it.
func CatalogResources() []Resource {
	cat := discovery.MustCatalog()
	var out []Resource
	for _, e := range cat.EntriesForRuntime(discovery.RuntimeKubernetes) {
		for _, t := range e.Targets {
			if t.Kind != discovery.TargetK8sResource || t.Resource == "" {
				continue
			}
			out = append(out, Resource{
				Plural:            t.Resource,
				EntryID:           e.ID,
				Application:       e.Name,
				Secret:            e.ID == "k8s_secret",
				ProductionProfile: cat.Profile(e.Profile),
				DevProfile:        cat.Profile(e.DevProfile),
				StagingNamespaces: e.StagingNamespaces,
			})
		}
	}
	return out
}

// Run reconciles every resource and keeps a watch running per resource until
// ctx is done. It blocks, so callers start it in its own goroutine.
func (c *Collector) Run(ctx context.Context) error {
	if c.o.Handle == nil {
		return errors.New("k8s: Handle is required")
	}
	scopes := c.scopes()
	c.log.Info("kubernetes collector started", "cluster", c.cluster,
		"resources", len(c.o.Resources), "scopes", len(scopes))

	var wg sync.WaitGroup
	for _, r := range c.o.Resources {
		for _, scope := range scopes {
			r, scope := r, scope
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.runScope(ctx, r, scope)
			}()
		}
	}
	wg.Wait()
	return nil
}

// scopes returns the namespace scopes to list and watch.
//
// One empty scope means "every namespace in one request", which needs a
// ClusterRole. A configured namespace list produces one scope per namespace,
// which works with a plain namespace-scoped Role — the least-privilege shape a
// security team is most likely to approve for a monitoring agent.
func (c *Collector) scopes() []string {
	if len(c.o.Namespaces) == 0 {
		return []string{""}
	}
	out := make([]string, 0, len(c.o.Namespaces))
	seen := make(map[string]bool, len(c.o.Namespaces))
	for _, ns := range c.o.Namespaces {
		ns = strings.TrimSpace(ns)
		if ns == "" || seen[ns] {
			continue
		}
		seen[ns] = true
		out = append(out, ns)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// runScope reconciles one resource in one namespace scope and keeps a watch
// running, with a periodic full resync as a safety net.
func (c *Collector) runScope(ctx context.Context, r Resource, scope string) {
	resync := time.NewTicker(c.o.ResyncInterval)
	defer resync.Stop()

	for {
		if ctx.Err() != nil {
			return
		}
		version, err := c.reconcile(ctx, r, scope)
		if err != nil {
			c.log.Warn("kubernetes resync failed", "resource", r.Plural, "namespace", scopeLabel(scope), "err", err)
			if !sleep(ctx, DefaultWatchRetry) {
				return
			}
			continue
		}

		// An empty resource version with no error means the API server did not
		// report one; polling the resync interval is the only correct fallback.
		if version == "" {
			select {
			case <-ctx.Done():
				return
			case <-resync.C:
				continue
			}
		}

		watchCtx, cancel := context.WithCancel(ctx)
		events, err := c.o.Client.Watch(watchCtx, r.Plural, scope, version)
		if err != nil {
			cancel()
			if errors.Is(err, ErrGone) {
				continue // re-list: the server expired the version
			}
			c.log.Warn("kubernetes watch failed", "resource", r.Plural, "namespace", scopeLabel(scope), "err", err)
			if !sleep(ctx, DefaultWatchRetry) {
				return
			}
			continue
		}

		c.consume(watchCtx, r, events)
		cancel()

		// The stream ended. Re-list rather than resuming from the last seen
		// version: a closed stream is not guaranteed to have delivered every
		// event, and a fresh list plus its resource version is the only way to
		// know the shadow state is complete again.
		select {
		case <-ctx.Done():
			return
		case <-resync.C:
		case <-time.After(DefaultWatchRetry):
		}
	}
}

// scopeLabel renders a scope for a log line, naming the cluster-wide case
// rather than logging an empty string.
func scopeLabel(scope string) string {
	if scope == "" {
		return "all-namespaces"
	}
	return scope
}

// consume applies every event on a watch stream until it closes.
func (c *Collector) consume(ctx context.Context, r Resource, events <-chan WatchEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			switch ev.Type {
			case "BOOKMARK":
				// Advances the resource version only; nothing to apply.
				continue
			case "ERROR":
				// The server rejected the watch. Closing the stream and
				// re-listing is the handler, and it is clearer to do that
				// explicitly than to fall through.
				return
			}
			if ev.Object == nil {
				continue
			}
			deleted := ev.Type == "DELETED"
			if err := c.observe(ctx, r, ev.Object, deleted); err != nil {
				c.log.Warn("kubernetes apply failed", "resource", r.Plural, "err", err)
			}
		}
	}
}

// reconcile lists the resource, applies every object, and returns the list's
// resource version for the watch to start from.
func (c *Collector) reconcile(ctx context.Context, r Resource, namespace string) (string, error) {
	res, err := c.o.Client.List(ctx, r.Plural, namespace)
	if err != nil {
		return "", err
	}
	for _, obj := range res.Items {
		// reconcile never fails the whole list on one bad object: a single
		// unreadable object must not stop the other four hundred.
		if err := c.observe(ctx, r, obj, false); err != nil {
			c.log.Warn("kubernetes reconcile failed", "resource", r.Plural, "err", err)
		}
	}
	return res.ResourceVersion, nil
}

// observe renders an object and hands it to the engine.
func (c *Collector) observe(ctx context.Context, r Resource, obj map[string]any, deleted bool) error {
	path := c.objectPath(r, obj)
	if path == "" {
		return nil
	}
	if c.o.Classifier != nil && c.o.Classifier.Blacklisted(path) {
		return nil
	}
	// Record the namespace so the collector can recommend a tiered policy rule
	// for it; a deleted object still tells us the namespace exists.
	if ns := nestedString(obj, "metadata", "namespace"); ns != "" {
		c.recordNamespace(r, ns)
	}

	// Redaction happens before anything else touches the payload: the
	// canonical document is what gets hashed, cached, diffed and transmitted,
	// so scrubbing here is what guarantees no cleartext secret leaves the
	// cluster. A ConfigMap is scrubbed too, because it routinely holds a
	// connection password.
	var content []byte
	if !deleted {
		content = canonicalFor(r, obj)
		if content == nil {
			return nil
		}
	}

	if c.o.Handle == nil {
		return nil
	}
	attr := Attribute(obj)
	return c.o.Handle(ctx, engine.DocEvent{
		Path:        path,
		TargetType:  targetTypeFor(r),
		Content:     content,
		ModTime:     c.modTime(obj),
		Actor:       actorFor(attr),
		Ancestry:    ancestryFor(attr),
		Attribution: attributionName(attr),
	})
}

// Seed records every object's baseline without emitting events. It is used on
// a first run so bringing the collector up on an existing cluster does not
// report the entire cluster as a change.
func (c *Collector) Seed(ctx context.Context) error {
	if c.o.Seed == nil {
		return errors.New("k8s: Seed is required")
	}
	for _, r := range c.o.Resources {
		for _, scope := range c.scopes() {
			res, err := c.o.Client.List(ctx, r.Plural, scope)
			if err != nil {
				return err
			}
			for _, obj := range res.Items {
				path := c.objectPath(r, obj)
				if path == "" {
					continue
				}
				if ns := nestedString(obj, "metadata", "namespace"); ns != "" {
					c.recordNamespace(r, ns)
				}
				content := canonicalFor(r, obj)
				if content == nil {
					continue
				}
				if err := c.o.Seed(ctx, path, content, c.modTime(obj)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// canonicalFor renders an object, redacting it when it can carry a payload.
//
// A Secret's values are all secret, so they are stubbed exactly. Anything else
// goes through the entropy scrubber, which keeps the document readable while
// still catching a credential it can recognise — a ConfigMap is ordinary
// configuration, and stubbing all of it would replace the whole document and
// leave a diff that says nothing but "something changed".
//
// `binaryData` on a ConfigMap is the exception: it is base64 by definition and
// the entropy scrubber cannot see through the encoding, so it is stubbed first
// and the remainder of the document is then scrubbed.
func canonicalFor(r Resource, obj map[string]any) []byte {
	if r.Secret {
		return Redact(obj)
	}
	if !hasSecretBearingFields(obj) {
		return Scrub(obj)
	}
	stubbed, err := yaml.Marshal(prune(obj, "", opaquePathsFor(obj)))
	if err != nil {
		return nil
	}
	return []byte(scrubText(string(stubbed)))
}

// objectPath renders the tracked document path for an object.
//
// The shape is an absolute POSIX-style path so the existing classifier, glob
// matcher and shadow-store prefix scans work on it unchanged — a Kubernetes
// object is tracked by exactly the same machinery as /etc/nginx/nginx.conf.
func (c *Collector) objectPath(r Resource, obj map[string]any) string {
	name := nestedString(obj, "metadata", "name")
	if name == "" {
		return ""
	}
	ns := nestedString(obj, "metadata", "namespace")
	if ns == "" {
		ns = clusterScope
	}
	return "/k8s/" + c.cluster + "/" + ns + "/" + r.Plural + "/" + name
}

// clusterScope is the pseudo-namespace used in paths for cluster-scoped
// objects, so the path shape stays uniform.
const clusterScope = "_cluster"

// modTime reads the object's creation or last-write time.
func (c *Collector) modTime(obj map[string]any) time.Time {
	for _, key := range []string{"creationTimestamp", "deletionTimestamp"} {
		if t := parseRFC3339(nestedString(obj, "metadata", key)); !t.IsZero() {
			return t
		}
	}
	return time.Now()
}

func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// hasSecretBearingFields reports whether an object carries an encoded payload
// field, so a ConfigMap holding a base64 blob is stubbed even though its catalog
// entry is not the Secret entry.
//
// It is deliberately narrower than "any secret-shaped key": a ConfigMap's `data`
// is configuration, and the entropy scrubber handles the credential hiding in it.
// Only an opaque base64 field needs to be stubbed before the scrubber runs,
// because the scrubber cannot see through the encoding.
func hasSecretBearingFields(obj map[string]any) bool {
	for _, key := range opaqueValuePaths {
		if _, ok := obj[key]; ok {
			return true
		}
	}
	return false
}

// targetTypeFor names the TargetResource type reported for a resource.
func targetTypeFor(r Resource) string {
	switch r.Plural {
	case "configmaps":
		return "k8s_configmap"
	case "secrets":
		return "k8s_secret"
	case "deployments":
		return "k8s_deployment"
	case "statefulsets":
		return "k8s_statefulset"
	case "ingresses":
		return "k8s_ingress"
	}
	return "k8s_" + strings.TrimSuffix(r.Plural, "s")
}

// actorFor renders the attribution as an ActorContext so the console's
// existing "who changed this" rendering works for cluster changes too.
func actorFor(a Attribution) *pb.ActorContext {
	if a.Manager == "" && a.Username == "" {
		return nil
	}
	username := a.Username
	if username == "" {
		username = a.Manager
	}
	return &pb.ActorContext{
		Username:    username,
		ProcessName: a.Manager,
		Cmdline:     a.Operation,
		RemoteIp:    a.SourceIP,
	}
}

// ancestryFor builds the grouping ancestry.
//
// A controller that owns a whole rollout (helm, Argo CD, Flux) becomes the
// grouping root, so its many object writes collapse into one Level 2
// transaction instead of surfacing as a storm of unrelated single edits. An
// interactive `kubectl edit` deliberately gets no ancestry: a human's single
// edit should be reported as itself.
func ancestryFor(a Attribution) []limiter.Process {
	if !isGroupingManager(a.Manager) {
		return nil
	}
	return []limiter.Process{{Name: a.Manager}}
}

// groupingManagers are the managers whose writes are a deliberate, batched
// deployment rather than an interactive edit.
var groupingManagers = map[string]bool{
	"helm":                          true,
	"argocd-controller":             true,
	"argocd-application-controller": true,
	"flux":                          true,
	"kustomize-controller":          true,
}

func isGroupingManager(m string) bool {
	return groupingManagers[strings.ToLower(m)]
}

// attributionName records how the actor was determined, for event metadata.
func attributionName(a Attribution) string {
	switch {
	case a.Manager != "":
		return "k8s_managed_fields"
	case a.Username != "":
		return "k8s_annotation"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------

// recordNamespace remembers that a resource exists in a namespace.
func (c *Collector) recordNamespace(r Resource, ns string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := c.namespaces[r.EntryID]
	if set == nil {
		set = make(map[string]bool)
		c.namespaces[r.EntryID] = set
	}
	set[ns] = true
}

// Recommendations reports the cluster workloads the console should offer to
// onboard, one per resource kind and namespace, tiered with the catalog's smart
// risk heuristics.
//
// This is the cluster half of Part 1's discovery: a Kubernetes entry has no
// host target, so the host scanner deliberately skips it, and the collector is
// what turns "there are Secrets in the payments namespace" into an actionable,
// correctly-tiered recommendation. The tier is the starting point an operator
// accepts, not a decision imposed on them.
func (c *Collector) Recommendations() []discovery.DiscoveredWorkload {
	c.mu.Lock()
	snapshot := make(map[string][]string, len(c.namespaces))
	for entry, set := range c.namespaces {
		ns := make([]string, 0, len(set))
		for name := range set {
			ns = append(ns, name)
		}
		snapshot[entry] = ns
	}
	c.mu.Unlock()

	var out []discovery.DiscoveredWorkload
	for _, r := range c.o.Resources {
		for _, ns := range snapshot[r.EntryID] {
			out = append(out, c.recommend(r, ns))
		}
	}
	sortWorkloads(out)
	return out
}

// recommend builds one recommendation for a resource kind in a namespace.
func (c *Collector) recommend(r Resource, ns string) discovery.DiscoveredWorkload {
	profile := r.ProductionProfile
	if namesStaging(r, ns) && r.DevProfile.Diff != r.ProductionProfile.Diff {
		profile = r.DevProfile
	}
	level, signal, reason := tierForNamespace(r, ns, profile)

	return discovery.DiscoveredWorkload{
		Type:           workloadType(r),
		Name:           ns + "/" + strings.TrimSuffix(r.Plural, "s"),
		ConfigPath:     "/k8s/" + c.cluster + "/" + ns + "/" + r.Plural + "/**",
		SuggestedLevel: level,
		SuggestedDiff:  profile.Diff,
		Reason:         reason,
		EntryID:        r.EntryID,
		Application:    r.Application,
		Runtime:        discovery.RuntimeKubernetes,
		Namespace:      ns,
		Meta: map[string]string{
			"entry_id": r.EntryID,
			"cluster":  c.cluster,
			"resource": r.Plural,
			"signal":   signal,
		},
	}
}

// tierForNamespace resolves the impact level and the explanation for one
// resource kind in one namespace.
func tierForNamespace(r Resource, ns string, profile discovery.Profile) (int, string, string) {
	level := profile.ForceLevel
	switch {
	case level == 0 && profile.Diff:
		level = discovery.LevelCritical
	case level == 0:
		level = discovery.LevelDrift
	}
	if namesStaging(r, ns) {
		return level, "staging_namespace",
			"Non-production namespace " + ns + " (" + r.Application + "); tracked with metadata and a hash only"
	}
	return level, "namespace_tier",
		"Production namespace " + ns + " (" + r.Application + "); full scrubbed YAML diff with an immediate alert"
}

// namesStaging reports whether a namespace is non-production for a resource:
// either explicitly listed in the catalog entry, or matching the production
// profile's staging patterns.
func namesStaging(r Resource, ns string) bool {
	for _, s := range r.StagingNamespaces {
		if strings.EqualFold(s, ns) {
			return true
		}
	}
	return r.ProductionProfile.StagingNamespace(ns)
}

// workloadType maps a resource kind onto the console's workload-type string,
// reusing the host scanner's identifiers so the recommendations table renders a
// cluster object the same way it renders a file.
func workloadType(r Resource) string {
	if t, ok := discovery.WorkloadTypeForEntry(r.EntryID); ok {
		return t
	}
	return r.EntryID
}

// sortWorkloads orders recommendations deterministically so the console does
// not reshuffle rows between heartbeats.
func sortWorkloads(ws []discovery.DiscoveredWorkload) {
	sort.Slice(ws, func(i, j int) bool {
		a, b := ws[i], ws[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
}

// sleep waits for d, reporting false when ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
