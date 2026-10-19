// Package k8s watches Kubernetes objects — ConfigMaps, Secrets, Deployments,
// StatefulSets and Ingresses — and feeds their mutations into the same
// classify -> shadow-diff -> spool pipeline the Linux and Windows collectors
// use.
//
// Everything about *what* to watch comes from the embedded enterprise catalog
// (agent/internal/discovery/catalog.yaml), so a cluster and a fleet of VMs are
// described by one manifest. This package only knows how to read the cluster
// and how to render an object as a stable text document.
//
// The client is deliberately stdlib-only: it speaks the Kubernetes REST API
// directly using the in-cluster service-account token. Pulling in client-go
// would add a large dependency and a second, independent notion of "what
// changed" to an agent whose whole design is one shared diff engine, and it
// would need a kubeconfig discovery step that is meaningless in the air-gapped
// environments this agent targets.
package k8s

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"go.yaml.in/yaml/v3"
)

// volatilePaths are object paths dropped before serialization because they
// change on every write or on their own schedule, and would therefore make a
// diff meaningless noise.
//
// The exclusion list is a *path* list rather than a per-kind list of kept
// fields: diffing the whole object minus the churn is what makes the collector
// future-proof, because a field added by a newer Kubernetes release is
// monitored automatically instead of being silently invisible.
var volatilePaths = map[string]bool{
	// resourceVersion increments on every write, including our own reads'
	// side effects, so it is pure noise in a diff.
	"metadata.resourceVersion": true,
	// managedFields carries per-write timestamps and is extracted separately
	// as *attribution* rather than diffed.
	"metadata.managedFields": true,
	// selfLink was removed in Kubernetes 1.24 but lingers on older clusters.
	"metadata.selfLink": true,
	// status is the observed-state half of an object; it changes constantly
	// and is not configuration.
	"status": true,
}

// secretValuePaths are the paths whose values are redacted at the edge before
// an object is cached or transmitted.
//
// A Secret's `data` is base64, `stringData` is plaintext, and `binaryData` is
// base64. All three are treated as secret-bearing on a Secret: every value in
// them is a credential by definition, so stubbing each one is both exact and
// cheap.
var secretValuePaths = []string{
	"data",
	"stringData",
	"binaryData",
}

// opaqueValuePaths are the paths stubbed on a resource that is not a Secret.
//
// Only `binaryData` qualifies. It is base64 by definition, and the entropy
// scrubber works on text — it cannot see through the encoding to notice that a
// decoded blob is a certificate or a key. A ConfigMap's `data`, by contrast, is
// ordinary configuration that occasionally carries a credential, so it is left
// to the scrubber: stubbing all of it would replace the whole document and leave
// a diff that says nothing but "something changed".
var opaqueValuePaths = []string{
	"binaryData",
}

// Stubber renders the deterministic redaction marker for a secret value. It is
// satisfied by *redact.Scrubber; the interface exists so tests can pin the
// marker instead of depending on a random salt.
type Stubber interface {
	Stub(secret string) string
}

// TextScrubber redacts secret-shaped content from an already-rendered document.
// It is satisfied by *redact.Scrubber: the lexical pattern list plus the
// Shannon-entropy pass that finds an unlabelled API key or password.
//
// The two interfaces exist because a Secret and a ConfigMap need different
// treatment. Every value in a Secret is secret, so stubbing each of them is both
// cheap and exact. A ConfigMap is mostly ordinary configuration that happens to
// carry the occasional credential, and stubbing all of it would replace the
// whole document — including the keys an operator needs to see — which is why it
// goes through the entropy scrubber instead.
type TextScrubber interface {
	Text(text string) string
}

// Canonicalize renders a Kubernetes object as a stable YAML document.
//
// Stability is the whole point: the shadow tracker hashes this text, so two
// reads of an unchanged object must produce byte-identical output or every
// poll would report a spurious change. Map keys are sorted (yaml.v3 does this),
// slices keep their order (Kubernetes lists such as `containers` and `rules`
// are ordered and their order is significant), and the volatile paths above are
// removed.
//
// The input map is not modified.
func Canonicalize(obj map[string]any) []byte {
	out, err := yaml.Marshal(prune(obj, "", nil))
	if err != nil {
		// yaml.Marshal only fails on values it cannot represent, and the
		// object came from encoding/json, so every value is representable.
		// Returning nil makes the caller skip the object rather than report a
		// corrupt change.
		return nil
	}
	return out
}

// Redact renders a Kubernetes Secret as a canonical YAML document with every
// secret-bearing value replaced by a deterministic stub.
//
// Pruning and redaction happen in a single deep-copying pass, which is what
// guarantees the caller's object is never mutated: a collector shares the
// decoded object with the API response cache, and redacting it in place would
// silently corrupt that cache.
//
// This is the function the collector calls for a Secret, where *every* value in
// `data`/`stringData` is by definition a credential, so stubbing each one is
// both exact and cheap. A ConfigMap takes the entropy-scrubber path instead (see
// Scrub) because stubbing all of it would replace the whole document and leave a
// diff that says nothing but "something changed".
//
// Either way, no secret payload is ever hashed, cached, diffed, or transmitted.
func Redact(obj map[string]any) []byte {
	allowed := secretPathsFor(obj)
	out, err := yaml.Marshal(prune(obj, "", allowed))
	if err != nil {
		return nil
	}
	return out
}

// Scrub renders an object as canonical YAML and then passes the text through
// the lexical + Shannon-entropy secret scrubber.
//
// This is the ConfigMap path. A ConfigMap is ordinary configuration that
// occasionally carries a credential, so the document has to stay readable —
// replacing every value would destroy the diff that makes ConfigMap monitoring
// worthwhile. The scrubber edits only what it recognises as a secret: a
// key=value whose key names a credential, a PEM block, or an unlabelled
// high-entropy token. The key is preserved either way, so a reviewer still sees
// *which* setting changed.
func Scrub(obj map[string]any) []byte {
	doc := Canonicalize(obj)
	if doc == nil {
		return nil
	}
	return []byte(scrubText(string(doc)))
}

// scrubText applies the installed text scrubber, falling back to the identity
// when none is installed so the package remains usable (and testable) alone.
func scrubText(text string) string {
	if t, ok := textScrubber.(TextScrubber); ok && t != nil {
		return t.Text(text)
	}
	return text
}

// secretPathsFor returns the secret-bearing top-level keys actually present in
// obj, so the document shape (a Secret's `data`, a ConfigMap's `binaryData`) is
// redacted without treating unrelated keys as secrets.
//
// The returned set is keyed by the secret-bearing key's own path. prune treats
// "the children of a path in this set" as scalars to redact, which is what
// replaces `data: {DB_PASSWORD: <base64>}` with `data: {DB_PASSWORD:
// [REDACTED:...]}` — keeping the key so a reviewer can see which credential
// changed, while the value never leaves the cluster.
func secretPathsFor(obj map[string]any) map[string]bool {
	var out map[string]bool
	for _, key := range secretValuePaths {
		if _, ok := obj[key]; !ok {
			continue
		}
		if out == nil {
			out = make(map[string]bool, len(secretValuePaths))
		}
		out[key] = true
	}
	return out
}

// opaquePathsFor returns the base64-by-definition keys to stub on a resource
// that is not a Secret. See opaqueValuePaths for why the list is shorter.
func opaquePathsFor(obj map[string]any) map[string]bool {
	var out map[string]bool
	for _, key := range opaqueValuePaths {
		if _, ok := obj[key]; !ok {
			continue
		}
		if out == nil {
			out = make(map[string]bool, len(opaqueValuePaths))
		}
		out[key] = true
	}
	return out
}

// stubValue renders the redaction marker for one secret value.
//
// A base64 value is decoded first when it decodes cleanly, so the *same* secret
// stored in two objects gets the *same* stub — which is what lets a reviewer
// distinguish a credential rotation from an unrelated edit. A value that is not
// a string cannot be a payload, so it is kept verbatim rather than stringified
// into a stub that would hide the value's real shape.
func stubValue(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
		return secretStub.Stub(string(decoded))
	}
	return secretStub.Stub(s)
}

// secretStub is the scrubber used for Kubernetes secret payloads. It is a
// package-level variable so the collector can point it at the agent's
// salt-derived scrubber; the default is a deterministic, salt-less stub that
// keeps the package usable (and testable) on its own.
var secretStub Stubber = fixedStub{}

// textScrubber is the entropy scrubber used for ConfigMap documents. The
// default is the identity (see scrubText): a package that has not been wired up
// still renders a readable document, and the agent always installs the real one.
var textScrubber TextScrubber = identityScrubber{}

// identityScrubber is the no-op default for a stubless build.
type identityScrubber struct{}

func (identityScrubber) Text(text string) string { return text }

// SetStubber installs the agent's salted scrubbers: s stubs a Secret's values
// and text redacts a ConfigMap's document.
//
// It is deliberately one call for both. A caller that installed only half of the
// pair would leave a redaction gap that no test would catch, because each half
// looks correct on its own.
func SetStubber(s Stubber) {
	if s != nil {
		secretStub = s
	}
	if t, ok := s.(TextScrubber); ok {
		textScrubber = t
	}
}

// fixedStub is the fallback marker for a stubless build. It is still
// deterministic and still hides the payload; it simply is not keyed to the
// installation salt, so the same secret in two *hosts* would produce the same
// marker. The agent always installs its salted scrubber, so this is only reachable
// in tests and in a standalone use of this package.
type fixedStub struct{}

func (fixedStub) Stub(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "[REDACTED:sha256:" + hex.EncodeToString(sum[:4]) + "]"
}

// prune deep-copies obj with the volatile paths removed and the secret-bearing
// paths redacted. secrets holds the paths whose *child* values are replaced by
// a stub.
//
// A map left empty by pruning is dropped, so removing `status` does not leave a
// `status: {}` line behind in the document — which would itself be a phantom
// diff target if the field later reappeared.
func prune(v any, path string, secrets map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		redactChildren := secrets[path]
		for k, child := range t {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			if volatilePaths[childPath] {
				continue
			}
			if redactChildren {
				out[k] = stubValue(child)
				continue
			}
			if m, isMap := child.(map[string]any); isMap && len(m) == 0 {
				continue
			}
			out[k] = prune(child, childPath, secrets)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, child := range t {
			out = append(out, prune(child, path, secrets))
		}
		return out
	case json.Number:
		// json.Number is a string type, so yaml would render every number as a
		// quoted string. Converting it back to a real number keeps the document
		// readable ("port: 8080", not 'port: "8080"') without giving up the
		// precision UseNumber preserved: an integer stays an int64, and only a
		// genuinely fractional value becomes a float.
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	default:
		return v
	}
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

// Attribution names who changed an object, and from where.
type Attribution struct {
	// Manager is the last non-empty managedFields manager (e.g. "kubectl",
	// "helm", "argocd-controller").
	Manager string
	// Operation is the last recorded management operation ("Apply" or
	// "Update").
	Operation string
	// Username is the actor recorded in the object's annotations, when the
	// cluster writes one.
	Username string
	// SourceIP is the originating API client IP when the cluster records one.
	// stock Kubernetes does not populate it, so it is reported empty rather
	// than guessed: an audit trail with an invented IP is worse than one that
	// says "unknown".
	SourceIP string
}

// SourceIPAnnotation is the annotation key clusters with an API audit
// admission webhook commonly use to stamp the originating client IP onto an
// object. It is read when present and ignored otherwise.
const SourceIPAnnotation = "statetrack.io/source-ip"

// Attribute extracts change attribution from an object's managedFields.
//
// managedFields is the cluster's own record of which controller or client last
// wrote each field set, which is exactly the lineage an operator wants when a
// production object changes unannounced: "was this helm, or was this someone
// with kubectl?".
//
// The most recent entry wins: Kubernetes appends in write order, so the final
// manager is the one responsible for the current state. Entries are ordered by
// their recorded time, falling back to field order when times are absent.
func Attribute(obj map[string]any) Attribution {
	md, _ := obj["metadata"].(map[string]any)
	if md == nil {
		return Attribution{}
	}
	var a Attribution
	fields, _ := md["managedFields"].([]any)
	best := ""
	for _, f := range fields {
		fm, ok := f.(map[string]any)
		if !ok {
			continue
		}
		manager, _ := fm["manager"].(string)
		if manager == "" {
			continue
		}
		if t, _ := fm["time"].(string); t >= best {
			best = t
			a.Manager = manager
			a.Operation, _ = fm["operation"].(string)
		}
	}

	// Some clusters record the actor as an annotation rather than in
	// managedFields (and managedFields can be disabled entirely).
	ann, _ := md["annotations"].(map[string]any)
	for _, key := range []string{"statetrack.io/actor", "kubernetes.io/change-cause"} {
		if v, ok := ann[key].(string); ok && v != "" {
			a.Username = v
			break
		}
	}
	if v, ok := ann[SourceIPAnnotation].(string); ok {
		a.SourceIP = v
	}
	// The API server records the writer's identity per managed-field entry on
	// some cluster versions; prefer it over the annotation when present.
	if a.Username == "" {
		for _, f := range fields {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			if sub, ok := fm["subresource"].(string); ok && sub != "" {
				continue
			}
			if u, ok := fm["manager"].(string); ok && strings.HasPrefix(u, "https://") {
				a.Username = u
			}
		}
	}
	return a
}

// ManagerOrDefault returns the attribution manager, or fallback when the
// cluster records none.
func (a Attribution) ManagerOrDefault(fallback string) string {
	if a.Manager != "" {
		return a.Manager
	}
	return fallback
}
