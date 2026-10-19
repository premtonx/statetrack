package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/statetrack/statetrack/agent/internal/discovery"
	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
)

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

// unmarshalYAML decodes a rendered document, so a test can assert the output is
// genuinely YAML rather than a string that merely looks like it.
func unmarshalYAML(t *testing.T, doc []byte, dst any) error {
	t.Helper()
	return yaml.Unmarshal(doc, dst)
}

// TestCanonicalizeIsStable is the property the whole shadow cache depends on:
// hashing the rendered text is only a valid change test if two reads of the
// same object render byte-for-byte identically. Map iteration order in Go is
// randomised, so this would fail loudly if the serializer ever stopped sorting
// keys.
func TestCanonicalizeIsStable(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":            "checkout-config",
			"namespace":       "production",
			"resourceVersion": "918273645",
			"selfLink":        "/api/v1/namespaces/production/configmaps/checkout-config",
			"managedFields":   []any{map[string]any{"manager": "kubectl"}},
			"labels":          map[string]any{"app": "checkout", "tier": "web"},
		},
		"data": map[string]any{"LOG_LEVEL": "info", "RETRIES": "3"},
		"status": map[string]any{
			"observedGeneration": 4,
		},
	}

	first := Canonicalize(obj)
	if len(first) == 0 {
		t.Fatal("Canonicalize returned nothing")
	}
	for i := 0; i < 50; i++ {
		if got := Canonicalize(obj); string(got) != string(first) {
			t.Fatalf("render %d differs from the first render:\n%s\n---\n%s", i, first, got)
		}
	}
}

// TestCanonicalizePrunesVolatilePaths pins the fields deliberately excluded,
// and the fields deliberately kept.
//
// resourceVersion and managedFields change on every write and on their own
// schedule; if either survived into the document every single watch event would
// render a different hash and the timeline would be pure noise. `status` is the
// observed-state half of an object and is not configuration. Everything else —
// including a field this agent has never heard of — must be preserved, which is
// what makes the collector forward-compatible with a newer Kubernetes.
func TestCanonicalizePrunesVolatilePaths(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"name":            "app",
			"resourceVersion": "123",
			"selfLink":        "/api/v1/x",
			"managedFields":   []any{map[string]any{"manager": "kubectl"}},
		},
		"status": map[string]any{"readyReplicas": 3},
		"spec":   map[string]any{"replicas": 3, "unknownFutureField": "kept"},
	}
	doc := string(Canonicalize(obj))

	for _, gone := range []string{"resourceVersion", "selfLink", "managedFields", "status", "readyReplicas"} {
		if strings.Contains(doc, gone) {
			t.Errorf("volatile field %q was not pruned:\n%s", gone, doc)
		}
	}
	for _, kept := range []string{"name: app", "replicas: 3", "unknownFutureField: kept"} {
		if !strings.Contains(doc, kept) {
			t.Errorf("expected %q in the document:\n%s", kept, doc)
		}
	}
}

// TestCanonicalizePreservesNumericPrecision guards the json.Number path.
//
// The API server is decoded with UseNumber precisely so a 64-bit value is not
// rounded through a float64. If the serializer then rendered those numbers as
// quoted strings, or as floats, two genuinely different int64 values could
// render identically and a real change would go unreported.
func TestCanonicalizePreservesNumericPrecision(t *testing.T) {
	const big = int64(9007199254740993) // 2^53 + 1, unrepresentable as float64
	obj := map[string]any{
		"metadata":   map[string]any{"name": "precise"},
		"generation": json.Number(fmt.Sprint(big)),
		"ratio":      json.Number("0.25"),
		"port":       json.Number("8080"),
	}
	doc := string(Canonicalize(obj))

	if !strings.Contains(doc, fmt.Sprint(big)) {
		t.Errorf("int64 generation lost precision:\n%s", doc)
	}
	if strings.Contains(doc, "9.007199254740992e+15") {
		t.Errorf("int64 generation was rendered in scientific notation:\n%s", doc)
	}
	if strings.Contains(doc, `"8080"`) {
		t.Errorf("an integer was rendered as a quoted string:\n%s", doc)
	}
	if !strings.Contains(doc, "port: 8080") {
		t.Errorf("expected an unquoted port:\n%s", doc)
	}
	if !strings.Contains(doc, "ratio: 0.25") {
		t.Errorf("expected the fractional value to stay a float:\n%s", doc)
	}
}

// TestCanonicalizeEmitsValidYAML verifies the document round-trips, so what the
// server renders in a diff view is genuinely YAML rather than a string that
// merely looks like it.
func TestCanonicalizeEmitsValidYAML(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{"name": "ingress-1", "labels": map[string]any{"a": "b"}},
		"spec": map[string]any{
			"rules": []any{
				map[string]any{"host": "checkout.example.com", "port": json.Number("443")},
				map[string]any{"host": "admin.example.com", "port": json.Number("8443")},
			},
		},
	}
	doc := Canonicalize(obj)
	var back map[string]any
	if err := unmarshalYAML(t, doc, &back); err != nil {
		t.Fatalf("rendered document is not valid YAML: %v\n%s", err, doc)
	}
	spec, _ := back["spec"].(map[string]any)
	rules, _ := spec["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules to survive the round trip, got %d:\n%s", len(rules), doc)
	}
	// List order is significant (a rule's position decides which one wins), so
	// it must be preserved rather than sorted.
	first, _ := rules[0].(map[string]any)
	if first["host"] != "checkout.example.com" {
		t.Errorf("list order changed across serialization:\n%s", doc)
	}
}

// TestCanonicalizeDropsEmptyMapsAfterPruning keeps the document free of
// phantom sections: removing `status` entirely must not leave a `status: {}`
// line, which would itself become a diff target if the field later reappeared.
func TestCanonicalizeDropsEmptyMapsAfterPruning(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{"name": "x"},
		"status":   map[string]any{"conditions": nil},
	}
	doc := string(Canonicalize(obj))
	if strings.Contains(doc, "status") {
		t.Errorf("pruning left an empty section behind:\n%s", doc)
	}
}

// ---------------------------------------------------------------------------
// Edge secret redaction
// ---------------------------------------------------------------------------

// countingStub is a deterministic stand-in for the agent's salted scrubber, so
// the assertions can name the marker instead of depending on a random salt.
// Stub records how many values it was asked to stub, which is how a test proves
// a Secret's values were redacted rather than merely unrecognised.
//
// The marker deliberately does NOT echo its input: a test double that embedded
// the secret it was given would make the leak assertion below pass vacuously.
type countingStub struct{ calls int }

func (c *countingStub) Stub(secret string) string {
	c.calls++
	return fmt.Sprintf("[REDACTED:test:#%d]", c.calls)
}

// entropyStub is a deterministic stand-in for the entropy scrubber. It redacts
// only a value whose key names a credential, which is enough to pin the
// ConfigMap path: the ordinary settings around it must survive.
//
// It implements Stubber as well as TextScrubber because the agent's real
// scrubber is one object satisfying both; a test double that satisfied only one
// interface would not catch a wiring mistake in SetStubber.
type entropyStub struct{ marker string }

func (e entropyStub) Stub(secret string) string { return e.marker }

func (e entropyStub) Text(text string) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if key, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && looksLikeCredentialKey(key) {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			out = append(out, indent+key+": "+e.marker)
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func looksLikeCredentialKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{"password", "passwd", "secret", "token", "api_key", "apikey", "credential"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

// TestRedactReplacesSecretValues is the core guarantee of Part 2: no secret
// payload leaves the cluster. The *key* is kept so a reviewer can still see
// which credential changed; the value must not survive in any form.
func TestRedactReplacesSecretValues(t *testing.T) {
	stub := &countingStub{}
	restore := swapStub(t, stub)

	plain := "s3cr3t-p@ssw0rd"
	obj := secretObject(map[string]any{
		"DB_PASSWORD": base64.StdEncoding.EncodeToString([]byte(plain)),
		"API_TOKEN":   base64.StdEncoding.EncodeToString([]byte("tok_live_abcdef")),
	})
	doc := string(Redact(obj))

	if strings.Contains(doc, plain) {
		t.Fatalf("plaintext secret leaked into the document:\n%s", doc)
	}
	if strings.Contains(doc, base64.StdEncoding.EncodeToString([]byte(plain))) {
		t.Fatalf("base64 secret leaked into the document:\n%s", doc)
	}
	// The keys must remain: a redacted diff is only useful if it still says
	// *which* credential was rotated.
	for _, key := range []string{"DB_PASSWORD", "API_TOKEN"} {
		if !strings.Contains(doc, key) {
			t.Errorf("secret key %q was dropped; the diff can no longer name the credential:\n%s", key, doc)
		}
	}
	if !strings.Contains(doc, "[REDACTED:test:") {
		t.Errorf("expected the installed stub marker:\n%s", doc)
	}
	if stub.calls != 2 {
		t.Errorf("stub called %d times, want 2 (one per secret value)", stub.calls)
	}
	restore()
}

// TestRedactDoesNotMutateInput is what keeps the collector honest.
//
// The decoded object is handed to the renderer while the API response is still
// being used; redacting in place would silently corrupt it, and the corruption
// would surface as a *missing* change rather than as an error.
func TestRedactDoesNotMutateInput(t *testing.T) {
	restore := swapStub(t, &countingStub{})
	defer restore()

	encoded := base64.StdEncoding.EncodeToString([]byte("keep-me"))
	obj := secretObject(map[string]any{"PASSWORD": encoded})
	obj["metadata"].(map[string]any)["managedFields"] = []any{map[string]any{"manager": "kubectl"}}

	_ = Redact(obj)

	data, _ := obj["data"].(map[string]any)
	if data["PASSWORD"] != encoded {
		t.Fatalf("Redact mutated the caller's object: PASSWORD = %v, want %q", data["PASSWORD"], encoded)
	}
	if _, ok := obj["metadata"].(map[string]any)["managedFields"]; !ok {
		t.Error("Redact removed managedFields from the caller's object")
	}
}

// TestRedactStubIsStableAcrossEncodings pins the property that makes a
// redacted diff readable: the same secret stored two ways must produce the
// same marker, or a rotation is indistinguishable from a re-encode.
func TestRedactStubIsStableAcrossEncodings(t *testing.T) {
	restore := swapStub(t, fixedStub{})
	defer restore()

	secret := "correct-horse-battery-staple"
	fromBase64 := string(Redact(secretObject(map[string]any{
		"K": base64.StdEncoding.EncodeToString([]byte(secret)),
	})))
	fromPlaintext := string(Redact(map[string]any{
		"metadata":   map[string]any{"name": "s"},
		"stringData": map[string]any{"K": secret},
	}))

	marker := stubFor(fixedStub{}, secret)
	if !strings.Contains(fromBase64, marker) {
		t.Errorf("base64 value did not decode before stubbing:\n%s", fromBase64)
	}
	if !strings.Contains(fromPlaintext, marker) {
		t.Errorf("stringData value was not stubbed with the same marker:\n%s", fromPlaintext)
	}

	// A different secret must produce a different marker, or the redaction
	// would be constant and the diff worthless.
	if marker == stubFor(fixedStub{}, "a-different-secret") {
		t.Error("two different secrets produced the same stub")
	}
}

// TestRedactCoversBinaryDataOnConfigMaps covers the ConfigMap half of the
// requirement. A ConfigMap is not "the Secret kind", but its `binaryData` is a
// base64 blob the entropy scrubber cannot see through, so it is stubbed first.
func TestRedactCoversBinaryDataOnConfigMaps(t *testing.T) {
	restore := swapStub(t, &countingStub{})
	defer restore()

	obj := map[string]any{
		"kind":     "ConfigMap",
		"metadata": map[string]any{"name": "app-config", "namespace": "production"},
		"data":     map[string]any{"LOG_LEVEL": "debug"},
		"binaryData": map[string]any{
			"license.pem": base64.StdEncoding.EncodeToString([]byte("-----BEGIN KEY-----")),
		},
	}
	// hasSecretBearingFields is what routes a ConfigMap through the stub pass
	// before the entropy scrubber; assert the routing decision explicitly.
	if !hasSecretBearingFields(obj) {
		t.Fatal("a ConfigMap carrying binaryData was not recognised as secret-bearing")
	}
	doc := string(canonicalFor(Resource{Plural: "configmaps", EntryID: "k8s_configmap"}, obj))
	if strings.Contains(doc, "BEGIN KEY") {
		t.Errorf("binaryData payload leaked:\n%s", doc)
	}
	if strings.Contains(doc, base64.StdEncoding.EncodeToString([]byte("-----BEGIN KEY-----"))) {
		t.Errorf("encoded binaryData payload leaked:\n%s", doc)
	}
	// A non-secret sibling key must survive untouched, or redaction would be
	// over-broad and the diff useless.
	if !strings.Contains(doc, "LOG_LEVEL: debug") {
		t.Errorf("a non-secret ConfigMap key was redacted:\n%s", doc)
	}
}

// TestConfigMapDataGoesThroughTheEntropyScrubber pins the deliberate asymmetry
// between a Secret and a ConfigMap.
//
// A Secret's values are all secret, so they are stubbed exactly. A ConfigMap is
// mostly ordinary configuration; stubbing every value would replace the whole
// document and leave a diff that says nothing but "something changed". So its
// `data` is handed to the entropy scrubber, which edits only what it recognises
// as a credential and leaves the rest readable.
func TestConfigMapDataGoesThroughTheEntropyScrubber(t *testing.T) {
	restore := swapStub(t, entropyStub{marker: "[REDACTED:entropy]"})
	defer restore()

	obj := map[string]any{
		"kind":     "ConfigMap",
		"metadata": map[string]any{"name": "checkout-config", "namespace": "production"},
		"data": map[string]any{
			"LOG_LEVEL":       "info",
			"MAX_CONNECTIONS": "200",
			"DB_PASSWORD":     "correct-horse-battery-staple",
			"FEATURE_NEW_UI":  "true",
		},
	}
	doc := string(canonicalFor(Resource{Plural: "configmaps", EntryID: "k8s_configmap"}, obj))

	if strings.Contains(doc, "correct-horse-battery-staple") {
		t.Fatalf("the credential survived the scrubber:\n%s", doc)
	}
	// The ordinary settings must still be visible: that is the whole reason a
	// ConfigMap is not stubbed wholesale.
	for _, kept := range []string{"LOG_LEVEL: info", "MAX_CONNECTIONS: \"200\"", "FEATURE_NEW_UI: \"true\""} {
		if !strings.Contains(doc, kept) {
			t.Errorf("expected ordinary configuration %q to survive:\n%s", kept, doc)
		}
	}
	// The key survives even though the value does not, so a reviewer can still
	// see which setting changed.
	if !strings.Contains(doc, "DB_PASSWORD") {
		t.Errorf("the credential's key was dropped:\n%s", doc)
	}
}

// TestRedactKeepsNonStringValues asserts redaction does not stringify a value
// that cannot be a payload: replacing a nested structure with a stub would hide
// the shape of a real change rather than the secret.
func TestRedactKeepsNonStringValues(t *testing.T) {
	restore := swapStub(t, &countingStub{})
	defer restore()

	obj := map[string]any{
		"metadata": map[string]any{"name": "s"},
		"data":     map[string]any{"NESTED": map[string]any{"keep": "structure"}},
	}
	doc := string(Redact(obj))
	if !strings.Contains(doc, "keep: structure") {
		t.Errorf("a non-string secret value was replaced instead of preserved:\n%s", doc)
	}
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

// TestAttributeUsesMostRecentManager pins the "who did it" answer.
//
// managedFields is appended in write order, so the *last* entry is the manager
// that produced the current state. Getting this backwards would blame the
// operator who created an object for a change made by a deployment controller
// hours later — which is exactly the question a post-mortem has to answer.
func TestAttributeUsesMostRecentManager(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"name": "checkout",
			"managedFields": []any{
				map[string]any{"manager": "kubectl-create", "operation": "Update", "time": "2026-10-16T09:00:00Z"},
				map[string]any{"manager": "argocd-controller", "operation": "Apply", "time": "2026-10-16T11:30:00Z"},
				map[string]any{"manager": "helm", "operation": "Update", "time": "2026-10-16T11:31:00Z"},
			},
		},
	}
	got := Attribute(obj)
	if got.Manager != "helm" {
		t.Errorf("Manager = %q, want %q (the most recent write)", got.Manager, "helm")
	}
	if got.Operation != "Update" {
		t.Errorf("Operation = %q, want Update", got.Operation)
	}
	if a := attributionName(got); a != "k8s_managed_fields" {
		t.Errorf("attributionName = %q, want k8s_managed_fields", a)
	}
}

// TestAttributeFallsBackToAnnotations covers clusters with managedFields
// disabled, where the actor is recorded as an annotation instead.
func TestAttributeFallsBackToAnnotations(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{
				"kubernetes.io/change-cause": "hotfix for checkout 500s",
				SourceIPAnnotation:           "10.42.7.19",
			},
		},
	}
	got := Attribute(obj)
	if got.Username != "hotfix for checkout 500s" {
		t.Errorf("Username = %q, want the recorded change cause", got.Username)
	}
	if got.SourceIP != "10.42.7.19" {
		t.Errorf("SourceIP = %q, want 10.42.7.19", got.SourceIP)
	}
	if a := attributionName(got); a != "k8s_annotation" {
		t.Errorf("attributionName = %q, want k8s_annotation", a)
	}
}

// TestAttributeReportsNoSourceIPWhenUnknown is a deliberate anti-hallucination
// check: stock Kubernetes does not record the writer's IP, and an audit trail
// that invents one is worse than one that says "unknown".
func TestAttributeReportsNoSourceIPWhenUnknown(t *testing.T) {
	obj := map[string]any{"metadata": map[string]any{"name": "x"}}
	if got := Attribute(obj); got.SourceIP != "" {
		t.Errorf("SourceIP = %q, want empty when the cluster records none", got.SourceIP)
	}
}

// TestGroupingManagerCollapsesControllerRollouts verifies the Level 2 grouping
// decision: a controller writing forty objects is one deployment transaction,
// while a human's `kubectl edit` is reported as itself.
func TestGroupingManagerCollapsesControllerRollouts(t *testing.T) {
	for _, tc := range []struct {
		manager string
		group   bool
	}{
		{"helm", true},
		{"argocd-controller", true},
		{"ArgoCD-Controller", true},
		{"flux", true},
		{"kubectl", false},
		{"kubectl-edit", false},
		{"", false},
	} {
		if got := len(ancestryFor(Attribution{Manager: tc.manager})) > 0; got != tc.group {
			t.Errorf("ancestryFor(%q) grouped = %v, want %v", tc.manager, got, tc.group)
		}
	}
}

// TestActorForRendersClusterActor verifies the console's existing "who changed
// this" rendering works unchanged for a cluster change.
func TestActorForRendersClusterActor(t *testing.T) {
	got := actorFor(Attribution{Manager: "argocd-controller", Operation: "Apply", SourceIP: "10.0.0.9"})
	if got == nil {
		t.Fatal("actorFor returned nil for a fully attributed change")
	}
	if got.Username != "argocd-controller" || got.ProcessName != "argocd-controller" {
		t.Errorf("actor = %+v, want the manager as both principal and process", got)
	}
	if got.RemoteIp != "10.0.0.9" {
		t.Errorf("RemoteIp = %q, want 10.0.0.9", got.RemoteIp)
	}
	if actorFor(Attribution{}) != nil {
		t.Error("actorFor invented an actor from an empty attribution")
	}
}

// ---------------------------------------------------------------------------
// Catalog projection and risk tiering
// ---------------------------------------------------------------------------

// TestCatalogResourcesComeFromTheEmbeddedCatalog asserts the collector's watch
// list is projected from the embedded manifest rather than hard-coded, which is
// what keeps the watched kinds and the tiering policy from drifting apart.
func TestCatalogResourcesComeFromTheEmbeddedCatalog(t *testing.T) {
	got := CatalogResources()
	byPlural := make(map[string]Resource, len(got))
	for _, r := range got {
		byPlural[r.Plural] = r
	}
	for _, want := range []string{"configmaps", "secrets", "deployments", "statefulsets", "ingresses"} {
		if _, ok := byPlural[want]; !ok {
			t.Errorf("catalog did not project a resource for %q", want)
		}
	}
	if r := byPlural["secrets"]; !r.Secret {
		t.Error("the secrets resource is not marked as secret-bearing")
	}
	if r := byPlural["configmaps"]; r.Secret {
		t.Error("configmaps was marked secret-bearing; it is scrubbed conditionally instead")
	}
	if r := byPlural["secrets"]; r.ProductionProfile.ForceLevel != discovery.LevelCritical {
		t.Errorf("secrets production profile level = %d, want %d",
			r.ProductionProfile.ForceLevel, discovery.LevelCritical)
	}
}

// TestRecommendationsTierProductionNamespaceCritical covers the smart tiering
// requirement for a Kubernetes target: an object in a production namespace is
// offered as Level 1 Critical with full text diff.
func TestRecommendationsTierProductionNamespaceCritical(t *testing.T) {
	c := newTestCollector(t)
	c.recordNamespace(Resource{Plural: "secrets", EntryID: "k8s_secret"}, "production")

	ws := c.Recommendations()
	if len(ws) != 1 {
		t.Fatalf("got %d recommendations, want 1: %+v", len(ws), ws)
	}
	w := ws[0]
	if w.SuggestedLevel != discovery.LevelCritical {
		t.Errorf("level = %d, want %d for a production namespace", w.SuggestedLevel, discovery.LevelCritical)
	}
	if !w.SuggestedDiff {
		t.Error("SuggestedDiff = false, want a full text diff for a production namespace")
	}
	if w.Type != discovery.TypeK8sSecret {
		t.Errorf("Type = %q, want %q", w.Type, discovery.TypeK8sSecret)
	}
	if w.Namespace != "production" {
		t.Errorf("Namespace = %q, want production", w.Namespace)
	}
	if w.Runtime != discovery.RuntimeKubernetes {
		t.Errorf("Runtime = %q, want %q", w.Runtime, discovery.RuntimeKubernetes)
	}
	if w.ConfigPath != "/k8s/test-cluster/production/secrets/**" {
		t.Errorf("ConfigPath = %q, want the tracked object glob", w.ConfigPath)
	}
	if w.Meta["signal"] != "namespace_tier" {
		t.Errorf("signal = %q, want namespace_tier", w.Meta["signal"])
	}
}

// TestRecommendationsTierStagingNamespaceDrift is the other half of the
// heuristic: a non-production namespace is offered as Level 3 Drift with
// metadata and a hash only.
func TestRecommendationsTierStagingNamespaceDrift(t *testing.T) {
	c := newTestCollector(t)
	c.recordNamespace(Resource{Plural: "configmaps", EntryID: "k8s_configmap"}, "staging")

	ws := c.Recommendations()
	if len(ws) != 1 {
		t.Fatalf("got %d recommendations, want 1", len(ws))
	}
	if ws[0].SuggestedLevel != discovery.LevelDrift {
		t.Errorf("level = %d, want %d for a staging namespace", ws[0].SuggestedLevel, discovery.LevelDrift)
	}
	if ws[0].SuggestedDiff {
		t.Error("SuggestedDiff = true, want metadata + hash only for a staging namespace")
	}
	if ws[0].Meta["signal"] != "staging_namespace" {
		t.Errorf("signal = %q, want staging_namespace", ws[0].Meta["signal"])
	}
}

// TestStagingNamespaceTieringIsNotOverbroad guards the tiering against the
// dangerous direction: a namespace that merely *contains* a marker must not be
// mistaken for production, and a paid production namespace must not be
// downgraded because its name happens to embed a staging token.
func TestStagingNamespaceTieringIsNotOverbroad(t *testing.T) {
	c := newTestCollector(t)
	for _, ns := range []string{"production", "payments", "prod-payments"} {
		c.recordNamespace(Resource{Plural: "secrets", EntryID: "k8s_secret"}, ns)
	}
	ws := c.Recommendations()
	if len(ws) != 3 {
		t.Fatalf("got %d recommendations, want 3", len(ws))
	}
	for _, w := range ws {
		if w.SuggestedLevel != discovery.LevelCritical {
			t.Errorf("namespace %q tiered at %d, want %d", w.Namespace, w.SuggestedLevel, discovery.LevelCritical)
		}
	}
}

// TestRecommendationsAreDeterministic protects the console from reshuffling
// rows between heartbeats, which would make the review queue unusable.
func TestRecommendationsAreDeterministic(t *testing.T) {
	c := newTestCollector(t)
	for _, ns := range []string{"zeta", "alpha", "production", "beta"} {
		c.recordNamespace(Resource{Plural: "configmaps", EntryID: "k8s_configmap"}, ns)
		c.recordNamespace(Resource{Plural: "secrets", EntryID: "k8s_secret"}, ns)
	}
	want := recommendationKeys(c.Recommendations())
	for i := 0; i < 20; i++ {
		if got := recommendationKeys(c.Recommendations()); !equalSlices(got, want) {
			t.Fatalf("recommendation order changed between calls:\n%v\n---\n%v", want, got)
		}
	}
}

// TestObjectPathShape pins the tracked document path.
//
// It is an absolute POSIX-style path on purpose: the existing classifier, glob
// matcher and shadow-store prefix scans then work on a Kubernetes object with
// no change at all, which is what makes the cluster a first-class citizen of
// the same pipeline instead of a parallel implementation.
func TestObjectPathShape(t *testing.T) {
	c := newTestCollector(t)
	obj := map[string]any{"metadata": map[string]any{"name": "checkout", "namespace": "production"}}

	if got, want := c.objectPath(Resource{Plural: "secrets"}, obj),
		"/k8s/test-cluster/production/secrets/checkout"; got != want {
		t.Errorf("objectPath = %q, want %q", got, want)
	}
	clusterScoped := map[string]any{"metadata": map[string]any{"name": "cluster-thing"}}
	if got, want := c.objectPath(Resource{Plural: "configmaps"}, clusterScoped),
		"/k8s/test-cluster/_cluster/configmaps/cluster-thing"; got != want {
		t.Errorf("cluster-scoped objectPath = %q, want %q", got, want)
	}
	if got := c.objectPath(Resource{Plural: "secrets"}, map[string]any{"metadata": map[string]any{}}); got != "" {
		t.Errorf("an object with no name produced path %q, want empty", got)
	}
}

// TestScopes covers the least-privilege namespace scoping: no configured list
// means one cluster-wide request, and a configured list means one request per
// namespace so a plain namespace-scoped Role is sufficient.
func TestScopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"unset", nil, []string{""}},
		{"empty entries are ignored", []string{"", "  "}, []string{""}},
		{"configured", []string{"production", "payments"}, []string{"production", "payments"}},
		{"de-duplicated", []string{"production", "production", " payments "}, []string{"production", "payments"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCollectorWith(t, func(o *Options) { o.Namespaces = tc.in })
			if got := c.scopes(); !equalSlices(got, tc.want) {
				t.Errorf("scopes() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Collector: seed, observe, redaction, namespace scoping
// ---------------------------------------------------------------------------

// TestCollectorSeedsBaselineWithoutEvents verifies a first run on an existing
// cluster records the baseline silently. Without it, bringing the watcher up
// would report the entire cluster as a change and bury the real timeline.
func TestCollectorSeedsBaselineWithoutEvents(t *testing.T) {
	srv, client := clusterServer(t, map[string]string{
		"secrets": `{"metadata":{"resourceVersion":"10"},"items":[
			{"metadata":{"name":"db-credentials","namespace":"production","resourceVersion":"5"},
			 "data":{"PASSWORD":"` + base64.StdEncoding.EncodeToString([]byte("hunter2")) + `"}}]}`,
	})

	var seeded, events int
	var mu sync.Mutex
	var seedContent []byte
	col, err := New(Options{
		Client:     client,
		Resources:  []Resource{{Plural: "secrets", EntryID: "k8s_secret", Secret: true}},
		Classifier: testClassifier(t),
		Seed: func(_ context.Context, _ string, content []byte, _ time.Time) error {
			mu.Lock()
			defer mu.Unlock()
			seeded++
			seedContent = content
			return nil
		},
		Handle: func(context.Context, engine.DocEvent) error {
			mu.Lock()
			defer mu.Unlock()
			events++
			return nil
		},
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := col.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if seeded != 1 {
		t.Errorf("seeded %d objects, want 1", seeded)
	}
	if events != 0 {
		t.Errorf("Seed emitted %d events, want 0", events)
	}
	if strings.Contains(string(seedContent), "hunter2") {
		t.Fatalf("the baseline cache received a cleartext secret:\n%s", seedContent)
	}
	if !strings.Contains(string(seedContent), "[REDACTED") {
		t.Errorf("the baseline was not scrubbed:\n%s", seedContent)
	}
	if srv.requests() == 0 {
		t.Error("the collector did not call the API server")
	}
}

// TestCollectorObservesChangeAsDocEvent walks the full path for one modified
// object: canonical render, redaction, attribution, and dispatch to the engine
// under the tracked path.
func TestCollectorObservesChangeAsDocEvent(t *testing.T) {
	restore := swapStub(t, entropyStub{marker: "[REDACTED:entropy]"})
	defer restore()

	var got engine.DocEvent
	col, err := New(Options{
		Client:     clientForServer(t, ""),
		Resources:  []Resource{{Plural: "configmaps", EntryID: "k8s_configmap"}},
		Classifier: testClassifier(t),
		Handle: func(_ context.Context, de engine.DocEvent) error {
			got = de
			return nil
		},
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      "checkout-config",
			"namespace": "production",
			"managedFields": []any{
				map[string]any{"manager": "kubectl", "operation": "Update", "time": "2026-10-16T11:00:00Z"},
			},
		},
		"data": map[string]any{"DB_PASSWORD": base64.StdEncoding.EncodeToString([]byte("rotate-me"))},
	}
	if err := col.observe(context.Background(), Resource{Plural: "configmaps", EntryID: "k8s_configmap"}, obj, false); err != nil {
		t.Fatalf("observe: %v", err)
	}

	if got.Path != "/k8s/test-cluster/production/configmaps/checkout-config" {
		t.Errorf("Path = %q, want the tracked object path", got.Path)
	}
	if got.TargetType != "k8s_configmap" {
		t.Errorf("TargetType = %q, want k8s_configmap", got.TargetType)
	}
	if got.Actor.GetUsername() != "kubectl" {
		t.Errorf("Actor = %+v, want the managedFields manager", got.Actor)
	}
	if got.Attribution != "k8s_managed_fields" {
		t.Errorf("Attribution = %q, want k8s_managed_fields", got.Attribution)
	}
	// A ConfigMap carrying a password-shaped key is scrubbed even though its
	// catalog entry is not the Secret entry.
	if strings.Contains(string(got.Content), "rotate-me") {
		t.Errorf("a ConfigMap password reached the engine in cleartext:\n%s", got.Content)
	}
	if !strings.Contains(string(got.Content), "DB_PASSWORD") || !strings.Contains(string(got.Content), "[REDACTED:entropy]") {
		t.Errorf("expected the ConfigMap's password to be stubbed in place:\n%s", got.Content)
	}

	// Deletion must arrive as nil content, which the engine interprets as
	// "the document no longer exists".
	got = engine.DocEvent{}
	if err := col.observe(context.Background(), Resource{Plural: "configmaps", EntryID: "k8s_configmap"}, obj, true); err != nil {
		t.Fatalf("observe deleted: %v", err)
	}
	if got.Content != nil {
		t.Errorf("deleted object carried content: %s", got.Content)
	}
}

// TestCollectorHonoursBlacklist keeps the Level 0 escape hatch working for
// cluster objects: an excluded pattern must stop the object before it costs a
// render, a hash or a diff.
func TestCollectorHonoursBlacklist(t *testing.T) {
	handled := 0
	col, err := New(Options{
		Client: clientForServer(t, ""),
		Resources: []Resource{{
			Plural: "configmaps", EntryID: "k8s_configmap",
		}},
		Classifier: testClassifier(t, "/k8s/**"),
		Handle: func(context.Context, engine.DocEvent) error {
			handled++
			return nil
		},
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	obj := map[string]any{"metadata": map[string]any{"name": "x", "namespace": "production"}}
	if err := col.observe(context.Background(), Resource{Plural: "configmaps", EntryID: "k8s_configmap"}, obj, false); err != nil {
		t.Fatal(err)
	}
	if handled != 0 {
		t.Errorf("a blacklisted object was handed to the engine %d times", handled)
	}
}

// TestCollectorScopesListRequests asserts a configured namespace list produces
// one list per namespace, which is what makes a namespace-scoped Role work.
func TestCollectorScopesListRequests(t *testing.T) {
	srv, client := clusterServer(t, map[string]string{
		"configmaps": `{"metadata":{"resourceVersion":"1"},"items":[]}`,
	})
	col, err := New(Options{
		Client:     client,
		Resources:  []Resource{{Plural: "configmaps", EntryID: "k8s_configmap"}},
		Classifier: testClassifier(t),
		Namespaces: []string{"production", "payments"},
		Seed:       func(context.Context, string, []byte, time.Time) error { return nil },
		Handle:     func(context.Context, engine.DocEvent) error { return nil },
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := col.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	paths := srv.seen()
	for _, want := range []string{
		"/api/v1/namespaces/production/configmaps",
		"/api/v1/namespaces/payments/configmaps",
	} {
		if !containsString(paths, want) {
			t.Errorf("expected a list request for %q, saw %v", want, paths)
		}
	}
	if containsString(paths, "/api/v1/configmaps") {
		t.Errorf("a cluster-wide list was issued despite a configured namespace list: %v", paths)
	}
}

// TestRunIsANoOpWithoutNamespaceAccess verifies a forbidden list degrades to a
// warning rather than a crash: an agent whose RBAC is incomplete must keep
// collecting everything else.
func TestRunIsANoOpWithoutNamespaceAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"kind":"Status","message":"configmaps is forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	col, err := New(Options{
		Client:     clientForServer(t, srv.URL),
		Resources:  []Resource{{Plural: "configmaps", EntryID: "k8s_configmap"}},
		Classifier: testClassifier(t),
		Seed:       func(context.Context, string, []byte, time.Time) error { return nil },
		Handle:     func(context.Context, engine.DocEvent) error { return nil },
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := col.Seed(context.Background()); err == nil {
		t.Error("Seed reported success on a 403 response")
	}
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

// TestResourcePathPinsGroupsAndVersions covers the version pinning that lets
// one agent binary monitor a heterogeneous fleet without an API discovery
// round-trip (which would itself be a network call whose result could differ
// between hosts, making the tracked path unstable).
func TestResourcePathPinsGroupsAndVersions(t *testing.T) {
	for _, tc := range []struct{ resource, namespace, want string }{
		{"configmaps", "production", "/api/v1/namespaces/production/configmaps"},
		{"secrets", "", "/api/v1/secrets"},
		{"deployments", "payments", "/apis/apps/v1/namespaces/payments/deployments"},
		{"statefulsets", "production", "/apis/apps/v1/namespaces/production/statefulsets"},
		{"ingresses", "production", "/apis/networking.k8s.io/v1/namespaces/production/ingresses"},
	} {
		if got := resourcePath(tc.resource, tc.namespace); got != tc.want {
			t.Errorf("resourcePath(%q, %q) = %q, want %q", tc.resource, tc.namespace, got, tc.want)
		}
	}
}

// TestListDecodesPreciseNumbers is the client half of the precision guarantee.
func TestListDecodesPreciseNumbers(t *testing.T) {
	srv, client := clusterServer(t, map[string]string{
		"configmaps": `{"metadata":{"resourceVersion":"42"},"items":[
			{"metadata":{"name":"precise","namespace":"production"},
			 "data":{"GEN":"9007199254740993"}}]}`,
	})
	_ = srv
	res, err := client.List(context.Background(), "configmaps", "production")
	if err != nil {
		t.Fatal(err)
	}
	if res.ResourceVersion != "42" {
		t.Errorf("ResourceVersion = %q, want 42", res.ResourceVersion)
	}
	if len(res.Items) != 1 {
		t.Fatalf("decoded %d items, want 1", len(res.Items))
	}
	data, _ := res.Items[0]["data"].(map[string]any)
	if data["GEN"] != "9007199254740993" {
		t.Errorf("GEN = %v (%T), want the exact string or a precise number", data["GEN"], data["GEN"])
	}
}

// TestMalformedListObjectIsSkipped asserts one unreadable object cannot discard
// the other four hundred in the same response.
func TestMalformedListObjectIsSkipped(t *testing.T) {
	srv, client := clusterServer(t, map[string]string{
		"configmaps": `{"metadata":{"resourceVersion":"1"},"items":[
			{"metadata":{"name":"good"}}, "this-is-not-an-object"]}`,
	})
	_ = srv
	res, err := client.List(context.Background(), "configmaps", "")
	if err != nil {
		t.Fatalf("a malformed item failed the whole list: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("decoded %d items, want 1", len(res.Items))
	}
}

// TestWatchStreamsEvents covers the watch decoder: newline-delimited JSON
// frames, uppercased event types, BOOKMARK handling and per-event resource
// versions — the values the collector uses to know where to resume from.
func TestWatchStreamsEvents(t *testing.T) {
	const stream = `{"type":"ADDED","object":{"metadata":{"name":"a","namespace":"production","resourceVersion":"11"}}}
{"type":"MODIFIED","object":{"metadata":{"name":"a","namespace":"production","resourceVersion":"12"}}}
{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"13"}}}
{"type":"DELETED","object":{"metadata":{"name":"a","namespace":"production","resourceVersion":"14"}}}
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			http.Error(w, "not a watch", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(stream))
	}))
	defer srv.Close()

	client := clientForServer(t, srv.URL)
	events, err := client.Watch(context.Background(), "configmaps", "production", "10")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.Type)
		// Every event must carry the resource version it reported, including a
		// BOOKMARK: that is the whole purpose of the frame, and a decoder that
		// dropped it would leave the collector unable to resume a stream.
		if ev.ResourceVersion == "" {
			t.Errorf("%s event lost its resource version", ev.Type)
		}
		if ev.Type == "BOOKMARK" {
			// A bookmark carries metadata only; there must be no payload for a
			// caller to mistakenly treat as an object change.
			if _, ok := ev.Object["data"]; ok {
				t.Errorf("BOOKMARK carried a payload: %+v", ev.Object)
			}
		}
	}
	want := []string{"ADDED", "MODIFIED", "BOOKMARK", "DELETED"}
	if !equalSlices(got, want) {
		t.Errorf("watch events = %v, want %v", got, want)
	}
}

// TestWatchExpiredVersionIsReportedAsGone pins the HTTP 410 contract. It must
// be distinguishable from a generic error: 410 means "re-list", while any other
// failure means "retry the watch".
func TestWatchExpiredVersionIsReportedAsGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"kind":"Status","reason":"Expired"}`, http.StatusGone)
	}))
	defer srv.Close()

	client := clientForServer(t, srv.URL)
	if _, err := client.List(context.Background(), "configmaps", ""); err != ErrGone {
		t.Fatalf("List on a 410 returned %v, want ErrGone", err)
	}
}

// TestNewClientRejectsBadEndpoint covers the configuration errors that would
// otherwise fail confusingly later.
func TestNewClientRejectsBadEndpoint(t *testing.T) {
	if _, err := NewClient(Config{}); err == nil {
		t.Error("NewClient accepted an empty endpoint")
	}
	if _, err := NewClient(Config{Endpoint: "https://cluster.example:6443", CAData: []byte("not a certificate")}); err == nil {
		t.Error("NewClient accepted a CA bundle containing no certificates")
	}
}

// TestClientDerivesClusterNameFromEndpoint keeps tracked paths stable when no
// explicit cluster name is configured.
func TestClientDerivesClusterNameFromEndpoint(t *testing.T) {
	client, err := NewClient(Config{Endpoint: "https://10.0.0.7:6443"})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Cluster(); got != "10.0.0.7:6443" {
		t.Errorf("Cluster() = %q, want the API server host", got)
	}
	if got := client.DefaultNamespace(); got != DefaultNamespace {
		t.Errorf("DefaultNamespace() = %q, want %q", got, DefaultNamespace)
	}
}

// TestInClusterConfigReportsNotInCluster asserts the no-op path used by every
// non-pod host is a clear, non-fatal error.
func TestInClusterConfigReportsNotInCluster(t *testing.T) {
	t.Setenv(envHost, "")
	t.Setenv(envPort, "")
	if _, err := InClusterConfig(); err == nil {
		t.Error("InClusterConfig succeeded outside a cluster")
	}
}

// ---------------------------------------------------------------------------
// Protobuf / discovery interoperability
// ---------------------------------------------------------------------------

// TestRecommendationsConvertToWireFormat verifies a cluster recommendation
// survives the same conversion the host scanner's results use, so the console
// needs no Kubernetes-specific rendering path.
func TestRecommendationsConvertToWireFormat(t *testing.T) {
	c := newTestCollector(t)
	c.recordNamespace(Resource{Plural: "secrets", EntryID: "k8s_secret"}, "production")

	pb := discovery.ToPB(c.Recommendations())
	if len(pb) != 1 {
		t.Fatalf("converted %d workloads, want 1", len(pb))
	}
	w := pb[0]
	if w.GetNamespace() != "production" {
		t.Errorf("Namespace = %q, want production", w.GetNamespace())
	}
	if w.GetRuntime() != discovery.RuntimeKubernetes {
		t.Errorf("Runtime = %q, want %q", w.GetRuntime(), discovery.RuntimeKubernetes)
	}
	if w.GetEntryId() != "k8s_secret" {
		t.Errorf("EntryId = %q, want k8s_secret", w.GetEntryId())
	}
	if w.GetSuggestedLevel() != discovery.LevelCritical {
		t.Errorf("SuggestedLevel = %d, want %d", w.GetSuggestedLevel(), discovery.LevelCritical)
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testCluster = "test-cluster"

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// swapStub installs a scrubber for the duration of a test and returns the
// restore function. Redaction is the one package-level setting the collector
// mutates, so a test must be able to pin it without leaking into the next test.
func swapStub(t *testing.T, s Stubber) func() {
	t.Helper()
	prev := secretStub
	SetStubber(s)
	restore := func() { secretStub = prev }
	t.Cleanup(restore)
	return restore
}

// secretObject builds a minimal Secret carrying `data`.
func secretObject(data map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": "app-secrets", "namespace": "production"},
		"type":       "Opaque",
		"data":       data,
	}
}

// stubFor renders the marker a Stubber would produce for secret, so an
// assertion can name it instead of depending on a random salt.
func stubFor(s Stubber, secret string) string { return s.Stub(secret) }

type recordingServer struct {
	*httptest.Server
	mu   sync.Mutex
	urls []string
}

func (s *recordingServer) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.urls)
}

func (s *recordingServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.urls...)
}

// clusterServer serves canned list responses keyed by resource name and records
// the paths requested, so tests can assert both decoding and request shaping.
func clusterServer(t *testing.T, lists map[string]string) (*recordingServer, *Client) {
	t.Helper()
	srv := &recordingServer{}
	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.mu.Lock()
		srv.urls = append(srv.urls, r.URL.Path)
		srv.mu.Unlock()
		for resource, body := range lists {
			if strings.HasSuffix(r.URL.Path, "/"+resource) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
				return
			}
		}
		http.Error(w, `{"kind":"Status","message":"not found"}`, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, clientForServer(t, srv.URL)
}

// clientForServer builds a client for a test server. The URL overrides
// Endpoint; cluster naming is pinned so tracked paths are predictable.
func clientForServer(t *testing.T, base string) *Client {
	t.Helper()
	if base == "" {
		base = "https://api.test.invalid:6443"
	}
	client, err := NewClient(Config{Endpoint: base, Cluster: testCluster})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func newTestCollector(t *testing.T) *Collector {
	return newTestCollectorWith(t, nil)
}

func newTestCollectorWith(t *testing.T, mutate func(*Options)) *Collector {
	t.Helper()
	o := Options{
		Client:     clientForServer(t, ""),
		Classifier: testClassifier(t),
		Handle:     func(context.Context, engine.DocEvent) error { return nil },
		Seed:       func(context.Context, string, []byte, time.Time) error { return nil },
		Logger:     testLogger(),
	}
	if mutate != nil {
		mutate(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testClassifier(t *testing.T, extraBlacklist ...string) *limiter.Classifier {
	t.Helper()
	c, err := limiter.NewClassifier(limiter.ClassifierConfig{ExtraBlacklist: extraBlacklist})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func recommendationKeys(ws []discovery.DiscoveredWorkload) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Key())
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
