package k8s

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultNamespace is used when a namespace is not supplied.
const DefaultNamespace = "default"

// Service account material mounted by the kubelet into every pod that uses the
// default service-account token projection.
const (
	saDir      = "/var/run/secrets/kubernetes.io/serviceaccount"
	saToken    = "token"
	saCACert   = "ca.crt"
	saNS       = "namespace"
	envHost    = "KUBERNETES_SERVICE_HOST"
	envPort    = "KUBERNETES_SERVICE_PORT"
	apiTimeout = 30 * time.Second
)

// Config describes how to reach one cluster's API server.
type Config struct {
	// Endpoint is the API server base URL, e.g. "https://10.0.0.1:6443".
	Endpoint string
	// Token is the bearer token (a service account token in-cluster).
	Token string
	// CAData is the PEM-encoded CA bundle that signed the API server
	// certificate. Empty means "use the system pool".
	CAData []byte
	// Namespace is the default namespace for namespaced reads.
	Namespace string
	// InsecureSkipVerify disables certificate verification. It exists for a
	// cluster whose API server certificate is not signed by the mounted CA;
	// it should be off in any real deployment.
	InsecureSkipVerify bool
	// Cluster is a display name used in the tracked document path. It defaults
	// to the API server host.
	Cluster string
}

// InClusterConfig builds a Config from the pod service account mount.
//
// An air-gapped cluster is reached exactly the same way a connected one is:
// through the in-cluster service account, with no kubeconfig discovery, no
// cloud metadata probe and no network call of our own.
func InClusterConfig() (Config, error) {
	host, port := os.Getenv(envHost), os.Getenv(envPort)
	if host == "" || port == "" {
		return Config{}, fmt.Errorf("k8s: %s/%s not set; not running in a cluster", envHost, envPort)
	}
	cfg := Config{
		Endpoint:  "https://" + host + ":" + port,
		Namespace: DefaultNamespace,
		Cluster:   host,
	}
	if b, err := os.ReadFile(filepath.Join(saDir, saToken)); err == nil {
		cfg.Token = strings.TrimSpace(string(b))
	} else {
		return Config{}, fmt.Errorf("k8s: read service account token: %w", err)
	}
	if b, err := os.ReadFile(filepath.Join(saDir, saCACert)); err == nil {
		cfg.CAData = b
	}
	if b, err := os.ReadFile(filepath.Join(saDir, saNS)); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			cfg.Namespace = ns
		}
	}
	return cfg, nil
}

// Client is a minimal, read-only Kubernetes API client.
//
// It is deliberately read-only: every call goes through Get (and the watch
// variant of Get), so the agent's RBAC can be limited to `get`, `list` and
// `watch` — see deploy/k8s/rbac.yaml. A monitoring agent that cannot write to
// the cluster it watches cannot break it.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient builds a client from cfg.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("k8s: endpoint is required")
	}
	if _, err := url.Parse(cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("k8s: invalid endpoint %q: %w", cfg.Endpoint, err)
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}
	if len(cfg.CAData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CAData) {
			return nil, fmt.Errorf("k8s: CA bundle contains no certificates")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	if cfg.Cluster == "" {
		if u, err := url.Parse(cfg.Endpoint); err == nil {
			cfg.Cluster = u.Host
		} else {
			cfg.Cluster = cfg.Endpoint
		}
	}
	if cfg.Namespace == "" {
		cfg.Namespace = DefaultNamespace
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 0}}, nil
}

// Cluster returns the display name used in tracked document paths.
func (c *Client) Cluster() string { return c.cfg.Cluster }

// DefaultNamespace returns the namespace used when none is supplied.
func (c *Client) DefaultNamespace() string { return c.cfg.Namespace }

// ListResult is a list response.
type ListResult struct {
	Items []map[string]any
	// ResourceVersion is the list's snapshot version, used to start a watch
	// without missing the writes in between.
	ResourceVersion string
}

// WatchEvent is one event from a watch stream.
type WatchEvent struct {
	// Type is "ADDED", "MODIFIED", "DELETED" or "BOOKMARK".
	Type string
	// Object is the raw object (nil for a BOOKMARK).
	Object map[string]any
	// ResourceVersion is the version this event reported.
	ResourceVersion string
}

// ErrGone reports a watch that must be restarted from a fresh list (HTTP 410).
// Kubernetes expires old resource versions; the correct response is to re-list
// rather than to keep watching from a version the server no longer has.
var ErrGone = fmt.Errorf("k8s: resource version expired")

// List reads every object of a resource kind. namespace is empty for
// cluster-scoped kinds.
func (c *Client) List(ctx context.Context, resource, namespace string) (*ListResult, error) {
	body, err := c.get(ctx, resourcePath(resource, namespace), nil)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return decodeList(body)
}

// Watch streams events for a resource kind starting at resourceVersion.
//
// The returned channel is closed when ctx is cancelled, the server closes the
// stream, or an error occurs. A caller seeing it close unexpectedly should
// re-list; ErrGone means the resource version expired, which is the server
// telling us to re-list.
func (c *Client) Watch(ctx context.Context, resource, namespace, resourceVersion string) (<-chan WatchEvent, error) {
	q := url.Values{}
	q.Set("watch", "true")
	q.Set("allowWatchBookmarks", "true")
	if resourceVersion != "" {
		q.Set("resourceVersion", resourceVersion)
	}
	body, err := c.get(ctx, resourcePath(resource, namespace), q)
	if err != nil {
		return nil, err
	}
	out := make(chan WatchEvent, 16)
	go func() {
		defer close(out)
		defer body.Close()
		c.streamWatch(ctx, body, out)
	}()
	return out, nil
}

// resourcePath builds the API path for a resource, handling both the core
// group (served under /api/v1) and a named group (served under
// /apis/<group>/<version>).
func resourcePath(resource, namespace string) string {
	var b strings.Builder
	if group := resourceAPIGroup(resource); group != "" {
		b.WriteString("/apis/")
		b.WriteString(group)
		b.WriteString("/")
		b.WriteString(resourceAPIVersion(resource))
	} else {
		b.WriteString("/api/")
		b.WriteString(resourceAPIVersion(resource))
	}
	if namespace != "" {
		b.WriteString("/namespaces/")
		b.WriteString(url.PathEscape(namespace))
	}
	b.WriteString("/")
	b.WriteString(resource)
	return b.String()
}

// decodeObject decodes one JSON object, preserving numeric precision with
// UseNumber.
//
// A plain json.Unmarshal turns every number into a float64, which silently
// loses precision above 2^53 and renders large integers in scientific notation
// (9007199254740993 becomes 9.007199254740992e+15). For a change detector that
// is a correctness bug: two *different* int64 values could hash identically and
// a real change would go unreported. json.Number keeps the original text, so
// the canonical document preserves exactly what the API server sent.
func decodeObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// streamWatch decodes the newline-delimited JSON watch stream onto out.
func (c *Client) streamWatch(ctx context.Context, body io.Reader, out chan<- WatchEvent) {
	dec := json.NewDecoder(bufio.NewReaderSize(body, 64<<10))
	dec.UseNumber()
	for {
		if ctx.Err() != nil {
			return
		}
		var raw struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := dec.Decode(&raw); err != nil {
			return
		}
		ev := WatchEvent{Type: strings.ToUpper(raw.Type)}
		if len(raw.Object) > 0 {
			if obj, err := decodeObject(raw.Object); err == nil {
				ev.Object = obj
				ev.ResourceVersion = nestedString(obj, "metadata", "resourceVersion")
			}
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// get performs an authenticated GET and returns the response body. The caller
// closes it.
func (c *Client) get(ctx context.Context, path string, q url.Values) (io.ReadCloser, error) {
	u := strings.TrimRight(c.cfg.Endpoint, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	watch := q != nil && q.Get("watch") == "true"
	reqCtx := ctx
	if !watch {
		// A list is bounded; a watch is long-lived and relies on its own
		// context plus the server's timeout.
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, apiTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("k8s: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "statetrack-agent")
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s: GET %s: %w", path, err)
	}
	switch {
	case resp.StatusCode == http.StatusGone:
		closeBody(resp.Body)
		return nil, ErrGone
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		closeBody(resp.Body)
		return nil, fmt.Errorf("k8s: GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp.Body, nil
}

// closeBody closes and drains a response body so the connection can be reused.
func closeBody(b io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(b, 4<<10))
	_ = b.Close()
}

// decodeList turns a Kubernetes list response into its items.
func decodeList(body io.Reader) (*ListResult, error) {
	var raw struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []json.RawMessage `json:"items"`
	}
	dec := json.NewDecoder(body)
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("k8s: decode list: %w", err)
	}
	res := &ListResult{ResourceVersion: raw.Metadata.ResourceVersion}
	res.Items = make([]map[string]any, 0, len(raw.Items))
	for _, item := range raw.Items {
		obj, err := decodeObject(item)
		if err != nil {
			// One malformed object must not discard the whole list.
			continue
		}
		res.Items = append(res.Items, obj)
	}
	return res, nil
}

// nestedString reads a nested string field, returning "" when any step is
// missing or has the wrong shape.
func nestedString(obj map[string]any, path ...string) string {
	var cur any = obj
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[key]
	}
	s, _ := cur.(string)
	return s
}

// ---------------------------------------------------------------------------
// Resource group / version resolution
// ---------------------------------------------------------------------------

// apiVersionOf maps a resource to the API group and version the collector
// reads it from.
//
// The versions are pinned to the versions that have been served since
// Kubernetes 1.19 and remain served today, which is what lets one agent
// version monitor a heterogeneous fleet without an API discovery round-trip.
// Discovery would also be a network call whose result could vary between hosts
// in the same fleet, making the tracked document path unstable.
var apiVersionOf = map[string]string{
	"configmaps":   "/api/v1",
	"secrets":      "/api/v1",
	"deployments":  "/apis/apps/v1",
	"statefulsets": "/apis/apps/v1",
	"ingresses":    "/apis/networking.k8s.io/v1",
}

func resourceAPIVersion(resource string) string {
	if v, ok := apiVersionOf[resource]; ok {
		if i := strings.LastIndex(v, "/"); i >= 0 {
			return v[i+1:]
		}
	}
	return "v1"
}

func resourceAPIGroup(resource string) string {
	v, ok := apiVersionOf[resource]
	if !ok || strings.HasPrefix(v, "/api/") {
		return ""
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(v, "/apis/"), "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		return trimmed[:i]
	}
	return trimmed
}
