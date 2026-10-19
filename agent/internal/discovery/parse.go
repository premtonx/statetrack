package discovery

import (
	"encoding/json"
	"strconv"
	"strings"
)

// docResult is one instance found inside a matched document: an nginx server
// block, an IIS site, a systemd unit. Most files yield exactly one (the file
// itself), which is why the "raw" parser exists: it lets the catalog describe
// an application whose internal structure the agent does not need to
// understand, while still getting a name, a path and a risk tier.
type docResult struct {
	// Name is the instance name shown in the console.
	Name string
	// Kind is the workload noun used in the tiering sentence.
	Kind string
	// Path overrides the matched document's path when the instance's real
	// configuration lives elsewhere (an IIS site's web.config).
	Path string
	// Ports are the TCP ports the instance binds; nil when it has no socket.
	Ports []int
	// HTTPS reports an explicit TLS-terminating bind.
	HTTPS bool
	// Namespace is set for cluster-scoped documents.
	Namespace string
}

// parserFunc turns a matched document into the instances it contains.
type parserFunc func(path string, data []byte) []docResult

// parseDocument dispatches on the catalog's `parser` field. An unknown parser
// degrades to "raw" rather than failing the scan, so a catalog extended in the
// field still produces a labelled recommendation instead of nothing.
func parseDocument(path string, data []byte, parser string) []docResult {
	fn, ok := parsers[parser]
	if !ok {
		fn = parseRaw
	}
	return fn(path, data)
}

// parseModeOf maps the catalog's parser name onto the parse mode used by
// parseDocument, so callers can resolve the parser once per target.
func parseModeOf(parser string) string {
	if _, ok := parsers[parser]; ok {
		return parser
	}
	return "raw"
}

var parsers = map[string]parserFunc{
	"raw":     parseRaw,
	"nginx":   parseNginxDoc,
	"apache":  parseApacheDoc,
	"iis":     parseIISDoc,
	"systemd": parseSystemdDoc,
	"ini":     parseINIDoc,
	"json":    parseJSONDoc,
	"yaml":    parseRaw,
}

// parseRaw treats a document as one opaque configuration instance.
func parseRaw(path string, _ []byte) []docResult {
	return []docResult{{Name: nameFromPath(path)}}
}

// parseSystemdDoc names each unit after its file, which is what an operator
// types in `systemctl status <name>`.
func parseSystemdDoc(path string, _ []byte) []docResult {
	return []docResult{{Name: nameFromPath(path), Kind: "systemd unit"}}
}

// parseNginxDoc expands the server blocks of an nginx configuration. A file
// with no server block (a snippet, an upstream-only file) still yields one
// instance named after the file.
func parseNginxDoc(path string, data []byte) []docResult {
	servers := parseNginxServers(data)
	if len(servers) == 0 {
		return []docResult{{Name: nameFromPath(path), Kind: "nginx configuration"}}
	}
	out := make([]docResult, 0, len(servers))
	for i, s := range servers {
		name := s.primaryName()
		if name == "" || name == "_" {
			// Unnamed catch-all: distinguish siblings by index so three
			// anonymous blocks do not collapse into one recommendation.
			name = nameFromPath(path)
			if len(servers) > 1 {
				name += "#" + strconv.Itoa(i+1)
			}
		}
		out = append(out, docResult{
			Name:  name,
			Kind:  "nginx vhost",
			Ports: s.ports,
			HTTPS: s.https,
		})
	}
	return out
}

// parseApacheDoc expands the <VirtualHost> blocks of an Apache fragment.
func parseApacheDoc(path string, data []byte) []docResult {
	blocks := parseApacheVHosts(data)
	if len(blocks) == 0 {
		return []docResult{{Name: nameFromPath(path), Kind: "Apache configuration"}}
	}
	out := make([]docResult, 0, len(blocks))
	for i, b := range blocks {
		name := b.name
		if name == "" || name == "_" {
			name = nameFromPath(path)
			if len(blocks) > 1 {
				name += "#" + strconv.Itoa(i+1)
			}
		}
		out = append(out, docResult{
			Name:  name,
			Kind:  "Apache vhost",
			Ports: b.ports,
			HTTPS: b.https,
		})
	}
	return out
}

// parseIISDoc expands an applicationHost.config into its sites, preferring each
// site's own web.config as the tracked document. That preference matters: the
// site's real configuration is usually the nested web.config, and pointing the
// policy rule at it means the diff a reviewer sees is the app's, not the whole
// server's.
func parseIISDoc(path string, data []byte) []docResult {
	sites := parseIISSites(data)
	if len(sites) == 0 {
		return []docResult{{Name: "IIS configuration", Kind: "IIS configuration", Path: path}}
	}
	out := make([]docResult, 0, len(sites))
	for _, s := range sites {
		out = append(out, docResult{
			Name:  s.Name,
			Kind:  "IIS site",
			Path:  s.primaryPath(path),
			Ports: s.ports(),
			HTTPS: s.https(),
		})
	}
	return out
}

// parseINIDoc reads a `key = value` configuration, picking up the listening
// port so a database or cache instance can still be tiered from a real signal.
func parseINIDoc(path string, data []byte) []docResult {
	r := docResult{Name: nameFromPath(path), Kind: "configuration file"}
	for _, line := range strings.Split(string(data), "\n") {
		line = stripComment(strings.TrimSpace(line))
		if line == "" || line[0] == '[' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if !strings.Contains(key, "port") && !strings.Contains(key, "listen") {
			continue
		}
		if p, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && p > 0 && p <= 65535 {
			r.Ports = append(r.Ports, p)
		}
	}
	return []docResult{r}
}

// parseJSONDoc extracts a listening port from a JSON configuration, which is how
// a Docker daemon's `hosts` list ("tcp://0.0.0.0:2376") is discovered.
func parseJSONDoc(path string, data []byte) []docResult {
	r := docResult{Name: nameFromPath(path), Kind: "configuration file"}
	var doc struct {
		Hosts []string `json:"hosts"`
		TLS   bool     `json:"tls"`
	}
	if err := json.Unmarshal(data, &doc); err == nil {
		for _, h := range doc.Hosts {
			if i := strings.LastIndexByte(h, ':'); i >= 0 {
				if p, err := strconv.Atoi(h[i+1:]); err == nil && p > 0 && p <= 65535 {
					r.Ports = append(r.Ports, p)
					if p == 2376 || p == 2375 {
						// An exposed daemon socket is a production control-plane
						// surface whether or not TLS terminates it.
						r.HTTPS = r.HTTPS || doc.TLS
					}
				}
			}
		}
	}
	return []docResult{r}
}

// apacheVHostBlock is one parsed <VirtualHost> section.
type apacheVHostBlock struct {
	name  string
	ports []int
	https bool
}

// parseApacheVHosts extracts the virtual host sections of an Apache fragment
// along with each block's ServerName, ports and whether TLS is enabled.
func parseApacheVHosts(data []byte) []apacheVHostBlock {
	var (
		out []apacheVHostBlock
		cur *apacheVHostBlock
	)
	for _, raw := range strings.Split(string(data), "\n") {
		line := stripComment(raw)
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "<virtualhost") {
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &apacheVHostBlock{}
			// <VirtualHost *:443> — the port is the tiering signal.
			if i := strings.LastIndexByte(lower, ':'); i >= 0 {
				rest := lower[i+1:]
				if j := strings.IndexAny(rest, " >"); j >= 0 {
					rest = rest[:j]
				}
				if p, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil {
					cur.ports = append(cur.ports, p)
					if p == 443 {
						cur.https = true
					}
				}
			}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(lower, "</virtualhost") {
			out = append(out, *cur)
			cur = nil
			continue
		}
		switch {
		case strings.HasPrefix(lower, "servername"):
			if f := strings.Fields(trimmed); len(f) >= 2 {
				cur.name = f[1]
			}
		case strings.HasPrefix(lower, "serveralias") && cur.name == "":
			if f := strings.Fields(trimmed); len(f) >= 2 {
				cur.name = f[1]
			}
		case strings.HasPrefix(lower, "sslengine") && strings.Contains(lower, "on"):
			cur.https = true
		case strings.HasPrefix(lower, "listen"):
			if f := strings.Fields(trimmed); len(f) >= 2 {
				if p := parseListenPort(f[1]); p != 0 {
					cur.ports = append(cur.ports, p)
					if p == 443 {
						cur.https = true
					}
				}
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}
