package discovery

import (
	"strings"
	"unicode"
)

// linuxProbers returns the discovery probe set for a Linux host.
//
// It is derived entirely from the embedded catalog: every entry whose runtime is
// "linux" (web servers, databases, brokers, core system files) or "docker" (the
// container runtime, which is a Linux-host detection surface) registers one
// probe. Nothing about what to scan lives in this file, which is what lets a
// security team extend discovery by reviewing one YAML manifest rather than
// auditing Go code.
func linuxProbers() []Prober {
	return CatalogProbers(RuntimeLinux, RuntimeDocker)
}

// webServer is one parsed nginx server block.
type webServer struct {
	names []string
	ports []int
	https bool
}

// primaryName returns the first concrete server name, skipping nginx's
// wildcard catch-alls.
func (s webServer) primaryName() string {
	for _, n := range s.names {
		n = strings.TrimSpace(n)
		if n == "" || n == "_" || strings.HasPrefix(n, "~") {
			continue
		}
		return n
	}
	if len(s.names) > 0 {
		return strings.TrimSpace(s.names[0])
	}
	return ""
}

// nginxTokens splits an nginx config into lower-cased tokens, treating '{',
// '}' and ';' as standalone tokens and dropping '#' comments.
func nginxTokens(data []byte) []string {
	var toks []string
	var b strings.Builder
	inComment := false
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, strings.ToLower(b.String()))
			b.Reset()
		}
	}
	for _, r := range string(data) {
		if r == '\n' {
			inComment = false
			flush()
			continue
		}
		if inComment {
			continue
		}
		switch r {
		case '#':
			flush()
			inComment = true
		case '{', '}', ';':
			flush()
			toks = append(toks, string(r))
		default:
			if unicode.IsSpace(r) {
				flush()
			} else {
				b.WriteRune(r)
			}
		}
	}
	flush()
	return toks
}

// readUntil collects tokens until the terminator (exclusive).
func readUntil(toks []string, start int, term string) []string {
	var out []string
	for i := start; i < len(toks); i++ {
		if toks[i] == term {
			break
		}
		if toks[i] == "{" || toks[i] == "}" {
			break
		}
		out = append(out, toks[i])
	}
	return out
}

// parseNginxServers extracts the server blocks from an nginx config, including
// the ports each binds and whether it terminates TLS. Both are inputs to the
// risk tiering heuristics in the catalog's web_server profile.
func parseNginxServers(data []byte) []webServer {
	toks := nginxTokens(data)
	var out []webServer
	for i := 0; i < len(toks); i++ {
		if toks[i] != "server" || i+1 >= len(toks) || toks[i+1] != "{" {
			continue
		}
		var srv webServer
		depth := 0
		j := i + 1
		for ; j < len(toks); j++ {
			t := toks[j]
			switch t {
			case "{":
				depth++
			case "}":
				depth--
			}
			if depth == 0 {
				break
			}
			switch t {
			case "listen":
				args := readUntil(toks, j+1, ";")
				if len(args) > 0 {
					if p := parseListenPort(args[0]); p != 0 {
						srv.ports = append(srv.ports, p)
					}
					if hasAny(args, "ssl", "http2") {
						srv.https = true
					}
				}
			case "server_name":
				srv.names = append(srv.names, readUntil(toks, j+1, ";")...)
			}
		}
		out = append(out, srv)
		i = j
	}
	return out
}

func hasAny(args []string, want ...string) bool {
	for _, a := range args {
		for _, w := range want {
			if a == w {
				return true
			}
		}
	}
	return false
}

// stripComment removes a '#' comment from a config line.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	return line
}
