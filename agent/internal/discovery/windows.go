package discovery

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// windowsProbers returns the discovery probe set for a Windows host.
//
// Like its Linux counterpart it is catalog-driven: IIS, SQL Server, RabbitMQ,
// MSMQ, the HKLM\Software product table, the Service Control Manager key store,
// scheduled tasks and the OpenSSH daemon policy all come from catalog.yaml. The
// registry/SCM bodies live in winprobe_windows.go behind a build tag, so a Linux
// cross-compile of the agent still contains the catalog and simply finds nothing.
func windowsProbers() []Prober {
	return CatalogProbers(RuntimeWindows)
}

// defaultApplicationHostPath is IIS's central configuration file. It is
// variable-overridable so tests (and unusual deployments) can point the probe
// at a fixture.
var defaultApplicationHostPath = `C:\Windows\System32\inetsrv\config\applicationHost.config`

// iisConfigPath resolves the applicationHost.config the IIS parser should read.
func iisConfigPath() string {
	if v := strings.TrimSpace(os.Getenv("STATETRACK_IIS_CONFIG")); v != "" {
		return v
	}
	return defaultApplicationHostPath
}

// iisBinding is one IIS site binding.
type iisBinding struct {
	Protocol   string `xml:"protocol,attr"`
	BindingInf string `xml:"bindingInformation,attr"`
}

// iisSite is the parsed representation of one IIS site.
type iisSite struct {
	Name      string
	Bindings  []iisBinding
	PhysRoots []string
}

// parseIISSites walks the XML tree to find system.applicationHost/sites.
// Element ordering and namespace prefixes do not matter, and a malformed or
// unexpected file yields no sites rather than an error.
func parseIISSites(data []byte) []iisSite {
	dec := xml.NewDecoder(strings.NewReader(string(stripBOM(data))))
	var (
		sites     []iisSite
		cur       *iisSite
		depthSite int
		stack     []string
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if strings.EqualFold(t.Name.Local, "site") && parentIsSites(stack) {
				s := iisSite{Name: attr(t, "name")}
				sites = append(sites, s)
				cur = &sites[len(sites)-1]
				depthSite = len(stack)
			}
			if cur != nil {
				switch {
				case strings.EqualFold(t.Name.Local, "binding"):
					*cur = appendBinding(*cur, iisBinding{
						Protocol:   attr(t, "protocol"),
						BindingInf: attr(t, "bindingInformation"),
					})
				case strings.EqualFold(t.Name.Local, "virtualDirectory"):
					if p := attr(t, "physicalPath"); p != "" {
						cur.PhysRoots = append(cur.PhysRoots, p)
					}
				}
			}
		case xml.EndElement:
			if cur != nil && len(stack) == depthSite && strings.EqualFold(t.Name.Local, "site") {
				cur = nil
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return sites
}

func appendBinding(s iisSite, b iisBinding) iisSite {
	s.Bindings = append(s.Bindings, b)
	return s
}

func parentIsSites(stack []string) bool {
	if len(stack) < 2 {
		return false
	}
	return strings.EqualFold(stack[len(stack)-2], "sites")
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if strings.EqualFold(a.Name.Local, name) {
			return a.Value
		}
	}
	return ""
}

func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// ports extracts the TCP ports this site binds.
func (s iisSite) ports() []int {
	var out []int
	for _, b := range s.Bindings {
		if b.Protocol != "" && !strings.EqualFold(b.Protocol, "http") && !strings.EqualFold(b.Protocol, "https") {
			continue
		}
		// bindingInformation is "IP:port:hostHeader".
		parts := strings.Split(b.BindingInf, ":")
		if len(parts) < 2 {
			continue
		}
		if p, err := strconv.Atoi(parts[1]); err == nil && p != 0 {
			out = append(out, p)
		}
	}
	return out
}

// https reports whether the site has an HTTPS binding.
func (s iisSite) https() bool {
	for _, b := range s.Bindings {
		if strings.EqualFold(b.Protocol, "https") {
			return true
		}
	}
	return false
}

// primaryPath returns the site's physical root (preferring the shallowest
// mapping), falling back to a nested web.config when the root has one.
func (s iisSite) primaryPath(configPath string) string {
	roots := append([]string(nil), s.PhysRoots...)
	sort.Strings(roots)
	root := ""
	for _, r := range roots {
		if root == "" || len(r) < len(root) {
			root = r
		}
	}
	if root == "" {
		return configPath
	}
	root = expandEnv(root)
	if wc := filepath.Join(root, "web.config"); fileExists(wc) {
		return wc
	}
	return root
}

// expandEnv expands %WINDIR%-style variables; on non-Windows test hosts the
// lookup is a no-op for a literal path.
func expandEnv(p string) string {
	if !strings.Contains(p, "%") {
		return p
	}
	return os.ExpandEnv(strings.ReplaceAll(p, "%WINDIR%", os.Getenv("WINDIR")))
}
