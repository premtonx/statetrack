//go:build windows

package discovery

import (
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// windowsRegistryTargets enumerates the concrete documents a registry/service
// catalog target names.
//
// The registry renders a key as a text document — "HKLM\...\Value" = data, one
// line per value — which is exactly the shape the Windows registry collector
// already diffs. Reusing that convention here means a discovered registry key
// becomes a policy rule whose diffs look identical to an operator-collected
// one, rather than a second, subtly different rendering.
//
// Every failure is silent: a key the agent cannot open (permissions, a
// 32/64-bit view mismatch, a product that is simply not installed) is reported
// as "not discovered", never as a scan error.
func windowsRegistryTargets(t Target) []scanDoc {
	var out []scanDoc
	for _, raw := range expandPatterns(t.Patterns) {
		if strings.HasPrefix(strings.ToLower(raw), "hklm") {
			out = append(out, enumerateRegistryKey(raw, t.maxFiles())...)
			continue
		}
		// A SCM service name (MSSQLSERVER, MSSQL$PROD, …).
		out = append(out, enumerateServices(raw, t.maxFiles())...)
	}
	return out
}

// enumerateRegistryKey renders each requested registry key plus its immediate
// subkeys, bounded. Subkeys matter because the production signal for an
// installed product lives one level down: SQL Server registers one subkey per
// instance under ...\Microsoft SQL Server.
func enumerateRegistryKey(hivePath string, max int) []scanDoc {
	root, sub, ok := openRegistryPath(hivePath)
	if !ok {
		return nil
	}
	defer root.Close()

	// The key itself, if it holds values worth tracking.
	if len(sub) > 0 {
		if k, err := registry.OpenKey(root, sub, registry.READ); err == nil {
			if doc, ok := renderRegistryKey(root, k, hivePath); ok {
				k.Close()
				return []scanDoc{doc}
			}
			k.Close()
		}
	}
	// Otherwise: the key's own values plus one level of subkeys. For
	// HKLM\Software that is the whole product table; for
	// ...\Microsoft SQL Server it is the per-instance registrations.
	return enumerateRegistrySubkeys(root, sub, hivePath, max)
}

// enumerateRegistrySubkeys renders a key and each of its immediate subkeys,
// skipping the uninteresting leaves (an empty key with no values is not a
// configuration surface worth recommending).
func enumerateRegistrySubkeys(root registry.Key, sub, display string, max int) []scanDoc {
	if max <= 0 {
		max = defaultWalkFiles
	}
	var out []scanDoc
	if len(sub) > 0 {
		if k, err := registry.OpenKey(root, sub, registry.READ); err == nil {
			if doc, ok := renderRegistryKey(root, k, display); ok {
				out = append(out, doc)
			}
			k.Close()
		}
	}
	k, err := registry.OpenKey(root, sub, registry.READ)
	if err != nil {
		return out
	}
	names, _ := k.ReadSubKeyNames(-1)
	k.Close()
	sort.Strings(names)
	for _, name := range names {
		if len(out) >= max {
			break
		}
		child := joinRegistry(sub, name)
		ck, err := registry.OpenKey(root, child, registry.READ)
		if err != nil {
			continue
		}
		// Reject values that are only name/value pairs the classifier
		// blacklists anyway? No: keep them, but require the subkey to carry at
		// least one value, so a bare organisational folder is not a finding.
		if doc, ok := renderRegistryKey(root, ck, joinRegistry(display, name)); ok {
			out = append(out, doc)
		}
		ck.Close()
	}
	return out
}

// openRegistryPath splits "HKLM\Software\..." into a hive handle and the
// remainder of the path.
func openRegistryPath(hivePath string) (registry.Key, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(hivePath), `\`, 2)
	if len(parts) == 0 {
		return 0, "", false
	}
	var hive registry.Key
	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		hive = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		hive = registry.USERS
	case "HKCC", "HKEY_CURRENT_CONFIG":
		hive = registry.CURRENT_CONFIG
	default:
		return 0, "", false
	}
	if len(parts) == 1 {
		return hive, "", true
	}
	return hive, parts[1], true
}

// renderRegistryKey renders a key's values as the text document the registry
// collector produces, so a discovered key and a collected key are byte-identical
// for the same state.
func renderRegistryKey(root registry.Key, k registry.Key, display string) (scanDoc, bool) {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return scanDoc{}, false
	}
	sort.Strings(names)
	if len(names) == 0 {
		return scanDoc{}, false
	}
	var b strings.Builder
	b.WriteString("Windows Registry Editor Version 5.00\n\n")
	b.WriteString("[" + display + "]\n")
	for _, n := range names {
		b.WriteString(renderRegistryValue(k, n))
	}
	_ = root
	return scanDoc{Path: display, Data: []byte(b.String())}, true
}

// renderRegistryValue renders one value in .reg syntax, falling back to a type
// note for shapes that have no .reg literal so a value's existence is never
// silently dropped from the document.
//
// Every registry read is typed (String / Strings / Integer / Binary) rather
// than a raw REG_ANY: x/sys does not expose a variant type, and the typed
// accessors are what let the rendering pick the right .reg literal.
func renderRegistryValue(k registry.Key, name string) string {
	var b strings.Builder
	b.WriteString(quoteRegistryName(name))
	b.WriteString("=")

	// A string value (REG_SZ / REG_EXPAND_SZ) is the common case.
	if s, kind, err := k.GetStringValue(name); err == nil {
		b.WriteString(regQuote(s))
		if kind == registry.EXPAND_SZ {
			// REG_EXPAND_SZ and REG_SZ hash identically in most tooling, so
			// record the type explicitly rather than losing it.
			b.WriteString("  ; type=expand_sz")
		}
		b.WriteString("\n")
		return b.String()
	}
	if strs, kind, err := k.GetStringsValue(name); err == nil && (kind == registry.MULTI_SZ || len(strs) > 0) {
		b.WriteString("hex(7):" + multiSZHex(strings.Join(strs, "\x00")))
		b.WriteString("\n")
		return b.String()
	}
	if n, kind, err := k.GetIntegerValue(name); err == nil {
		if kind == registry.QWORD {
			b.WriteString("hex(b):" + qwordHex(n))
		} else {
			b.WriteString("dword:" + uintHex(uint32(n)))
		}
		b.WriteString("\n")
		return b.String()
	}
	if raw, _, err := k.GetBinaryValue(name); err == nil {
		b.WriteString("hex:" + byteHex(raw))
		b.WriteString("\n")
		return b.String()
	}
	// A value that exists but could not be read in any known shape: record
	// that it is present so a deletion or addition still shows up in a diff.
	b.WriteString(`"<unreadable>"` + "\n")
	return b.String()
}

// regQuote renders a string as a .reg literal.
func regQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(s) + `"`
}

func quoteRegistryName(name string) string {
	if name == "" {
		return "@"
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(name) + `"`
}

// qwordHex renders a little-endian REG_QWORD as the .reg hex(b) literal.
func qwordHex(v uint64) string {
	raw := make([]byte, 8)
	for i := 0; i < 8; i++ {
		raw[i] = byte(v >> (8 * i))
	}
	return byteHex(raw)
}

func uintHex(v uint32) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = hexDigits[v&0xf]
		v >>= 4
	}
	return string(b)
}

func byteHex(raw []byte) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, 0, len(raw)*2)
	for _, c := range raw {
		b = append(b, hexDigits[c>>4], hexDigits[c&0xf])
	}
	return string(b)
}

func multiSZHex(s string) string {
	return byteHex([]byte(s))
}

// enumerateServices lists SCM services whose name matches the pattern
// (MSSQLSERVER, MSSQL$PROD, or the MSSQL$* glob). Each service is rendered as a
// small document of its image path and start type so the tiering heuristics and
// the diff both have something real to work with.
func enumerateServices(pattern string, max int) []scanDoc {
	if max <= 0 {
		max = defaultWalkFiles
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil
	}
	sort.Strings(names)
	var out []scanDoc
	for _, name := range names {
		if len(out) >= max {
			break
		}
		if !serviceNameMatches(pattern, name) {
			continue
		}
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		cfg, cfgErr := s.Config()
		status, statusErr := s.Query()
		s.Close()
		if cfgErr != nil && statusErr != nil {
			continue
		}
		var b strings.Builder
		b.WriteString("service: " + name + "\n")
		if cfgErr == nil {
			b.WriteString("display_name: " + cfg.DisplayName + "\n")
			b.WriteString("binary_path: " + cfg.BinaryPathName + "\n")
			b.WriteString("start_type: " + serviceStartType(cfg.StartType) + "\n")
		}
		if statusErr == nil {
			b.WriteString("state: " + serviceState(status.State) + "\n")
		}
		out = append(out, scanDoc{Path: "service:" + name, Data: []byte(b.String())})
	}
	return out
}

// serviceNameMatches implements the catalog's exact-or-glob service match.
func serviceNameMatches(pattern, name string) bool {
	p := strings.ToUpper(strings.TrimSpace(pattern))
	n := strings.ToUpper(name)
	if p == n {
		return true
	}
	if !strings.ContainsAny(p, "*?") {
		return false
	}
	// A simple glob is enough for the catalog's shapes (MSSQL$*, SQLAgent$*).
	parts := strings.Split(p, "*")
	if len(parts) == 2 {
		return strings.HasPrefix(n, parts[0]) && strings.HasSuffix(n, parts[1])
	}
	return strings.HasPrefix(n, parts[0])
}

func serviceStartType(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "auto"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	default:
		return "other"
	}
}

func serviceState(s svc.State) string {
	switch s {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start_pending"
	case svc.StopPending:
		return "stop_pending"
	default:
		return "other"
	}
}

// scheduledTaskTargets enumerates Windows Scheduled Task definitions. Each task
// is an XML document under the task store, which is how the Task Scheduler
// itself serialises it — so a diff of a discovered task and a diff of a
// collected one are the same artefact.
func scheduledTaskTargets(t Target) []scanDoc {
	max := t.maxFiles()
	var out []scanDoc
	for _, root := range expandPatterns(t.Patterns) {
		for _, f := range walkConfigFiles(root, 2, nil, max) {
			data, ok := readFileLimited(f)
			if !ok {
				continue
			}
			// The task store holds extension-less XML files, which is why the
			// walk is unfiltered by extension.
			name := taskNameFromPath(root, f)
			out = append(out, scanDoc{Path: filepath.ToSlash(f), Data: renderTaskDoc(name, f, data)})
			if len(out) >= max {
				return out
			}
		}
	}
	return out
}

// taskNameFromPath renders the scheduler's own path form:
// C:\Windows\System32\Tasks\Company\Deploy -> \Company\Deploy.
func taskNameFromPath(root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return filepath.Base(file)
	}
	return `\` + strings.ReplaceAll(filepath.ToSlash(rel), "/", `\`)
}

// renderTaskDoc prepends a one-line header to the task XML so the document
// carries the task's scheduler name alongside the definition it contains.
func renderTaskDoc(name, path string, data []byte) []byte {
	var b strings.Builder
	b.WriteString("task: " + name + "\n")
	b.WriteString("store_path: " + filepath.ToSlash(path) + "\n\n")
	b.Write(data)
	return []byte(b.String())
}

// joinRegistry appends a subkey to a registry path.
func joinRegistry(base, name string) string {
	base = strings.TrimRight(base, `\`)
	if base == "" {
		return name
	}
	return base + `\` + name
}
