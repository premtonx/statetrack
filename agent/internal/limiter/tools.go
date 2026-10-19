package limiter

import (
	"strings"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// Process is one entry of a process ancestry chain.
type Process struct {
	PID     uint32
	Name    string
	Cmdline string
}

// ToolKind distinguishes package managers from deployment/CM tools.
type ToolKind int

const (
	ToolPackageManager ToolKind = iota + 1
	ToolDeployment
)

// Tool is a package-management or deployment tool whose child mutations are
// grouped into one transaction.
type Tool struct {
	Name string
	Kind ToolKind
}

// Category is the event category used for the tool's parent event.
func (t Tool) Category() pb.Category {
	if t.Kind == ToolPackageManager {
		return pb.Category_CATEGORY_PACKAGE
	}
	return pb.Category_CATEGORY_CONFIG
}

// Keys are lower-cased process names (Linux comm is truncated to 15 chars).
var groupingTools = map[string]Tool{
	"apt":                  {"apt", ToolPackageManager},
	"apt-get":              {"apt", ToolPackageManager},
	"aptitude":             {"apt", ToolPackageManager},
	"unattended-upgr":      {"apt", ToolPackageManager},
	"unattended-upgrade":   {"apt", ToolPackageManager},
	"unattended-upgrades":  {"apt", ToolPackageManager},
	"dpkg":                 {"dpkg", ToolPackageManager},
	"yum":                  {"yum", ToolPackageManager},
	"dnf":                  {"dnf", ToolPackageManager},
	"dnf-automatic":        {"dnf", ToolPackageManager},
	"rpm":                  {"rpm", ToolPackageManager},
	"zypper":               {"zypper", ToolPackageManager},
	"apk":                  {"apk", ToolPackageManager},
	"snapd":                {"snap", ToolPackageManager},
	"msiexec":              {"msiexec", ToolPackageManager},
	"msiexec.exe":          {"msiexec", ToolPackageManager},
	"wusa.exe":             {"windows-update", ToolPackageManager},
	"tiworker.exe":         {"windows-update", ToolPackageManager},
	"trustedinstaller.exe": {"windows-update", ToolPackageManager},
	"ansible":              {"ansible", ToolDeployment},
	"ansible-playbook":     {"ansible", ToolDeployment},
	"ansible-pull":         {"ansible", ToolDeployment},
	"puppet":               {"puppet", ToolDeployment},
	"chef-client":          {"chef", ToolDeployment},
	"salt-minion":          {"salt", ToolDeployment},
	"salt-call":            {"salt", ToolDeployment},
	"runner.worker":        {"github-actions", ToolDeployment},
	"runner.worker.exe":    {"github-actions", ToolDeployment},
}

// GroupingTool reports whether p is a package-management or deployment tool.
// Interpreted tools (ansible-playbook run by python3) are recognised from
// the command line, as are Ansible's remote AnsiballZ modules.
func GroupingTool(p Process) (Tool, bool) {
	if t, ok := groupingTools[baseName(p.Name)]; ok {
		return t, true
	}
	args := strings.Fields(p.Cmdline)
	for i := 0; i < len(args) && i < 2; i++ {
		if t, ok := groupingTools[baseName(args[i])]; ok {
			return t, true
		}
	}
	if strings.Contains(p.Cmdline, "AnsiballZ_") {
		return groupingTools["ansible"], true
	}
	return Tool{}, false
}

// GroupingRoot returns the outermost grouping tool in ancestry, which is
// ordered from the acting process ([0]) up towards init. For
// apt -> dpkg -> postinst the root is apt.
func GroupingRoot(ancestry []Process) (Process, Tool, bool) {
	for i := len(ancestry) - 1; i >= 0; i-- {
		if t, ok := GroupingTool(ancestry[i]); ok {
			return ancestry[i], t, true
		}
	}
	return Process{}, Tool{}, false
}

func baseName(s string) string {
	s = strings.ToLower(s)
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return s
}
