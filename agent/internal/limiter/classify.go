package limiter

import (
	"fmt"
	"sync/atomic"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// MaxForensicWindow caps how long Level 4 collection stays enabled after a
// remote toggle.
const MaxForensicWindow = 15 * time.Minute

// DefaultBlacklist is the Level 0 hard blacklist: never hashed, diffed or
// logged. Editor/tool temp files are included so atomic-save sequences
// (vim, sed -i, emacs) only surface the real target file.
var DefaultBlacklist = []string{
	"/proc/**", "/sys/**", "/dev/**", "/run/**", "/tmp/**", "/var/tmp/**",
	"/var/log/**", "/var/cache/**",
	"/var/spool/postfix/**", "/var/spool/mail/**", "/var/spool/exim4/**", "/var/spool/cups/**", "/var/spool/rsyslog/**",
	"/var/lib/docker/overlay2/**", "/var/lib/containerd/**",
	"/var/lib/postgresql/**/data/**", "/var/lib/postgresql/data/**", "/var/lib/pgsql/**/data/**",
	"/var/lib/mysql/**", "/var/lib/mongodb/**", "/var/lib/redis/**", "/var/lib/elasticsearch/**",
	"/var/lib/statetrack/**",
	`C:\Windows\Temp\**`, `C:\Windows\Logs\**`, `C:\Windows\SoftwareDistribution\**`, `C:\Windows\Prefetch\**`,
	`C:\$Recycle.Bin\**`, `C:\System Volume Information\**`,
	`C:\ProgramData\StateTrack\**`, `C:\Program Files\Microsoft SQL Server\**\DATA\**`,
	// C:\ProgramData churn: telemetry, caches, Defender, VM images, MSI payload caches.
	`C:\ProgramData\Microsoft\Windows Defender\**`, `C:\ProgramData\Microsoft\Windows Security Health\**`,
	`C:\ProgramData\Microsoft\Windows\WER\**`, `C:\ProgramData\Microsoft\Diagnosis\**`,
	`C:\ProgramData\Microsoft\Search\**`, `C:\ProgramData\Microsoft\Windows\Caches\**`,
	`C:\ProgramData\Microsoft\Network\Downloader\**`, `C:\ProgramData\Microsoft\Windows\AppRepository\**`,
	`C:\ProgramData\Microsoft\Windows\wfp\**`, `C:\ProgramData\Microsoft\Windows\Hyper-V\**`,
	`C:\ProgramData\Microsoft\Windows\SystemData\**`, `C:\ProgramData\Microsoft\Windows\DeviceMetadataCache\**`,
	`C:\ProgramData\Microsoft\Windows\Containers\**`, `C:\ProgramData\Microsoft\Windows\Power Efficiency Diagnostics\**`,
	`C:\ProgramData\Package Cache\**`, `C:\ProgramData\USOShared\**`, `C:\ProgramData\USOPrivate\**`,
	// Registry churn: COM/WinRT registrations, servicing and MSI internals,
	// app model state, counters, and per-launch activity tracking.
	`HKLM\SOFTWARE\Classes\**`, `HKLM\SOFTWARE\WOW6432Node\Classes\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\**`,
	`HKLM\SOFTWARE\Microsoft\Windows Defender\**`, `HKLM\SOFTWARE\Microsoft\Windows Search\**`,
	`HKLM\SOFTWARE\Microsoft\Tracing\**`, `HKLM\SOFTWARE\Microsoft\SQMClient\**`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\**`,
	`HKLM\SYSTEM\CurrentControlSet\Services\bam\State\**`,
	"*.log", "*.etl", "*.evtx", "*.swp", "*.swo", "*.swx", "*~", ".#*", "4913", "sed??????",
	"*.dpkg-tmp", "*.dpkg-new", "*.rpmnew.tmp", "*.tmp",
	"*.db-wal", "*.db-shm", "*.db-journal", "*.sqlite-wal", "*.sqlite-shm",
	// shadow-utils/sudo lock files, staging copies and backups.
	"/etc/*+", "/etc/*.lock", "/etc/.pwd.lock", "/etc/passwd-", "/etc/shadow-", "/etc/group-", "/etc/gshadow-",
	"/etc/subuid-", "/etc/subgid-",
}

// DefaultCritical lists Level 1 paths: core configuration, identity and
// service definitions.
var DefaultCritical = []string{
	// Virtual configuration documents rendered by the surgical watchers. Their
	// document paths are not files, so a path-based heuristic would classify
	// them as drift; a pool stopping or a production config table changing is
	// exactly the Level 1 signal those watchers exist to raise. An operator rule
	// still overrides this (a non-production pool can be demoted to L3).
	"iis://**", "db://**",
	"/etc/**", "/usr/local/etc/**", "/var/spool/cron/**",
	"/usr/lib/systemd/system/**", "/lib/systemd/system/**",
	"/root/.ssh/**", "**/.ssh/authorized_keys", "**/.ssh/authorized_keys2",
	`C:\Windows\System32\inetsrv\config\**`, `C:\Windows\System32\drivers\etc\**`,
	`C:\Windows\System32\Tasks\**`, `C:\ProgramData\ssh\**`,
	`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\**`,
	"**/web.config", "**/applicationHost.config",
	`HKLM\SYSTEM\CurrentControlSet\Services\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\**`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\**`,
	`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\**`,
	`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\**`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\**`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\**`,
	`HKLM\SOFTWARE\Policies\**`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\**`,
	`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\**`,
}

// DefaultSelf lists the agent's own configuration and binaries; changes here
// are reported as self-tamper events.
var DefaultSelf = []string{
	"/etc/statetrack/**", "/usr/bin/statetrack-agent", "/usr/local/bin/statetrack-agent",
	"/etc/systemd/system/statetrack-agent.service", "/lib/systemd/system/statetrack-agent.service",
	`C:\Program Files\StateTrack\**`,
}

var identityPaths = MustMatcher(
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/**",
	"/root/.ssh/**", "**/.ssh/authorized_keys", "**/.ssh/authorized_keys2",
	`C:\ProgramData\ssh\administrators_authorized_keys`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\**`,
)

var servicePaths = MustMatcher(
	"/etc/systemd/**", "/usr/lib/systemd/system/**", "/lib/systemd/system/**", "/etc/init.d/**",
	`HKLM\SYSTEM\CurrentControlSet\Services\**`,
)

// ClassifierConfig holds the pattern lists; nil fields use the defaults.
// The Extra* lists are appended to the (default or explicit) lists.
type ClassifierConfig struct {
	Blacklist []string
	Critical  []string
	Self      []string

	ExtraBlacklist []string
	ExtraCritical  []string
	ExtraSelf      []string

	// Rules are the granular per-target policy overrides (see rules.go).
	// They take precedence over the built-in critical-path and category
	// heuristics, but never over the Level 0 blacklist.
	Rules []PolicyRule
}

// Classifier assigns impact levels (spec section 3) to candidate events.
// It is safe for concurrent use, including Reconfigure.
type Classifier struct {
	rules         atomic.Pointer[classifierRules]
	forensicUntil atomic.Int64 // unix nanoseconds
}

type classifierRules struct {
	blacklist, critical, self *Matcher
	policy                    *policyRules
}

// NewClassifier compiles cfg.
func NewClassifier(cfg ClassifierConfig) (*Classifier, error) {
	c := &Classifier{}
	if err := c.Reconfigure(cfg); err != nil {
		return nil, err
	}
	return c, nil
}

// Reconfigure atomically replaces the pattern lists. The forensic window is
// kept. On error the previous rules stay in effect.
func (c *Classifier) Reconfigure(cfg ClassifierConfig) error {
	pick := func(v, def, extra []string) []string {
		if v == nil {
			v = def
		}
		return append(append([]string{}, v...), extra...)
	}
	r := &classifierRules{}
	var err error
	if r.blacklist, err = NewMatcher(pick(cfg.Blacklist, DefaultBlacklist, cfg.ExtraBlacklist)...); err != nil {
		return fmt.Errorf("blacklist: %w", err)
	}
	if r.critical, err = NewMatcher(pick(cfg.Critical, DefaultCritical, cfg.ExtraCritical)...); err != nil {
		return fmt.Errorf("critical: %w", err)
	}
	if r.self, err = NewMatcher(pick(cfg.Self, DefaultSelf, cfg.ExtraSelf)...); err != nil {
		return fmt.Errorf("self: %w", err)
	}
	if r.policy, err = compileRules(cfg.Rules); err != nil {
		return fmt.Errorf("policy rules: %w", err)
	}
	c.rules.Store(r)
	return nil
}

// Candidate describes an observed mutation before it is hashed or diffed.
type Candidate struct {
	// Path is the file path or registry key; empty for non-path events.
	Path string
	// Category is set by collectors of non-file events (service, process,
	// network, user, registry). Leave unspecified for files.
	Category pb.Category
	// TargetType names the concrete target kind ("file", "registry",
	// "iis_apppool", "database_table", ...) when the collector knows it. A
	// granular rule is matched against this value, so a rule authored for an IIS
	// app pool is not accidentally applied to a file that happens to share its
	// path shape. When empty the type is derived from the category.
	TargetType string
	// Tool is the grouping root tool from the actor's ancestry, if any.
	Tool *Tool
	Now  time.Time
}

// Decision is the classifier verdict.
type Decision struct {
	Level    pb.ImpactLevel
	Category pb.Category
	// Drop is true for Level 0 events and Level 4 events outside forensic mode.
	Drop bool
	// Diff is true when a text diff should be computed (otherwise hashes and
	// sizes only).
	Diff   bool
	Reason string
	// RuleName is set when a granular policy rule decided the verdict; the
	// engine reports it as metadata["rule_name"].
	RuleName string
	// RuleTags is the matched rule's comma-joined tag list; the engine
	// reports it as metadata["rule_tags"].
	RuleTags string
}

// Blacklisted reports whether p is in the Level 0 blacklist. Collectors
// should call this before doing any work, including on directories while
// walking. The agent's own files are never blacklisted, even inside the
// state directory (C:\ProgramData\StateTrack\agent.yaml).
func (c *Classifier) Blacklisted(p string) bool {
	r := c.rules.Load()
	return r.blacklist.Match(p) && !r.self.Match(p)
}

// SelfPath reports whether p is one of the agent's own files.
func (c *Classifier) SelfPath(p string) bool { return c.rules.Load().self.Match(p) }

// SetForensicUntil enables Level 4 collection until t, capped at
// MaxForensicWindow from now. A zero or past t disables it.
func (c *Classifier) SetForensicUntil(now, t time.Time) {
	if limit := now.Add(MaxForensicWindow); t.After(limit) {
		t = limit
	}
	c.forensicUntil.Store(t.UnixNano())
}

// ForensicActive reports whether Level 4 collection is enabled at now.
func (c *Classifier) ForensicActive(now time.Time) bool {
	return now.UnixNano() < c.forensicUntil.Load()
}

// Classify applies the impact level rules.
func (c *Classifier) Classify(cand Candidate) Decision {
	r := c.rules.Load()
	if cand.Path != "" && r.blacklist.Match(cand.Path) && !r.self.Match(cand.Path) {
		return Decision{Drop: true, Reason: "blacklisted"}
	}

	switch cand.Category {
	case pb.Category_CATEGORY_PROCESS, pb.Category_CATEGORY_NETWORK:
		d := Decision{Level: pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC, Category: cand.Category, Reason: "forensic"}
		if !c.ForensicActive(cand.Now) {
			d.Drop, d.Reason = true, "forensic_disabled"
		}
		return d
	}

	if cand.Path != "" && r.self.Match(cand.Path) {
		return Decision{Level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, Category: pb.Category_CATEGORY_AGENT_HEALTH,
			Diff: true, Reason: "agent_self_tamper"}
	}

	category := cand.Category
	if category == pb.Category_CATEGORY_UNSPECIFIED {
		category = pathCategory(cand.Path)
	}

	// Granular policy rules (exact match, then glob) override the built-in
	// heuristics. Level 0 is a hard drop; levels 1–4 set the outcome and the
	// rule's diff flag fully replaces the heuristic's.
	if cand.Path != "" {
		if rule, ok := r.policy.match(cand.Path, candidateTargetType(cand, category)); ok {
			if rule.Level <= 0 {
				return Decision{Drop: true, Reason: "rule_drop:" + rule.Name, RuleName: rule.Name,
					RuleTags: rule.normalizedTags()}
			}
			return Decision{
				Level:    clampLevel(rule.Level),
				Category: category,
				Diff:     rule.Diff,
				Reason:   "rule:" + rule.Name,
				RuleName: rule.Name,
				RuleTags: rule.normalizedTags(),
			}
		}
	}

	critical := cand.Path != "" && r.critical.Match(cand.Path)

	if cand.Tool != nil {
		// Grouped under the tool's transaction; only configuration files
		// get text diffs, other package payload is hash-only.
		return Decision{Level: pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED, Category: category,
			Diff: critical, Reason: "grouped:" + cand.Tool.Name}
	}

	switch {
	case cand.Category == pb.Category_CATEGORY_SERVICE || cand.Category == pb.Category_CATEGORY_USER:
		return Decision{Level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, Category: category, Diff: cand.Path != "", Reason: "critical_category"}
	case critical:
		return Decision{Level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, Category: category, Diff: true, Reason: "critical_path"}
	}
	return Decision{Level: pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, Category: category, Reason: "drift"}
}

func pathCategory(p string) pb.Category {
	switch {
	case p == "":
		return pb.Category_CATEGORY_UNSPECIFIED
	case identityPaths.Match(p):
		return pb.Category_CATEGORY_USER
	case servicePaths.Match(p):
		return pb.Category_CATEGORY_SERVICE
	case isWindowsStyle(p) && len(p) > 2 && (p[0] == 'H' || p[0] == 'h') && (p[1] == 'K' || p[1] == 'k'):
		return pb.Category_CATEGORY_REGISTRY
	}
	return pb.Category_CATEGORY_CONFIG
}

// targetTypeName maps an event category to the TargetResource.target_type
// string a policy rule matches against ("file", "registry", "service", ...).
func targetTypeName(category pb.Category) string {
	switch category {
	case pb.Category_CATEGORY_REGISTRY:
		return "registry"
	case pb.Category_CATEGORY_SERVICE:
		return "service"
	case pb.Category_CATEGORY_PACKAGE:
		return "package"
	case pb.Category_CATEGORY_PROCESS:
		return "process"
	case pb.Category_CATEGORY_NETWORK:
		return "network"
	case pb.Category_CATEGORY_USER:
		return "user"
	case pb.Category_CATEGORY_AGENT_HEALTH:
		return "agent_health"
	}
	return "file"
}

// candidateTargetType resolves the type a policy rule is matched against.
//
// An explicit type from the collector always wins. That is what lets the
// surgical watchers share one classifier: a rule authored for
// target_type=iis_apppool must not match an ordinary file whose path happens to
// look like an app-pool URI, and a rule authored for a database table must not
// apply to a Windows registry key.
func candidateTargetType(cand Candidate, category pb.Category) string {
	if cand.TargetType != "" {
		return cand.TargetType
	}
	return targetTypeName(category)
}

// clampLevel bounds a rule's level to the valid impact range 1–4.
func clampLevel(level int) pb.ImpactLevel {
	if level < 1 {
		level = 1
	}
	if level > 4 {
		level = 4
	}
	return pb.ImpactLevel(level)
}
