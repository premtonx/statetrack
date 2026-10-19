package limiter

import (
	"testing"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

const (
	l1 = pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL
	l2 = pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED
	l3 = pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT
	l4 = pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC
)

func TestPolicyRuleExactMatch(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "checkout-app", TargetType: "file", Pattern: `C:\inetpub\wwwroot\checkout\web.config`, Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := c.Classify(Candidate{Path: `C:\inetpub\wwwroot\checkout\web.config`})
	if d.Drop || d.Level != l1 || !d.Diff {
		t.Fatalf("exact rule not applied: %+v", d)
	}
	if d.RuleName != "checkout-app" || d.Reason != "rule:checkout-app" {
		t.Fatalf("rule attribution wrong: %+v", d)
	}
}

func TestPolicyRuleWindowsPathIsCaseInsensitive(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "iis", Pattern: `C:\inetpub\wwwroot\checkout\web.config`, Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: `c:\INETPUB\WWWROOT\Checkout\Web.Config`}); d.RuleName != "iis" {
		t.Fatalf("windows exact rule should be case-insensitive: %+v", d)
	}
}

func TestPolicyRuleUnixPathIsCaseSensitive(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "nginx", Pattern: "/etc/nginx/nginx.conf", Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/etc/NGINX/nginx.conf"}); d.RuleName == "nginx" {
		t.Fatalf("unix exact rule must stay case-sensitive: %+v", d)
	}
}

func TestPolicyRuleGlobMatch(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "staging-drift", Pattern: "/srv/staging/**", Level: 3, Diff: false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := c.Classify(Candidate{Path: "/srv/staging/app/config.yml"})
	if d.Drop || d.Level != l3 || d.Diff || d.RuleName != "staging-drift" {
		t.Fatalf("glob rule not applied: %+v", d)
	}
}

func TestPolicyRuleExactBeatsGlob(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		// Declared first, but only a glob: the exact rule must win.
		{Name: "glob", Pattern: "/etc/nginx/**", Level: 3, Diff: false},
		{Name: "exact", Pattern: "/etc/nginx/nginx.conf", Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := c.Classify(Candidate{Path: "/etc/nginx/nginx.conf"})
	if d.RuleName != "exact" || d.Level != l1 || !d.Diff {
		t.Fatalf("exact rule should take precedence over glob: %+v", d)
	}
	// A path that only the glob matches still uses the glob rule.
	if d := c.Classify(Candidate{Path: "/etc/nginx/conf.d/site.conf"}); d.RuleName != "glob" || d.Level != l3 {
		t.Fatalf("glob rule not applied for non-exact path: %+v", d)
	}
}

func TestPolicyRuleFirstMatchingGlobWins(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "first", Pattern: "/srv/**", Level: 2, Diff: false},
		{Name: "second", Pattern: "/srv/**/web.config", Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/srv/app/web.config"}); d.RuleName != "first" {
		t.Fatalf("first declared glob should win: %+v", d)
	}
}

func TestPolicyRuleLevelZeroDrops(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "noise", Pattern: "/srv/app/cache/**", Level: 0},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := c.Classify(Candidate{Path: "/srv/app/cache/state.json"})
	if !d.Drop || d.RuleName != "noise" || d.Reason != "rule_drop:noise" {
		t.Fatalf("level 0 rule must hard-drop: %+v", d)
	}
	// The built-in blacklist still drops silently ahead of any rule.
	if d := c.Classify(Candidate{Path: "/proc/1/status"}); !d.Drop || d.RuleName != "" {
		t.Fatalf("blacklist must beat policy rules: %+v", d)
	}
}

func TestPolicyRuleCannotResurrectBlacklist(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "resurrect", Pattern: "/tmp/**", Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/tmp/build/out.bin"}); !d.Drop {
		t.Fatalf("policy rule must not resurrect a blacklisted path: %+v", d)
	}
}

func TestPolicyRuleCannotOverrideSelfTamper(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "quiet", Pattern: "/etc/statetrack/**", Level: 3, Diff: false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := c.Classify(Candidate{Path: "/etc/statetrack/agent.yaml"})
	if d.Level != l1 || !d.Diff || d.Reason != "agent_self_tamper" {
		t.Fatalf("agent self-tamper must precede policy rules: %+v", d)
	}
}

func TestPolicyRuleTargetTypeFilter(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "reg-only", TargetType: "registry", Pattern: `HKLM\SOFTWARE\Vendor\**`, Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{
		Path:     `HKLM\SOFTWARE\Vendor\App\Theme`,
		Category: pb.Category_CATEGORY_REGISTRY,
	}); d.RuleName != "reg-only" || d.Level != l1 {
		t.Fatalf("registry-typed rule not applied: %+v", d)
	}
	// The same pattern as a file target must not match the registry rule.
	if d := c.Classify(Candidate{
		Path:     `HKLM\SOFTWARE\Vendor\App\Theme`,
		Category: pb.Category_CATEGORY_CONFIG,
	}); d.RuleName == "reg-only" {
		t.Fatalf("target_type filter ignored: %+v", d)
	}
}

func TestPolicyRuleEmptyPatternMatchesAny(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "catch-all", Level: 3, Diff: false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/opt/app/lib/x.jar"}); d.RuleName != "catch-all" || d.Level != l3 {
		t.Fatalf("empty pattern should match any target: %+v", d)
	}
}

func TestPolicyRuleRaisesAndLowersDefaultLevels(t *testing.T) {
	// Raise: a normally-drift web asset is promoted to Critical.
	raise, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "promote", Pattern: "/var/www/html/**", Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := raise.Classify(Candidate{Path: "/var/www/html/index.html"}); d.Level != l1 || !d.Diff {
		t.Fatalf("rule should raise drift to critical: %+v", d)
	}

	// Lower: a normally-critical /etc path is demoted to drift, diff off.
	lower, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "demote", Pattern: "/etc/nginx/conf.d/**", Level: 3, Diff: false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := lower.Classify(Candidate{Path: "/etc/nginx/conf.d/site.conf"}); d.Level != l3 || d.Diff {
		t.Fatalf("rule should lower critical to drift: %+v", d)
	}
}

func TestPolicyRuleTagsMetadata(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "checkout", Pattern: "/srv/checkout/**", Level: 1, Diff: true, Tags: []string{"pci", "prod", "web"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := c.Classify(Candidate{Path: "/srv/checkout/appsettings.json"})
	if d.RuleTags != "pci,prod,web" {
		t.Fatalf("tags should be sorted and comma-joined, got %q", d.RuleTags)
	}
}

func TestPolicyRuleNameFallsBackToPattern(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Pattern: "/srv/anon/**", Level: 2, Diff: false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/srv/anon/x"}); d.RuleName != "/srv/anon/**" {
		t.Fatalf("unnamed rule should fall back to its pattern: %+v", d)
	}
}

func TestPolicyRuleClampsOutOfRangeLevels(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "too-high", Pattern: "/srv/high/**", Level: 9, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/srv/high/x"}); d.Level != l4 {
		t.Fatalf("level above 4 should clamp to 4: %+v", d)
	}
}

func TestPolicyRuleBadGlobRejected(t *testing.T) {
	if _, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "bad", Pattern: "/etc/[abc", Level: 1},
	}}); err == nil {
		t.Fatal("expected an error for a malformed rule glob")
	}
}

func TestPolicyRulesReconfigureSwapsAtomically(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "old", Pattern: "/srv/app/**", Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/srv/app/x"}); d.RuleName != "old" {
		t.Fatalf("precondition: %+v", d)
	}
	if err := c.Reconfigure(ClassifierConfig{Rules: []PolicyRule{
		{Name: "new", Pattern: "/srv/app/**", Level: 3, Diff: false},
	}}); err != nil {
		t.Fatal(err)
	}
	if d := c.Classify(Candidate{Path: "/srv/app/x"}); d.RuleName != "new" || d.Level != l3 {
		t.Fatalf("reconfigure did not swap rules: %+v", d)
	}
	// A failed reconfigure must keep the previous rules.
	if err := c.Reconfigure(ClassifierConfig{Rules: []PolicyRule{{Name: "bad", Pattern: "[x", Level: 1}}}); err == nil {
		t.Fatal("bad rule set accepted")
	}
	if d := c.Classify(Candidate{Path: "/srv/app/x"}); d.RuleName != "new" {
		t.Fatalf("failed reconfigure must keep the previous rules: %+v", d)
	}
}

func TestPolicyRulesDoNotAffectNonPathEvents(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "catch-all", Level: 3, Diff: false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Service events are pathless and must still classify as critical.
	if d := c.Classify(Candidate{Category: pb.Category_CATEGORY_SERVICE}); d.Level != l1 {
		t.Fatalf("pathless service event should ignore rules: %+v", d)
	}
	// File events with a Tool grouping only matched rules win; a matching
	// rule overrides the Level 2 grouping default.
	apt := &Tool{Name: "apt", Kind: ToolPackageManager}
	if d := c.Classify(Candidate{Path: "/srv/app/x", Tool: apt}); d.Level != l3 || d.RuleName != "catch-all" {
		t.Fatalf("rule should override tool grouping: %+v", d)
	}
}

func TestPolicyRuleGroupedTransactionStillLevel2(t *testing.T) {
	c, err := NewClassifier(ClassifierConfig{Rules: []PolicyRule{
		{Name: "exact", Pattern: "/etc/nginx/nginx.conf", Level: 1, Diff: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	apt := &Tool{Name: "apt", Kind: ToolPackageManager}
	// No rule matches this packaged payload, so grouping keeps it Level 2.
	if d := c.Classify(Candidate{Path: "/usr/sbin/nginx", Tool: apt}); d.Level != l2 {
		t.Fatalf("unmatched grouped payload should stay Level 2: %+v", d)
	}
	// The matching config file is promoted by its rule despite grouping.
	if d := c.Classify(Candidate{Path: "/etc/nginx/nginx.conf", Tool: apt}); d.Level != l1 || d.RuleName != "exact" {
		t.Fatalf("matching rule should override grouping level: %+v", d)
	}
}
