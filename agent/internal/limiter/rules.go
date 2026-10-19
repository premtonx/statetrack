package limiter

import (
	"sort"
	"strings"
)

// PolicyRule is a granular, operator-authored classification override. Rules
// are matched against a mutation's target (path or registry key) and can
// raise, lower or drop an event's impact level, and independently control
// whether a text diff is captured.
//
// Matching precedence (see Classifier.Classify):
//
//  1. Level 0 hard blacklist — dropped before any rule is consulted.
//  2. Exact target rule  — rule.Pattern equals the target with no wildcards.
//  3. Glob pattern rule  — rule.Pattern matched as a wildcard glob.
//  4. Fallback           — the default category/path level.
type PolicyRule struct {
	// Name identifies the rule; it is attached to matched events as
	// metadata["rule_name"].
	Name string `json:"name" yaml:"name"`
	// TargetType restricts the rule to a target type ("file", "registry",
	// "service", ...). Empty matches any target type.
	TargetType string `json:"target_type" yaml:"target_type"`
	// Pattern is the exact target or wildcard glob matched against the
	// target's path or key. Empty matches any target.
	Pattern string `json:"pattern" yaml:"pattern"`
	// Level is the impact level to apply. Level 0 is a hard drop (equivalent
	// to the blacklist). 1–4 are the standard impact levels.
	Level int `json:"level" yaml:"level"`
	// Diff controls whether a text diff is captured for matched events.
	Diff bool `json:"diff" yaml:"diff"`
	// Tags are surfaced on matched events as metadata["rule_tags"].
	Tags []string `json:"tags" yaml:"tags"`
}

// policyRules is the compiled form of a []PolicyRule.
type policyRules struct {
	exact []compiledRule // patterns without wildcards
	globs []compiledRule // wildcard patterns, in declaration order
}

type compiledRule struct {
	rule       PolicyRule
	targetType string
	pattern    string // normalised exact pattern (for exact rules)
	match      *Matcher
}

// compileRules compiles rules, rejecting malformed globs. Order is preserved
// within each tier so the first declared match wins.
func compileRules(rules []PolicyRule) (*policyRules, error) {
	pr := &policyRules{}
	for _, r := range rules {
		name := r.Name
		if name == "" {
			name = r.Pattern
		}
		r.Name = name
		cr := compiledRule{rule: r, targetType: strings.ToLower(strings.TrimSpace(r.TargetType))}
		if r.Pattern == "" {
			// Match-any rule: compile as a catch-all glob.
			m, err := NewMatcher("*")
			if err != nil {
				return nil, err
			}
			cr.match = m
			pr.globs = append(pr.globs, cr)
			continue
		}
		if !hasGlobMeta(r.Pattern) {
			cr.pattern = normTarget(r.Pattern)
			pr.exact = append(pr.exact, cr)
			continue
		}
		m, err := NewMatcher(r.Pattern)
		if err != nil {
			return nil, err
		}
		cr.match = m
		pr.globs = append(pr.globs, cr)
	}
	return pr, nil
}

// match returns the first rule matching the candidate, preferring exact
// matches over glob matches.
func (pr *policyRules) match(path, targetType string) (PolicyRule, bool) {
	if pr == nil {
		return PolicyRule{}, false
	}
	if path != "" {
		nt := normTarget(path)
		for _, cr := range pr.exact {
			if !ruleTypeMatches(cr.targetType, targetType) {
				continue
			}
			if normTarget(cr.pattern) == nt {
				return cr.rule, true
			}
		}
	}
	for _, cr := range pr.globs {
		if !ruleTypeMatches(cr.targetType, targetType) {
			continue
		}
		if cr.match == nil {
			continue
		}
		if _, ok := cr.match.MatchPattern(path); ok {
			return cr.rule, true
		}
	}
	return PolicyRule{}, false
}

// ruleTypeMatches reports whether a rule scoped to ruleType applies to a
// document of docType.
//
// An exact match is the normal case. The prefix form exists so one rule can
// cover a family of related surfaces: a database watcher emits three document
// kinds (table, schema, server parameters) for one database, and an operator
// who wrote "database" once in the rule builder must not have to write it three
// times. The family is deliberately underscore-scoped ("database" covers
// "database_table" but never "databasez"), so a typo cannot silently widen a
// rule.
func ruleTypeMatches(ruleType, docType string) bool {
	if ruleType == "" || ruleType == docType {
		return true
	}
	return strings.HasPrefix(docType, ruleType+"_")
}

// RulePatterns returns the patterns of every rule scoped to targetType, in
// declaration order.
//
// The surgical watchers use this to discover *what* to watch: a rule authored
// in the console for target_type=iis_apppool with pattern
// iis://apppool/CheckoutAppPool is simultaneously the classification override
// and the instruction to start tracking that pool. Reading the rules instead of
// a second config list is what makes a rule added in the console take effect on
// the next heartbeat with no agent edit.
func (c *Classifier) RulePatterns(targetType string) []string {
	r := c.rules.Load()
	if r == nil || r.policy == nil {
		return nil
	}
	var out []string
	for _, cr := range r.policy.exact {
		if ruleTypeMatches(cr.targetType, targetType) && cr.rule.Pattern != "" {
			out = append(out, cr.rule.Pattern)
		}
	}
	for _, cr := range r.policy.globs {
		if ruleTypeMatches(cr.targetType, targetType) && cr.rule.Pattern != "" {
			out = append(out, cr.rule.Pattern)
		}
	}
	return out
}

// hasGlobMeta reports whether p contains glob metacharacters.
func hasGlobMeta(p string) bool {
	return strings.ContainsAny(p, "*?[")
}

// normTarget normalises a path/key for exact comparison: separators unified,
// and lower-cased for Windows-style paths and registry keys (which are
// case-insensitive) while POSIX paths stay case-sensitive.
func normTarget(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if isWindowsStyle(p) || strings.HasPrefix(strings.ToUpper(p), "HK") {
		return strings.ToLower(p)
	}
	return p
}

// normalizedTags returns the rule's tags as a sorted, comma-joined string for
// stable event metadata.
func (r PolicyRule) normalizedTags() string {
	if len(r.Tags) == 0 {
		return ""
	}
	tags := append([]string(nil), r.Tags...)
	sort.Strings(tags)
	return strings.Join(tags, ",")
}
