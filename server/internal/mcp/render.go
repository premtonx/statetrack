package mcp

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is the sentinel a backend returns for a resource that does not
// exist in the caller's org. It is a plain error rather than a *Error so a
// backend implementation does not have to depend on the JSON-RPC layer's error
// codes to signal a domain condition.
var ErrNotFound = errors.New("not found")

// IsNotFound reports whether an error means "no such resource". It matches the
// sentinel with errors.Is so a backend that wraps it (adding context about what
// was looked up) is still recognised.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

/* -------------------------------------------------------------------------- */
/* Text renderers                                                             */
/* -------------------------------------------------------------------------- */

// The renderers below produce the human- and model-readable text block that
// accompanies every tool result. They exist because a model reads text far more
// reliably than it reads nested JSON: a compact table plus a one-line summary is
// what lets it answer a question without another round trip, while
// StructuredContent remains available for a client that renders UI.
//
// Every renderer is deterministic — no map iteration in output, no wall-clock
// timestamps beyond the data's own — so the same call twice produces the same
// bytes, which makes a transcript reproducible and a tool result diffable.

// RenderChanges renders a change list as a compact table.
func RenderChanges(changes []Change, f ChangeFilter) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d change(s)", len(changes))
	if parts := filterPhrase(f); parts != "" {
		fmt.Fprintf(&sb, " matching %s", parts)
	}
	sb.WriteString(".\n\n")

	if len(changes) == 0 {
		sb.WriteString("No changes matched. Widen the window, or drop a filter.\n")
		return sb.String()
	}

	sb.WriteString("| Event ID | Time (UTC) | Lvl | Host | Target | Actor | Summary |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, c := range changes {
		fmt.Fprintf(&sb, "| `%s` | %s | L%d | %s | `%s` | %s | %s |\n",
			c.ID, formatTime(c.OccurredAt), c.Level,
			cell(c.Host), cell(c.PathOrKey), cell(orDash(c.Actor)), cell(c.Summary))
		if c.ChildCount > 0 {
			fmt.Fprintf(&sb, "| | | | | | | ↳ %d aggregated child change(s) inside this transaction |\n", c.ChildCount)
		}
	}
	sb.WriteString("\nUse statetrack_get_diff with an Event ID to read the change, or " +
		"statetrack_analyze_and_rollback for the rollback plan.\n")
	return sb.String()
}

// RenderDiff renders one change's identity, lineage and scrubbed diff.
func RenderDiff(d Diff) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Change `%s` on %s\n\n", d.ID, orDash(d.Host))
	fmt.Fprintf(&sb, "- **When:** %s\n", formatTime(d.OccurredAt))
	fmt.Fprintf(&sb, "- **Severity:** %s\n", orDash(d.LevelLabel))
	fmt.Fprintf(&sb, "- **Target:** `%s` (%s)\n", d.PathOrKey, d.TargetType)
	fmt.Fprintf(&sb, "- **Summary:** %s\n", d.Summary)

	if d.Actor != "" || d.Process != "" || d.RemoteIP != "" || len(d.Lineage) > 0 {
		sb.WriteString("\n### Actor lineage\n\n")
		if d.RemoteIP != "" {
			fmt.Fprintf(&sb, "- Originating IP: `%s`\n", d.RemoteIP)
		}
		if d.Actor != "" {
			fmt.Fprintf(&sb, "- Actor: %s", d.Actor)
			if d.UID != "" {
				fmt.Fprintf(&sb, " (uid %s)", d.UID)
			}
			sb.WriteString("\n")
		}
		if len(d.Lineage) > 0 {
			fmt.Fprintf(&sb, "- Process tree: %s\n", strings.Join(d.Lineage, " → "))
		} else if d.Process != "" {
			fmt.Fprintf(&sb, "- Process: %s\n", d.Process)
		}
		if d.Cmdline != "" {
			fmt.Fprintf(&sb, "- Command line: `%s`\n", d.Cmdline)
		}
	} else {
		sb.WriteString("\nNo actor could be attributed to this change.\n")
	}

	sb.WriteString("\n### Scrubbed diff\n\n")
	if strings.TrimSpace(d.Diff) == "" {
		sb.WriteString("No text diff was recorded (the change stored hashes only).\n")
		fmt.Fprintf(&sb, "- Before: `%s`\n- After: `%s`\n", orDash(d.HashBefore), orDash(d.HashAfter))
	} else {
		if d.DiffRedacted {
			sb.WriteString("Secret-looking values were replaced with `[REDACTED:sha256:…]` stubs at the host. " +
				"The stubs are stable, so two edits to the same secret remain distinguishable. " +
				"Do not attempt to recover the original values.\n\n")
		}
		sb.WriteString("```diff\n")
		sb.WriteString(strings.TrimRight(d.Diff, "\n"))
		sb.WriteString("\n```\n")
	}

	if len(d.Children) > 0 {
		fmt.Fprintf(&sb, "\n### Aggregated children (%d)\n\n", len(d.Children))
		sb.WriteString("| Event ID | Time (UTC) | Target | Actor | Summary |\n| --- | --- | --- | --- | --- |\n")
		for _, c := range d.Children {
			fmt.Fprintf(&sb, "| `%s` | %s | `%s` | %s | %s |\n",
				c.ID, formatTime(c.OccurredAt), cell(c.PathOrKey), cell(orDash(c.Actor)), cell(c.Summary))
		}
	}
	return sb.String()
}

// RenderHostSummary renders the health rollup.
func RenderHostSummary(s HostSummary) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s\n\n", orDash(s.Host))
	state := "offline"
	if s.Online {
		state = "online"
	}
	fmt.Fprintf(&sb, "- **Status:** %s (last reported %s ago)\n", state, humanDuration(time.Duration(s.LastSeenSeconds)*time.Second))
	if s.OS != "" {
		fmt.Fprintf(&sb, "- **Platform:** %s\n", s.OS)
	}
	fmt.Fprintf(&sb, "- **Window:** %s\n", orDash(s.Window))
	fmt.Fprintf(&sb, "- **Tracked configuration targets:** %d\n", s.DriftTargetsCount)

	if len(s.Counts) > 0 {
		fmt.Fprintf(&sb, "- **Changes in window:** %d total · %d critical · %d grouped · %d drift · %d forensic\n",
			s.Counts["total"], s.Counts["l1_critical"], s.Counts["l2_grouped"],
			s.Counts["l3_drift"], s.Counts["l4_forensic"])
	}
	if s.LatestCritical != nil {
		lc := s.LatestCritical
		fmt.Fprintf(&sb, "\n### Most recent critical change\n\n")
		fmt.Fprintf(&sb, "- **When:** %s\n", formatTime(lc.OccurredAt))
		fmt.Fprintf(&sb, "- **Target:** `%s`\n", lc.PathOrKey)
		fmt.Fprintf(&sb, "- **Summary:** %s\n", lc.Summary)
		if lc.Actor != "" {
			fmt.Fprintf(&sb, "- **Actor:** %s", lc.Actor)
			if lc.Process != "" {
				fmt.Fprintf(&sb, " via %s", lc.Process)
			}
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "- **Event ID:** `%s`\n", lc.ID)
	} else {
		sb.WriteString("\nNo critical change was recorded in this window.\n")
	}
	if s.ConsoleURL != "" {
		fmt.Fprintf(&sb, "\nConsole: %s\n", s.ConsoleURL)
	}
	return sb.String()
}

// RenderAnalysis renders the risk assessment and the rollback plan. The commands
// are fenced so a client can offer them as copy-pasteable blocks, and the engine
// is stated so the reader knows whether a model or the offline rules answered.
func RenderAnalysis(a Analysis) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Blast radius: %s\n\n", orDash(a.BlastRadius))
	fmt.Fprintf(&sb, "**Engine:** %s", orDash(a.ProviderLabel))
	if a.Model != "" {
		fmt.Fprintf(&sb, " (`%s`)", a.Model)
	}
	if a.LatencyMS > 0 {
		fmt.Fprintf(&sb, " · answered in %d ms", a.LatencyMS)
	}
	sb.WriteString("\n\n")

	if a.Fallback {
		sb.WriteString("> The configured AI provider was unreachable, so the built-in offline heuristics produced this ")
		sb.WriteString("assessment")
		if a.FallbackReason != "" {
			fmt.Fprintf(&sb, " (%s)", a.FallbackReason)
		}
		sb.WriteString(". Treat it as a rule-based answer, not a model's judgement.\n\n")
	}
	if a.Scrubbed {
		sb.WriteString("> The assessment reasoned only over the scrubbed diff; no secret value left the host.\n\n")
	}

	if a.RiskSummary != "" {
		fmt.Fprintf(&sb, "%s\n\n", a.RiskSummary)
	}
	if len(a.AffectedServices) > 0 {
		sb.WriteString("**Expected to affect**\n\n")
		for _, s := range a.AffectedServices {
			fmt.Fprintf(&sb, "- %s\n", s)
		}
		sb.WriteString("\n")
	}
	if a.RollbackCommand != "" {
		sb.WriteString("**Safe rollback**\n\n```bash\n")
		sb.WriteString(a.RollbackCommand)
		sb.WriteString("\n```\n\n")
	} else {
		sb.WriteString("No generic rollback command could be derived for this target. ")
		sb.WriteString("Restore the previous revision from the host's configuration management.\n\n")
	}
	if a.VerificationCommand != "" {
		sb.WriteString("**Verification after rollback**\n\n```bash\n")
		sb.WriteString(a.VerificationCommand)
		sb.WriteString("\n```\n\n")
	}
	if a.RollbackNotes != "" {
		fmt.Fprintf(&sb, "> %s\n", a.RollbackNotes)
	}
	sb.WriteString("\nShow the rollback command to the operator before running it.\n")
	return sb.String()
}

/* -------------------------------------------------------------------------- */
/* Formatting helpers                                                         */
/* -------------------------------------------------------------------------- */

// formatTime renders an RFC3339 instant pass-through, so a client that parses
// the text and the structured field sees the same value.
func formatTime(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC().Format("2006-01-02 15:04:05")
	}
	return value
}

// humanDuration renders an age for prose ("4m12s", "2h").
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// cell makes a value safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// filterPhrase renders the applied filters for the list header, so a model (and
// a human reading the transcript) can tell an empty result from an unfiltered
// one.
func filterPhrase(f ChangeFilter) string {
	var parts []string
	if f.Host != "" {
		parts = append(parts, "host "+f.Host)
	}
	if f.ImpactLevel > 0 {
		parts = append(parts, fmt.Sprintf("level %d", f.ImpactLevel))
	}
	if f.Category > 0 {
		parts = append(parts, "category "+categoryName(f.Category))
	}
	if f.Actor != "" {
		parts = append(parts, "actor "+f.Actor)
	}
	if f.Search != "" {
		parts = append(parts, fmt.Sprintf("search %q", f.Search))
	}
	parts = append(parts, "the last "+canonicalDuration(f.Window))
	return strings.Join(parts, ", ")
}

// categoryName is the inverse of categoryNumber, for the filter phrase.
func categoryName(n int) string {
	all := categoryArgs()
	if n >= 1 && n <= len(all) {
		return all[n-1]
	}
	return fmt.Sprintf("%d", n)
}

// canonicalDuration renders a duration back into the compact form a caller used.
func canonicalDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
}
