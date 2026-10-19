package ai

import (
	"strings"

	"github.com/statetrack/statetrack/server/internal/postmortem"
)

// deterministic derives the risk summary, blast radius and rollback command
// from the event alone, with no network and no model.
//
// It is a thin, deliberate adapter over internal/postmortem's remediation
// derivation: that is the single implementation of "what is the safe command to
// undo this target", and duplicating it would let the console's answer drift
// from the exported post-mortem's for the same change. What this adds is the
// coarse Low/Medium/High band, which is the console's and the alert's
// vocabulary rather than the report's prose.
func (g *Gateway) deterministic(ev Event) Analysis {
	br := postmortem.DeriveBlastRadius(postmortem.RemediationInput{
		TargetType:  ev.TargetType,
		PathOrKey:   ev.PathOrKey,
		Action:      ev.Action,
		LevelLabel:  ev.LevelLabel,
		OSFamily:    ev.OSFamily,
		DiffPresent: strings.TrimSpace(ev.Diff) != "",
	})

	out := Analysis{
		Provider:            string(ProviderDeterministic),
		ProviderLabel:       ProviderLabel(string(ProviderDeterministic)),
		RiskSummary:         br.RiskSummary,
		BlastRadius:         bandFor(ev, br),
		AffectedServices:    br.AffectedServices,
		RollbackCommand:     br.RollbackCommand,
		VerificationCommand: br.VerifyCommand,
		RollbackNotes:       br.RollbackNotes,
		Scrubbed:            ev.DiffRedacted || HasRedactions(ev.Diff),
	}

	// A change we cannot classify is still a change an operator has to act on.
	// An empty risk summary would render an empty drawer, so it is replaced with
	// a sentence that is honest about the limitation and points at the evidence.
	if strings.TrimSpace(out.RiskSummary) == "" {
		out.RiskSummary = "The blast radius of this target could not be determined from its path. " +
			"Review the diff and the host's role before acting."
	}
	// Append the attribution context the report's prose does not include, because
	// the console has the actor and process at hand and an operator triaging from
	// the drawer benefits from seeing them folded into the assessment.
	if note := attributionNote(ev); note != "" {
		out.RiskSummary += " " + note
	}
	return out
}

// bandFor maps the change onto Low/Medium/High.
//
// The band is driven by the impact level first — that is the classification the
// agent's policy engine already made with full knowledge of the host and the
// matched rule — and only refined by the target class. A Level 1 change is High
// regardless of target, so a Level 1 identity-file edit cannot be reported as
// "Low" merely because its component could not be identified.
func bandFor(ev Event, br postmortem.BlastRadius) string {
	switch ev.Level {
	case 1:
		return BlastRadiusHigh
	case 2:
		return BlastRadiusMedium
	case 3, 4:
		// Drift and forensic-sampling rows are informational: they record that a
		// file differs, not that anything was broken.
		return BlastRadiusLow
	}
	// An unknown level with a derived rollback plan is more consequential than
	// one with none, so it is not reported as Low.
	if strings.TrimSpace(br.RollbackCommand) != "" {
		return BlastRadiusMedium
	}
	return BlastRadiusLow
}

// attributionNote renders the actor lineage as a clause appended to the risk
// summary, so the drawer answers "who did this" alongside "what breaks".
func attributionNote(ev Event) string {
	who := firstNonEmpty(ev.Actor, "an unattributed actor")
	switch {
	case ev.Process != "" && ev.RemoteIP != "":
		return "Attributed to " + who + " via " + ev.Process + " from " + ev.RemoteIP + "."
	case ev.Process != "":
		return "Attributed to " + who + " via " + ev.Process + "."
	case ev.RemoteIP != "":
		return "Attributed to " + who + " from " + ev.RemoteIP + "."
	case ev.Actor != "":
		return "Attributed to " + ev.Actor + "."
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
