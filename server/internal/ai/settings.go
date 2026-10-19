package ai

import (
	"encoding/json"
	"errors"
	"strings"
)

// NormalizeSettings fills in defaults and clamps every field onto a safe range,
// so a settings row written by an older build (or hand-edited) still produces a
// usable configuration rather than a zero timeout or an unknown provider.
func NormalizeSettings(s Settings) Settings {
	def := DefaultSettings()
	if !IsValidProvider(string(s.Provider)) {
		s.Provider = def.Provider
	}
	if s.Temperature < 0 || s.Temperature > 1 {
		// Above 1 the model starts inventing commands, which is the one failure
		// mode this feature cannot afford.
		s.Temperature = def.Temperature
	}
	if s.MaxTokens <= 0 || s.MaxTokens > 8000 {
		s.MaxTokens = def.MaxTokens
	}
	if s.TimeoutSeconds <= 0 || s.TimeoutSeconds > 120 {
		s.TimeoutSeconds = def.TimeoutSeconds
	}
	return s
}

// modelReply is the structured answer we ask every provider for.
type modelReply struct {
	RiskSummary         string   `json:"risk_summary"`
	BlastRadius         string   `json:"blast_radius"`
	AffectedServices    []string `json:"affected_services"`
	RollbackCommand     string   `json:"rollback_command"`
	VerificationCommand string   `json:"verification_command"`
	RollbackNotes       string   `json:"rollback_notes"`
}

// parseModelReply extracts the JSON object from a model's reply.
//
// Models wrap JSON in prose, in ```json fences, or in both, so the parse is
// lenient about *where* the object is and strict about *what* it contains: a
// reply that does not yield a risk summary is a failure the caller degrades
// from, because an empty drawer is worse than the deterministic fallback. The
// first brace-balanced object in the text is used, which handles a leading
// "Here is the analysis:" as well as a trailing explanation.
func parseModelReply(raw string) (modelReply, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return modelReply{}, errors.New("the model returned an empty reply")
	}

	// Strip a fenced block if one is present, preferring the last fence so a
	// model that echoes its instructions first does not have the echoed example
	// parsed instead of its answer.
	if idx := strings.Index(text, "```"); idx >= 0 {
		if end := strings.Index(text[idx+3:], "```"); end >= 0 {
			inner := text[idx+3 : idx+3+end]
			// Drop the language tag on the opening fence.
			if nl := strings.IndexByte(inner, '\n'); nl >= 0 {
				inner = inner[nl+1:]
			}
			if strings.Contains(inner, "{") {
				text = strings.TrimSpace(inner)
			}
		}
	}

	candidate := firstJSONObject(text)
	if candidate == "" {
		return modelReply{}, errors.New("the model's reply contained no JSON object")
	}

	var reply modelReply
	if err := json.Unmarshal([]byte(candidate), &reply); err != nil {
		return modelReply{}, errors.New("the model's reply was not valid JSON: " + err.Error())
	}
	if strings.TrimSpace(reply.RiskSummary) == "" {
		return modelReply{}, errors.New("the model's reply had no risk_summary field")
	}
	reply.RiskSummary = strings.TrimSpace(reply.RiskSummary)
	reply.AffectedServices = trimAll(reply.AffectedServices)
	return reply, nil
}

// firstJSONObject returns the first brace-balanced object in the text, ignoring
// braces inside string literals. It returns "" when there is no object.
//
// This is deliberately a small scanner rather than a regex: matching nested
// JSON with a regex is not possible in general, and a naive "first { to last }"
// slice breaks the moment a model adds a sentence after its answer.
func firstJSONObject(text string) string {
	start := strings.IndexByte(text, '{')
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(text); i++ {
		c := text[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inString:
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// Braces inside a string are literal content.
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return text[start : i+1]
			}
		}
	}
	// Unbalanced: the reply was truncated. Returning "" makes the caller
	// degrade rather than feed half an object to the decoder.
	return ""
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
