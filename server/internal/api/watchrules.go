package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/statetrack/statetrack/server/internal/storage"
)

// watchRuleView is the console's representation of a watched target.
//
// It is the stored rule plus the labels the builder needs to render a row: the
// scope the operator chose ("All Hosts" or a hostname), the display name of the
// target type, and a phrase for the capture mode. All three are derived
// server-side so the browser never has to know that the fleet scope is stored as
// a NULL host id.
type watchRuleView struct {
	storage.WatchRule
	// TargetLabel is the display name of the target type ("IIS App Pool").
	TargetLabel string `json:"target_label"`
	// ImpactLabel is the display name of the level ("Level 1 Critical").
	ImpactLabel string `json:"impact_label"`
	// DiffMode is the human phrase for the capture mode, so the table's
	// "Capture" column is not a boolean rendered as "true".
	DiffMode string `json:"diff_mode"`
}

// watchTargetType is one option in the builder's Target Type dropdown.
type watchTargetType struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Help        string `json:"help"`
	// Platforms narrows the option to the hosts where it can work at all.
	Platforms []string `json:"platforms,omitempty"`
}

// watchTargetCatalog is the single source of truth for the builder's Target
// Type dropdown.
//
// It is served rather than hard-coded in the browser because the placeholder an
// operator sees has to be a path the agent can actually watch: a wrong example
// (`/opt/app/.env` on Windows) produces a rule that silently never matches,
// which is worse than no rule at all.
var watchTargetCatalog = []watchTargetType{
	{
		Value: storage.WatchTypeFile, Label: "File",
		Placeholder: `C:\inetpub\wwwroot\checkout\web.config`,
		Help:        "One configuration file. Supports * and ? wildcards in the file name.",
	},
	{
		Value: storage.WatchTypeDirectory, Label: "Directory",
		Placeholder: `D:\Apps\Billing\Config\**`,
		Help:        "A tree. Use ** to include subdirectories; a trailing * watches the top level only.",
	},
	{
		Value: storage.WatchTypeIISPool, Label: "IIS App Pool",
		Placeholder: "iis://apppool/CheckoutAppPool",
		Help:        "State, identity, recycling and rapid-fail protection. A pool that stops is Level 1.",
		Platforms:   []string{"windows"},
	},
	{
		Value: storage.WatchTypeIISSite, Label: "IIS Site",
		Placeholder: "iis://site/Checkout",
		Help:        "Bindings, SSL thumbprint, physical path and application pool mapping.",
		Platforms:   []string{"windows"},
	},
	{
		Value: storage.WatchTypeDBTable, Label: "Database Table",
		Placeholder: "db://postgres/settings_db/tables/public.app_settings",
		Help:        "A configuration table, read-only, ordered by primary key. Secret values are scrubbed at the edge.",
	},
	{
		Value: storage.WatchTypeDBSchema, Label: "Database Schema",
		Placeholder: "db://postgres/settings_db/schema",
		Help:        "Table columns and role grants, to catch an ALTER TABLE or a privilege change.",
	},
	{
		Value: storage.WatchTypeDBParams, Label: "Database Parameters",
		Placeholder: "db://postgres/settings_db/server_params",
		Help:        "Non-default server settings, to catch a live ALTER SYSTEM or sp_configure.",
	},
	{
		Value: storage.WatchTypeRegistry, Label: "Registry Key",
		Placeholder: `HKLM\Software\Company\App\**`,
		Help:        "A registry key and its values. A hive prefix (HKLM, HKCU, HKU) is required.",
		Platforms:   []string{"windows"},
	},
	{
		Value: storage.WatchTypeService, Label: "Service",
		Placeholder: "W3SVC",
		Help:        "One Windows service or systemd unit by name; the name is matched exactly.",
	},
	{
		Value: storage.WatchTypeK8sObject, Label: "Kubernetes Object",
		Placeholder: "/k8s/prod-k8s-01/production/configmaps/checkout-config",
		Help:        "One object by tracked path. The cluster watcher renders it at the same path it reports.",
	},
}

// defaultWatchLevel is the builder's default option: the "Full Diff & Instant
// Alert" choice, because a watched target an operator adds deliberately is
// almost always something they want to be told about immediately.
const defaultWatchLevel = storage.ImpactLevelCritical

// watchImpactLevels are the two choices the builder offers.
//
// Level 2 (grouped) and Level 4 (forensic) are deliberately absent: neither is
// a property of a watched target. Grouping comes from the process ancestry, and
// forensic collection is a time-boxed host toggle, so offering them here would
// create rules that mean something different from what the label says.
func watchImpactLevels() []map[string]any {
	return []map[string]any{
		{"value": storage.ImpactLevelCritical, "label": "Level 1 Critical",
			"help": "Full text diff and an instant alert. Use for production configuration.", "diff": true},
		{"value": storage.ImpactLevelDrift, "label": "Level 3 Drift",
			"help": "Hash only, no diff. Use for large or low-risk trees.", "diff": false},
	}
}

// watchRules serves the watched-target list and the builder's catalog.
func (s *Server) watchRules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rules, err := s.Store.ListWatchRules(r.Context(), s.OrgID, q.Get("target_type"), q.Get("host_scope"))
	if err != nil {
		writeErr(w, err)
		return
	}
	views := make([]watchRuleView, 0, len(rules))
	byType := map[string]int{}
	byHost := map[string]int{}
	critical := 0
	for _, rule := range rules {
		views = append(views, viewOf(rule))
		byType[rule.TargetType]++
		byHost[rule.HostScope]++
		if rule.Level == storage.ImpactLevelCritical {
			critical++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":    views,
		"count":    len(views),
		"critical": critical,
		"by_type":  byType,
		"by_host":  byHost,
		// The catalog ships with the list so the modal can open instantly and
		// cannot drift from what the server will accept.
		"target_types":  watchTargetCatalog,
		"impact_levels": watchImpactLevels(),
		"default_level": defaultWatchLevel,
	})
}

// createWatchRule adds a custom watched target.
//
// The audit row is written by the mutation wrapper, which is the only caller
// that knows the insert succeeded; addAuditDetail contributes the fields that
// make the row meaningful beyond the path it already carries.
func (s *Server) createWatchRule(w http.ResponseWriter, r *http.Request) {
	var in storage.WatchRuleInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}
	createdBy := ""
	if p := PrincipalFrom(r.Context()); p != nil {
		createdBy = p.ActorEmail()
	}
	rule, err := s.Store.CreateWatchRule(r.Context(), s.OrgID, createdBy, in)
	if err != nil {
		if isValidationError(err) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeErr(w, err)
		return
	}
	addAuditDetail(r, "rule_id", rule.ID)
	addAuditDetail(r, "name", rule.Name)
	addAuditDetail(r, "target_type", rule.TargetType)
	addAuditDetail(r, "host_scope", rule.HostScope)
	addAuditDetail(r, "level", rule.Level)
	addAuditDetail(r, "diff", rule.Diff)
	writeJSON(w, http.StatusCreated, viewOf(rule))
}

// deleteWatchRule removes a watched target.
//
// The audit row is written by the mutation wrapper after this returns, so the
// wrapper resolves its target from the route ({id}) before the handler runs.
// setAuditTarget replaces that id with the pattern the rule actually watched,
// because "stopped watching D:\Apps\Billing\Config\**" is the sentence an
// auditor needs and a UUID is not.
func (s *Server) deleteWatchRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rule, err := s.Store.DeleteWatchRule(r.Context(), s.OrgID, id)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "watched target not found", "id": id})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	// The target in the audit row is the rule's own pattern, so removing a
	// watch is recorded as "stopped watching <path>" rather than "deleted <id>".
	setAuditTarget(r, rule.Pattern)
	addAuditDetail(r, "rule_id", rule.ID)
	addAuditDetail(r, "name", rule.Name)
	addAuditDetail(r, "target_type", rule.TargetType)
	addAuditDetail(r, "host_scope", rule.HostScope)
	addAuditDetail(r, "level", rule.Level)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "deleted", "id": rule.ID, "pattern": rule.Pattern, "rule": viewOf(rule),
	})
}

// viewOf decorates a stored rule for the console.
func viewOf(rule storage.WatchRule) watchRuleView {
	view := watchRuleView{
		WatchRule:   rule,
		TargetLabel: rule.TargetType,
		ImpactLabel: "Level 3 Drift",
		DiffMode:    "Hash only",
	}
	for _, t := range watchTargetCatalog {
		if t.Value == rule.TargetType {
			view.TargetLabel = t.Label
			break
		}
	}
	if rule.Level == storage.ImpactLevelCritical {
		view.ImpactLabel, view.DiffMode = "Level 1 Critical", "Full diff"
	}
	if rule.HostID == "" {
		view.HostScope = storage.FleetScope
	}
	return view
}

// isValidationError reports whether err is an input problem rather than an
// infrastructure one.
//
// The store validates before it queries, so a validation failure carries no SQL
// state. Matching on the message is not elegant, but the alternative — a
// sentinel-wrapped error for each rule — would put a dozen exported error values
// in the storage package to describe conditions only one screen can cause.
func isValidationError(err error) bool {
	msg := err.Error()
	for _, marker := range []string{
		"unsupported target type", "pattern is required", "impact level must be",
		"must be a db:// path", "must name /tables/", "must start with a hive",
		"must be an absolute object path", "not found",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
