package postmortem

import (
	"path"
	"strings"
)

// blast radius and remediation derivation.
//
// The report's value in an incident is that it says what to *do*, not only what
// happened. Deriving that generically is impossible — no tool knows that this
// particular nginx box is behind an F5 — so the approach is: derive the specific
// command for the target types where the correct answer is knowable from the
// path alone (a systemd unit, an nginx config, a Kubernetes ConfigMap), and name
// the affected services for the rest. Anything the derivation cannot answer
// confidently is left empty, and the report says so, rather than emitting a
// plausible-looking command that damages production.

// remediation is the derived advice for one target.
type remediation struct {
	risk         string
	affected     []string
	rollback     string
	verify       string
	rollbackNote string
}

// serviceFromPath maps a configuration path onto the service it belongs to.
//
// Returned as a (service, component) pair so the caller can build a reload and a
// verification command for the right unit. An empty service means "no service
// could be confidently identified", which is different from "no service exists".
func serviceFromPath(targetType, p string) (service, component string) {
	base := strings.ToLower(path.Base(p))
	lower := strings.ToLower(p)

	switch {
	// ---- Linux services ---------------------------------------------------
	case strings.HasSuffix(lower, ".service"):
		return base, "systemd"
	case strings.HasSuffix(base, ".conf") && strings.Contains(lower, "nginx"):
		return "nginx", "nginx"
	case strings.Contains(lower, "/nginx/"):
		return "nginx", "nginx"
	case strings.Contains(lower, "/apache2/") || strings.Contains(lower, "/httpd/"):
		return "apache2", "http"
	case strings.Contains(lower, "/haproxy"):
		return "haproxy", "proxy"
	case base == "postgresql.conf" || base == "pg_hba.conf" || strings.Contains(lower, "/postgresql/"):
		return "postgresql", "database"
	case strings.Contains(lower, "my.cnf") || strings.Contains(lower, "/mysql/") || strings.Contains(lower, "/mariadb/"):
		return "mysql", "database"
	case strings.Contains(lower, "/redis/") || base == "redis.conf":
		return "redis", "cache"
	case strings.Contains(lower, "/rabbitmq/"):
		return "rabbitmq", "broker"
	case strings.Contains(lower, "/kafka/"):
		return "kafka", "broker"
	case strings.HasSuffix(base, ".conf") && strings.Contains(lower, "/caddy"):
		return "caddy", "webserver"

	// ---- Identity and audit files ----------------------------------------
	//
	// These have no service to reload, and a "reload" advice would be wrong:
	// their effect depends on the next login or on each daemon's own polling.
	case p == "/etc/passwd", p == "/etc/shadow", p == "/etc/group", p == "/etc/sudoers":
		return "", "identity"
	case strings.HasPrefix(p, "/etc/ssh/"):
		return "sshd", "identity"
	case p == "/etc/sysctl.conf" || strings.HasPrefix(p, "/etc/sysctl.d/"):
		return "", "kernel"

	// ---- Windows ---------------------------------------------------------
	case targetType == "registry":
		return "", "registry"
	case strings.HasSuffix(lower, "web.config") || strings.HasSuffix(lower, "applicationhost.config"):
		return "W3SVC", "iis"
	case strings.HasSuffix(lower, ".xml") && strings.Contains(lower, "iis"):
		return "W3SVC", "iis"

	// ---- Kubernetes ------------------------------------------------------
	//
	// The agent's Kubernetes collector reports `k8s_<resource>` target types, so
	// the component is the resource kind rather than anything filesystem-shaped.
	case strings.HasPrefix(targetType, "k8s_"), targetType == "k8s", targetType == "kubernetes":
		return "", k8sComponent(targetType, p)

	default:
		return "", ""
	}
}

// Component exposes the remediation component classification for a target.
//
// The AI gateway's deterministic fallback needs the same "is this a database,
// an identity file, a ConfigMap?" decision the report's remediation makes, and
// the two must not disagree: a second copy of serviceFromPath would drift, and
// then the risk sentence in the post-mortem and the one an operator reads in
// the console would describe the same change differently. An empty result means
// "not confidently classified", exactly as it does internally.
func Component(targetType, pathOrKey string) string {
	_, component := serviceFromPath(targetType, pathOrKey)
	return component
}

// k8sComponent names the Kubernetes resource class from a target type or key.
func k8sComponent(targetType, pathOrKey string) string {
	kind := strings.TrimPrefix(targetType, "k8s_")
	if kind == targetType {
		// Not a target-type prefix; recover the plural from the agent's key
		// shape: /k8s/<cluster>/<namespace>/<plural>/<name>.
		kind = k8sPluralFromKey(pathOrKey)
	}
	// Singular and plural are both listed rather than derived by trimming a
	// trailing "s": that trim is wrong for "ingress", which is already singular
	// and would become "ingres", silently falling through to "no remediation".
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "configmap", "configmaps":
		return "configmap"
	case "secret", "secrets":
		return "secret"
	case "deployment", "deployments":
		return "deployment"
	case "statefulset", "statefulsets":
		return "statefulset"
	case "ingress", "ingresses":
		return "ingress"
	default:
		return ""
	}
}

// k8sPluralFromKey recovers the resource plural from an agent Kubernetes key.
func k8sPluralFromKey(key string) string {
	parts := strings.Split(strings.TrimPrefix(key, "/"), "/")
	if len(parts) >= 4 && parts[0] == "k8s" {
		return strings.ToLower(parts[3])
	}
	// Fall back to a bare "<Kind>/<namespace>/<name>" form for hand-seeded rows.
	kind, _, _ := strings.Cut(key, "/")
	return strings.ToLower(kind)
}

// k8sKindLabel renders a Kubernetes component name as the resource kind a
// cluster operator would recognise, so the risk sentence reads "Ingress
// /k8s/.../ingresses/checkout" rather than naming an unlabelled workload.
// An unrecognised component returns "Workload", which is honest about the
// classification rather than asserting a kind the derivation did not identify.
func k8sKindLabel(component string) string {
	switch component {
	case "configmap":
		return "ConfigMap"
	case "secret":
		return "Secret"
	case "deployment":
		return "Deployment"
	case "statefulset":
		return "StatefulSet"
	case "ingress":
		return "Ingress"
	default:
		return "Workload"
	}
}

// mirrorPath is the "before" side of a path, for a restore command.
//
// This is deliberately naive — it strips a trailing version/date suffix or
// expects a `.bak` sibling — because the alternative (guessing a backup
// location) produces a command that silently restores nothing. The report
// labels it as a plan, and the notes say where the authoritative copy is.
func mirrorPath(p string) string {
	base := path.Base(p)
	switch {
	case strings.Contains(base, ".bak"):
		return p
	case strings.Contains(base, ".conf") && !strings.Contains(base, ".orig.conf"):
		return strings.TrimSuffix(p, base) + strings.TrimSuffix(base, ".conf") + ".conf.orig"
	}
	return p + ".orig"
}

// RemediationInput is what the derivation needs to produce advice for one
// change. It is a struct rather than a parameter list because it grew past the
// point where a positional call site was readable, and because every field here
// changes the *correct* command: an OS-aware derivation that silently received
// the wrong platform would emit a Windows command for a Linux host.
type RemediationInput struct {
	TargetType string
	PathOrKey  string
	// Action is the rendered verb ("Modified", "Deleted", "Restarted").
	Action string
	// LevelLabel is the rendered severity, folded into the risk sentence.
	LevelLabel string
	// OSFamily is the affected host's platform ("linux", "windows"), used to
	// select the command dialect.
	OSFamily string
	// DiffPresent reports whether a text diff was captured, which distinguishes
	// a configuration change from a forensic metadata-only event.
	DiffPresent bool
	// Cluster is the Kubernetes cluster name for a cluster resource.
	Cluster string
}

// DeriveBlastRadius builds the risk summary and remediation plan for a change.
func DeriveBlastRadius(in RemediationInput) BlastRadius {
	targetType, pathOrKey, action, levelLabel, diffPresent :=
		in.TargetType, in.PathOrKey, in.Action, in.LevelLabel, in.DiffPresent
	service, component := serviceFromPath(targetType, pathOrKey)
	windows := strings.EqualFold(in.OSFamily, "windows")
	out := BlastRadius{}

	// Risk summary: what this class of change can break. Written as prose
	// because it lands in a document read by people who are not going to parse
	// a struct.
	switch component {
	case "nginx", "webserver", "http", "proxy":
		out.RiskSummary = "Editing a web-tier configuration affects request routing and TLS termination. " +
			"A syntax error takes the site down on the next reload, and a bad upstream pool silently " +
			"routes traffic to the wrong backend."
		out.AffectedServices = []string{"Web tier (" + service + ") — inbound HTTP(S) traffic"}
	case "database":
		out.RiskSummary = "Editing a database server's configuration affects connection handling, " +
			"authentication and durability. Connection or authentication parameters require a restart " +
			"rather than a reload, which means a brief outage."
		out.AffectedServices = []string{"Database server (" + service + ") — all dependent applications"}
	case "cache", "broker":
		out.RiskSummary = "Editing a " + component + " configuration affects the message/session path " +
			"between services. A restart to apply it drops in-flight data."
		out.AffectedServices = []string{component + " (" + service + ") — dependent services"}
	case "systemd":
		out.RiskSummary = "Editing a unit file changes how the service starts, restarts and is " +
			"constrained. The change takes effect on the next restart, not immediately, so a mistake " +
			"can stay latent until the next reboot."
		out.AffectedServices = []string{strings.TrimSuffix(path.Base(pathOrKey), ".service")}
	case "identity":
		out.RiskSummary = "This file controls authentication and privilege. A malformed entry can " +
			"lock out interactive access entirely, including the account that would fix it, so the " +
			"change must be verified in a second session before the first is closed."
		out.AffectedServices = []string{"Host authentication and privilege escalation (" + pathOrKey + ")"}
	case "kernel":
		out.RiskSummary = "Kernel parameters affect networking, memory and process limits for every " +
			"process on the host. A value outside the supported range can make a running service " +
			"unable to bind a port or allocate memory."
		out.AffectedServices = []string{"Host kernel (" + pathOrKey + ") — every process"}
	case "registry":
		out.RiskSummary = "A registry change affects the whole host or, under HKLM\\Software, every " +
			"user on it. Some values only take effect on the next service restart or reboot, which can " +
			"delay the damage until a maintenance window."
		out.AffectedServices = []string{"Windows registry (" + pathOrKey + ")"}
	case "iis":
		out.RiskSummary = "Editing site configuration affects every binding defined in it. An invalid " +
			"`applicationHost.config` prevents the IIS service from starting at all, not just the " +
			"affected site."
		out.AffectedServices = []string{"IIS (" + service + ") — all hosted sites"}
	case "configmap", "secret":
		out.RiskSummary = "Changing a ConfigMap or Secret affects every workload that mounts it. " +
			"Consumers do not pick up the change until their pods restart, so a broken value can " +
			"present as an intermittent failure across several deployments rather than one clean break."
		out.AffectedServices = []string{"Workloads mounting " + k8sKindLabel(component) + " " + pathOrKey}
	case "deployment", "statefulset":
		out.RiskSummary = "Editing a workload spec triggers a rollout. A bad image, probe or resource " +
			"limit will take every replica down together if the strategy is Recreate, and can wedge a " +
			"rolling update mid-way if the new pods never become ready."
		out.AffectedServices = []string{k8sKindLabel(component) + " " + pathOrKey}
	case "ingress":
		out.RiskSummary = "Editing an Ingress changes external routing. A bad rule removes a public " +
			"endpoint from service while the backend pods stay perfectly healthy, so it reads as an " +
			"application outage rather than a network one."
		out.AffectedServices = []string{k8sKindLabel(component) + " " + pathOrKey}
	default:
		out.RiskSummary = "The blast radius of this target could not be determined from its path. " +
			"Review the diff and the host's role before acting."
	}

	if levelLabel != "" {
		out.RiskSummary += " Classified " + levelLabel + "."
	}

	// ---- Remediation -----------------------------------------------------
	//
	// A command is offered only where the target type makes the correct one
	// unambiguous. Everything else is left to the note below.
	//
	// The platform gate comes first: a Windows host must never receive a
	// `systemctl` command, and a Linux host must never receive a PowerShell one.
	// The generic service branch below is therefore Linux-only, and Windows
	// hosts fall through to the registry/IIS branches or to the note.
	switch {
	case windows && component != "registry" && component != "iis" && service != "":
		out.RollbackCommand = "# restore the previous revision of " + pathOrKey + " from your configuration management, then:\n" +
			"Restart-Service -Name '" + service + "' -Force"
		out.VerifyCommand = "Get-Service -Name '" + service + "' | Select-Object Name,Status,StartType"

	case component == "registry":
		out.RollbackNotes = "Registry values have no generic rollback. Restore the previous value " +
			"from the host's configuration management (Group Policy, DSC or Intune) and re-check " +
			"the effective value under the same 32/64-bit view that the application reads."
		out.VerifyCommand = "Get-ItemProperty -Path '" + registryParent(pathOrKey) + "'"

	case component == "iis":
		out.RollbackCommand = "Restore-WebConfiguration -Name 'applicationHost' -Path 'C:\\backup\\applicationHost.config'; iisreset /restart"
		out.VerifyCommand = "& $env:SystemRoot\\System32\\inetsrv\\appcmd.exe list sites"
		out.RollbackNotes = "Restoring applicationHost.config rolls back every site in the hierarchy, " +
			"not only the one edit under investigation. Scope the restore to the single site if other " +
			"changes are in flight."

	case component == "identity":
		if strings.Contains(pathOrKey, "ssh") {
			out.RollbackCommand = "# restore the previous sshd_config from your configuration management\n" +
				"sshd -t && systemctl reload sshd"
			out.VerifyCommand = "sshd -T | head -40"
			out.RollbackNotes = "Keep the current session open until a second session authenticates " +
				"successfully. `sshd -t` validates the file without applying it, which is the cheap check."
		} else {
			out.VerifyCommand = "getent passwd && getent group && sudo -l -U root"
			out.RollbackNotes = "There is no safe generic rollback for an identity file. Restore the " +
				"previous revision from a backup and verify interactive login in a second session before " +
				"closing the first — a bad /etc/shadow or /etc/sudoers can lock out all administrative access."
		}

	case component == "kernel":
		out.RollbackCommand = "# restore the previous value from your configuration management, then:\nsysctl -p"
		out.VerifyCommand = "sysctl -a | grep -F '<key from the diff>'"
		out.RollbackNotes = "sysctl -p re-reads /etc/sysctl.conf; values set per-parameter with `sysctl -w` " +
			"revert on reboot, so a change made that way can disappear as silently as it arrived."

	case component == "configmap" || component == "secret":
		out.RollbackCommand = "# roll the resource back to its previous revision\nkubectl rollout undo deployment/<workload> -n <namespace>"
		out.VerifyCommand = "kubectl get " + component + " -A -o yaml | grep -A2 -F '" + path.Base(pathOrKey) + "'"
		out.RollbackNotes = "A direct ConfigMap/Secret edit is not captured by `kubectl rollout history`: " +
			"undo only helps if the resource is managed by the referencing Deployment. Otherwise re-apply the " +
			"previous manifest from Git and restart the consuming workloads so they pick the value up."

	case component == "deployment" || component == "statefulset":
		out.RollbackCommand = "kubectl rollout undo " + component + "/" + path.Base(pathOrKey) + " -n <namespace>"
		out.VerifyCommand = "kubectl rollout status " + component + "/" + path.Base(pathOrKey) + " -n <namespace>"
		out.RollbackNotes = "`rollout undo` restores the immediately previous revision. If the resource " +
			"was applied outside the cluster's revision history (a direct edit), re-apply the previous " +
			"manifest from Git instead."

	case component == "ingress":
		// An Ingress has no rollout history, so `rollout undo` — which does not
		// accept Ingress at all — must not be offered here. The only reliable
		// rollback is re-applying the previous manifest.
		out.RollbackCommand = "# re-apply the previous revision of the Ingress manifest from Git\n" +
			"kubectl apply -f ingress-" + path.Base(pathOrKey) + ".yaml -n <namespace>"
		out.VerifyCommand = "kubectl get ingress " + path.Base(pathOrKey) + " -n <namespace> -o yaml | grep -A5 -F 'rules:'"
		out.RollbackNotes = "Ingress objects carry no revision history, so `kubectl rollout undo` is not " +
			"available for them. Re-apply the previous manifest and confirm the load balancer has " +
			"reprogrammed before declaring the endpoint restored."

	case service != "" && !windows:
		// A service-backed configuration file: there is a previous revision in
		// configuration management, and a reload to apply it. The command
		// validates before reloading, because a reload with a syntax error takes
		// the service down — which is the exact failure an incident report is
		// trying to stop an operator from repeating.
		mirror := mirrorPath(pathOrKey)
		out.RollbackCommand = "# restore the previous revision of " + pathOrKey + "\n" +
			"cp -a " + shellQuote(mirror) + " " + shellQuote(pathOrKey) + "\n" +
			serviceReload(service)
		out.VerifyCommand = serviceVerify(service)
		out.RollbackNotes = "The reload command above validates before it applies for services that " +
			"support it (`nginx -t`, `apachectl configtest`, `haproxy -c`). " + mirror + " is the " +
			"conventional backup path; if your configuration management keeps revisions elsewhere, " +
			"substitute that path."
	}

	if action == "Deleted" && servicelike(out.RollbackCommand) {
		out.RollbackNotes = "The target was deleted rather than modified, so the restore command must " +
			"come from a backup or from configuration management — there is no previous on-disk revision " +
			"to copy. " + out.RollbackNotes
	}

	// A restarted service with no diff is a forensic signal, not a config
	// change: say what to look at rather than proposing a rollback.
	if action == "Restarted" && !diffPresent {
		out.RollbackNotes = "This was a service restart with no configuration diff, so there is nothing " +
			"to roll back. Correlate the restart against the changes immediately preceding it — a restart " +
			"is usually the moment a latent change became visible."
	}

	return out
}

// registryParent strips the final value name from a registry key so
// `Get-ItemProperty` reads the value's container rather than the value itself
// (which would error: PowerShell reads properties, not values).
//
// It only strips when there is a container left to point at. A key of
// `HKLM\Software` has no parent beyond the hive root, and truncating it to
// `HKLM` would silently inspect the wrong scope — so short paths are returned
// unchanged, which makes `Get-ItemProperty -Path 'HKLM\Software'` read exactly
// what the report said it would.
func registryParent(key string) string {
	key = strings.TrimSpace(key)
	parts := strings.Split(key, `\`)
	if len(parts) < 3 {
		return key
	}
	return strings.Join(parts[:len(parts)-1], `\`)
}

// serviceReload renders the validation-and-reload command pair for a service.
func serviceReload(service string) string {
	switch service {
	case "nginx":
		return "nginx -t && systemctl reload nginx"
	case "apache2", "httpd":
		return "apachectl configtest && systemctl reload apache2"
	case "haproxy":
		return "haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy"
	case "caddy":
		return "caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy"
	case "postgresql":
		return "systemctl reload postgresql"
	case "mysql", "mariadb":
		return "systemctl reload mysql"
	case "redis":
		return "redis-cli CONFIG REWRITE && systemctl reload redis"
	default:
		return "systemctl reload " + service
	}
}

// serviceVerify renders a service-health check an operator can run after a
// rollback to prove the host is back.
func serviceVerify(service string) string {
	switch service {
	case "nginx":
		return "systemctl is-active nginx && curl -sS -o /dev/null -w '%{http_code}\\n' http://127.0.0.1/"
	case "apache2", "httpd":
		return "systemctl is-active apache2 && curl -sS -o /dev/null -w '%{http_code}\\n' http://127.0.0.1/"
	case "haproxy":
		return "systemctl is-active haproxy && echo 'show stat' | socat stdio /var/run/haproxy.sock | head -20"
	case "postgresql":
		return "systemctl is-active postgresql && pg_isready"
	case "mysql", "mariadb":
		return "systemctl is-active mysql && mysqladmin ping"
	case "redis":
		return "systemctl is-active redis && redis-cli ping"
	case "rabbitmq":
		return "systemctl is-active rabbitmq-server && rabbitmq-diagnostics -q ping"
	default:
		return "systemctl is-active " + service
	}
}

// servicelike reports whether a rendered command is a rollback of an existing
// file (as opposed to a note or an empty string).
func servicelike(cmd string) bool {
	return cmd != "" && strings.Contains(cmd, "cp -a")
}

// shellQuote single-quotes a value for shell use, so a path with spaces (or a
// hostname from the events table, which is attacker-influenced data in a
// multi-tenant deployment) cannot break out of the command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
