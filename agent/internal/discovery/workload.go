// Package discovery is the agent's lightweight, non-blocking workload
// scanner. It runs once at startup and then every six hours, probing for
// production workloads a host is running (IIS sites, nginx/apache vhosts,
// database instances, container runtimes) so the console can recommend
// onboarding them with a granular policy rule.
//
// Probes only read configuration files and process tables: they never modify
// host state, never block the collection pipeline, and every filesystem
// failure is treated as "not found" rather than an error.
package discovery

import (
	"strings"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// Workload type identifiers reported in DiscoveredWorkload.Type. These are the
// stable strings the console renders, so a catalog entry's category maps onto
// one of them.
const (
	TypeIISSite       = "iis_site"
	TypeNginxVHost    = "nginx_vhost"
	TypeApacheVHost   = "apache_vhost"
	TypeCaddySite     = "caddy_site"
	TypeHAProxy       = "haproxy"
	TypeMSSQLInstance = "mssql_instance"
	TypePostgresDB    = "postgres_db"
	TypeMySQLInstance = "mysql_instance"
	TypeRedis         = "redis"
	TypeRabbitMQ      = "rabbitmq"
	TypeKafka         = "kafka"
	TypeSSHD          = "sshd"
	TypeSystemFile    = "system_file"
	TypeSystemdUnit   = "systemd_unit"
	TypeSysctl        = "sysctl"
	TypeDocker        = "docker"
	TypeCompose       = "compose_project"
	TypeDockerVolume  = "docker_volume"
	TypeWindowsReg    = "windows_registry"
	TypeWindowsSvc    = "windows_service"
	TypeScheduledTask = "scheduled_task"
	TypeMSMQ          = "msmq"
	TypeK8sConfigMap  = "k8s_configmap"
	TypeK8sSecret     = "k8s_secret"
	TypeK8sDeployment = "k8s_deployment"
	TypeK8sStateful   = "k8s_statefulset"
	TypeK8sIngress    = "k8s_ingress"
)

// Suggested impact levels (mirrors pb.ImpactLevel).
const (
	LevelCritical = 1
	LevelGrouped  = 2
	LevelDrift    = 3
	LevelForensic = 4
)

// DiscoveredWorkload is a production workload the agent found on the host.
// It is the domain representation of pb.DiscoveredWorkload; the transport
// layer converts before sending it on a heartbeat.
type DiscoveredWorkload struct {
	// Type is one of the Type* constants.
	Type string
	// Name is a human-friendly instance name, e.g. "Default Web Site",
	// "CheckoutApp" or "MSSQL$PROD".
	Name string
	// ConfigPath is the config root or primary config file (the file the
	// agent would diff), e.g. "C:\inetpub\wwwroot\checkout\web.config".
	ConfigPath string
	// SuggestedLevel is the impact level the console should pre-select.
	SuggestedLevel int
	// SuggestedDiff enables text-diff capture for the workload's config.
	SuggestedDiff bool
	// Reason explains the suggested level in one sentence.
	Reason string
	// EntryID is the catalog entry that produced this workload. It is carried
	// so the console can group discoveries by application and so a support
	// engineer can trace a recommendation back to the knowledge base.
	EntryID string
	// Application is the catalog entry's human name ("Nginx", "IIS").
	Application string
	// Runtime is the environment the workload was found in (linux, windows,
	// docker, kubernetes).
	Runtime string
	// Namespace is set for Kubernetes workloads.
	Namespace string
	// Meta carries extra, low-cardinality facts (vendor, parser, matched
	// signal). It is reported as event metadata, never as a decision input.
	Meta map[string]string
}

// Key is a stable identity for de-duplicating and diffing scan results. It
// includes the namespace so a ConfigMap named "app-config" in two namespaces
// stays two distinct recommendations.
func (w DiscoveredWorkload) Key() string {
	return w.Type + "\x00" + w.Namespace + "\x00" + w.Name + "\x00" + w.ConfigPath
}

// displayType maps a catalog entry id onto the stable workload-type string the
// console renders. An unrecognised entry keeps its own id so a catalog extended
// in the field still produces a labelled recommendation instead of a blank.
func displayType(entryID string) string {
	if t, ok := entryTypeIDs[entryID]; ok {
		return t
	}
	return entryID
}

// EntryIDForType is the inverse of displayType: it maps a workload-type string
// (the value the console and the recommendations table speak) back onto the
// catalog entry that produces it. The Kubernetes collector uses it to resolve
// the profile and staging namespaces for the resource kind it is watching.
func EntryIDForType(workloadType string) (string, bool) {
	if id, ok := typeEntryIDs[workloadType]; ok {
		return id, true
	}
	// An entry with no mapping uses its own id as the type.
	if _, ok := MustCatalog().Entry(workloadType); ok {
		return workloadType, true
	}
	return "", false
}

// WorkloadTypeForEntry maps a catalog entry id onto the workload-type string
// the console renders. Its second result is false when the id is unknown to
// this build's catalog, so a caller can skip rather than emit a blank type.
func WorkloadTypeForEntry(entryID string) (string, bool) {
	if _, ok := entryTypeIDs[entryID]; ok {
		return displayType(entryID), true
	}
	if _, ok := MustCatalog().Entry(entryID); ok {
		return displayType(entryID), true
	}
	return "", false
}

var entryTypeIDs = map[string]string{
	"nginx":                   TypeNginxVHost,
	"apache":                  TypeApacheVHost,
	"caddy":                   TypeCaddySite,
	"haproxy":                 TypeHAProxy,
	"postgresql":              TypePostgresDB,
	"mysql":                   TypeMySQLInstance,
	"redis":                   TypeRedis,
	"rabbitmq":                TypeRabbitMQ,
	"kafka":                   TypeKafka,
	"sshd":                    TypeSSHD,
	"etc_passwd":              TypeSystemFile,
	"etc_shadow":              TypeSystemFile,
	"sudoers":                 TypeSystemFile,
	"systemd_units":           TypeSystemdUnit,
	"sysctl":                  TypeSysctl,
	"docker_daemon":           TypeDocker,
	"docker_compose":          TypeCompose,
	"docker_volumes":          TypeDockerVolume,
	"iis":                     TypeIISSite,
	"mssql":                   TypeMSSQLInstance,
	"rabbitmq_windows":        TypeRabbitMQ,
	"msmq":                    TypeMSMQ,
	"hklm_software":           TypeWindowsReg,
	"windows_services":        TypeWindowsSvc,
	"windows_scheduled_tasks": TypeScheduledTask,
	"windows_sshd":            TypeSSHD,
	"windows_hosts":           TypeSystemFile,
	"k8s_configmap":           TypeK8sConfigMap,
	"k8s_secret":              TypeK8sSecret,
	"k8s_deployment":          TypeK8sDeployment,
	"k8s_statefulset":         TypeK8sStateful,
	"k8s_ingress":             TypeK8sIngress,
}

var typeEntryIDs = invertEntryTypeIDs()

// invertEntryTypeIDs builds the workload-type -> entry-id index from
// entryTypeIDs. Built once at init so the two directions cannot drift.
func invertEntryTypeIDs() map[string]string {
	out := make(map[string]string, len(entryTypeIDs))
	for id, t := range entryTypeIDs {
		// First entry wins for a shared type (etc_passwd/etc_shadow/sudoers all
		// map to system_file); the profile is the same for all of them.
		if _, seen := out[t]; !seen {
			out[t] = id
		}
	}
	return out
}

// levelName renders a level for log/debug output.
func levelName(level int) string {
	switch level {
	case LevelCritical:
		return "critical"
	case LevelGrouped:
		return "grouped"
	case LevelDrift:
		return "drift"
	case LevelForensic:
		return "forensic"
	}
	return "unspecified"
}

// ToPB converts a scan result to the wire format. The order of the input is
// preserved and the output is never nil so it serialises as an absent repeated
// field rather than a JSON null.
func ToPB(ws []DiscoveredWorkload) []*pb.DiscoveredWorkload {
	out := make([]*pb.DiscoveredWorkload, 0, len(ws))
	for _, w := range ws {
		out = append(out, &pb.DiscoveredWorkload{
			Type:           w.Type,
			Name:           w.Name,
			ConfigPath:     w.ConfigPath,
			SuggestedLevel: int32(w.SuggestedLevel),
			SuggestedDiff:  w.SuggestedDiff,
			Reason:         w.Reason,
			EntryId:        w.EntryID,
			Application:    w.Application,
			Runtime:        w.Runtime,
			Namespace:      w.Namespace,
		})
	}
	return out
}

// Dedupe removes duplicate workloads (same type/name/config path), keeping the
// first occurrence, and drops entries with no name or type.
func Dedupe(ws []DiscoveredWorkload) []DiscoveredWorkload {
	seen := make(map[string]bool, len(ws))
	out := make([]DiscoveredWorkload, 0, len(ws))
	for _, w := range ws {
		if w.Type == "" || w.Name == "" {
			continue
		}
		k := w.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, w)
	}
	return out
}

// stagingName reports whether the workload name looks like a non-production
// environment, which downgrades the suggestion to Drift.
func stagingName(name string) bool {
	n := strings.ToLower(name)
	for _, marker := range []string{"stag", "dev", "test", "qa", "uat", "sandbox", "preprod", "pre-prod", "local"} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

// productionName reports whether the workload name looks production-facing.
func productionName(name string) bool {
	n := strings.ToLower(name)
	for _, marker := range []string{"prod", "live", "www", "checkout", "payment", "api"} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}
