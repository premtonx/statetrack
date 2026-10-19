// Shared types mirroring the server's REST + WebSocket payloads.
// See server/internal/storage/store.go and server/internal/api.

export type ImpactLevel = 1 | 2 | 3 | 4

export type Category =
  | 'config'
  | 'package'
  | 'service'
  | 'user'
  | 'registry'
  | 'network'
  | 'process'
  | 'agent_health'
  | 'unspecified'

export type Action =
  | 'created'
  | 'modified'
  | 'deleted'
  | 'restarted'
  | 'started'
  | 'stopped'
  | 'upgraded'
  | 'throttled'
  | 'unspecified'

export interface Host {
  id: string
  hostname: string
  os_family: string
  os_version: string
  agent_version: string
  clock_offset_ms: number
  forensic_until?: string | null
  last_seen_at: string
  status: string
}

export interface Event {
  id: string
  host_id: string
  hostname?: string
  parent_event_id?: string
  occurred_at: string
  impact_level: number
  category: number
  action: number
  summary: string
  target_type: string
  path_or_key: string
  actor_username?: string
  actor_sid?: string
  login_uid?: string
  process_name?: string
  process_lineage?: string[]
  remote_ip?: string
  pid?: number
  ppid?: number
  cmdline?: string
  hash_before?: string
  hash_after?: string
  version_before?: string
  version_after?: string
  child_count: number
  has_diff: boolean
  diff_source?: 'inline' | 's3' | ''
  metadata?: Record<string, string>
  /**
   * Change-control verdict, populated only when the feed asked the API to
   * annotate (`?annotate=compliance`, which the timeline sets). Optional rather
   * than always-present so a page that did not ask cannot be read as "no ticket
   * required" when the truth is "not evaluated".
   */
  compliance?: Compliance
  compliance_reason?: string
  ticket_ref?: string
  ticket_status?: string
  /**
   * Optional diff line counts. The backend does not store these as columns
   * today; they are parsed from the summary (`+12 -3`) when present and can be
   * supplied directly by fallback/aggregate data sources.
   */
  lines_added?: number
  lines_removed?: number
  file_size_before?: number
  file_size_after?: number
}

export interface EventDetail extends Event {
  diff?: string
  children?: Event[]
}

export interface DriftRow {
  target_id: number
  target_type: string
  path_or_key: string
  hash_a: string
  version_a: string
  hash_b: string
  version_b: string
  only_on?: 'a' | 'b' | ''
}

// The WebSocket "event" envelope carries a Notification (a subset of Event).
export interface LiveEvent {
  id: string
  host_id: string
  hostname?: string
  parent_event_id?: string
  occurred_at: string
  impact_level: number
  category: number
  action: number
  summary: string
  actor?: string
  target_type?: string
  path_or_key?: string
  /** Agent classification, incl. metadata.rule_name when a policy rule matched. */
  metadata?: Record<string, string>
}

export interface EventsPage {
  events: Event[]
  next_cursor: string
}

/**
 * A workload the agent's discovery engine found on a host but which has no
 * granular policy rule yet. Mirrors `storage.Recommendation` in
 * server/internal/storage/recommendations.go.
 */
export interface Recommendation {
  id: string
  host_id: string
  hostname?: string
  /** Discovery source, e.g. "iis_site", "nginx_vhost", "redis", "docker". */
  workload_type: string
  name: string
  config_path: string
  suggested_level: number
  suggested_diff: boolean
  reason: string
  status: 'pending' | 'applied' | 'dismissed' | string
  created_at: string
  updated_at: string
}

/** A host's active granular policy rule (storage.PolicyRuleRow). */
export interface PolicyRule {
  id: string
  name: string
  target_type: string
  pattern: string
  level: number
  diff: boolean
  tags: string[]
  created_at: string
}

export interface RecommendationsResponse {
  recommendations: Recommendation[]
  pending: number
  by_host: Record<string, number>
}

export interface ApplyAllResponse {
  status: string
  applied: number
  rules: PolicyRule[]
}

export type RecommendationStatusFilter = 'pending' | 'applied' | 'dismissed' | 'all'

/* -------------------------------------------------------------------------- */
/* Custom watched targets (the console's rule builder)                        */
/* -------------------------------------------------------------------------- */

/**
 * One custom watched target, mirroring `storage.WatchRule` on the server.
 *
 * A watched target is a policy rule with a scope: the same row classifies the
 * event and tells the surgical watcher what to poll, which is why `pattern` is
 * the identifier a collector understands (`iis://apppool/...`, `db://...`).
 */
export interface WatchRule {
  id: string
  /** Empty for a fleet-wide rule. */
  host_id: string
  hostname?: string
  /** The selector the builder chose: a hostname, a host id, or "*". */
  host_scope: string
  name: string
  target_type: string
  pattern: string
  level: number
  diff: boolean
  tags: string[]
  created_by: string
  created_at: string
  /** Server-rendered display name of the target type ("IIS App Pool"). */
  target_label: string
  /** Server-rendered display name of the level ("Level 1 Critical"). */
  impact_label: string
  /** Server-rendered capture phrase ("Full diff" / "Hash only"). */
  diff_mode: string
}

/** One option in the builder's Target Type dropdown, served by the API. */
export interface WatchTargetType {
  value: string
  label: string
  placeholder: string
  help: string
  /** Present when the target only works on one platform ("windows"). */
  platforms?: string[]
}

/** One option in the builder's Impact Level choice. */
export interface WatchImpactLevel {
  value: number
  label: string
  help: string
  diff: boolean
}

/** The watched-target list plus the builder's catalog. */
export interface WatchRulesResponse {
  rules: WatchRule[]
  count: number
  critical: number
  by_type: Record<string, number>
  by_host: Record<string, number>
  target_types: WatchTargetType[]
  impact_levels: WatchImpactLevel[]
  default_level: number
}

/** The payload the builder submits. */
export interface WatchRuleInput {
  host_scope: string
  target_type: string
  pattern: string
  level: number
  diff?: boolean
  name?: string
}

/** Fleet-wide scope sentinel; mirrors `storage.FleetScope`. */
export const FLEET_SCOPE = '*'

export interface EventFilters {
  host_id?: string
  impact_level?: ImpactLevel | 0
  category?: number
  actor?: string
  search?: string
  from?: string
  to?: string
  cursor?: string
  limit?: number
  /**
   * Exclude child events. Root-level feeds (dashboard "latest changes",
   * Grafana annotations) set this so an aggregated transaction's children
   * cannot consume the page and hide other root changes. The timeline leaves
   * it unset because expanded parent cards render their children inline.
   */
  root_only?: boolean
  /**
   * Ask the API to attach each event's change-control verdict. Opt-in because
   * the correlation costs two extra reads per page (the ITSM settings and the
   * whole ticket set), which the dashboard feed and the Grafana data source
   * have no use for. Only the timeline sets it, so its rows can badge
   * unauthorised production edits inline.
   */
  annotate?: 'compliance'
}

/* -------------------------------------------------------------------------- */
/* Integrations (Grafana, outbound notifications)                              */
/* -------------------------------------------------------------------------- */

/**
 * Grafana integration settings, mirroring `storage.GrafanaSettings` on the
 * server. The API accepts a partial update, so every field is optional when
 * saving.
 */
export interface GrafanaSettings {
  url: string
  api_token: string
  org: string
  push_l1: boolean
  push_l2: boolean
  push_l3: boolean
  /** Annotation text template; supports {{summary}}, {{actor}}, {{hostname}}, {{level}}, {{category}}, {{path}}. */
  template: string
  /** Dashboards the operator marked as receiving these annotations. */
  dashboards: string[]
  /** Gates live dispatch without discarding the configuration. */
  enabled: boolean
  last_test_at?: string
  last_test_ok: boolean
  last_test_error?: string
}

export type GrafanaSettingsUpdate = Partial<
  Pick<
    GrafanaSettings,
    'url' | 'api_token' | 'org' | 'push_l1' | 'push_l2' | 'push_l3' | 'template' | 'dashboards' | 'enabled'
  >
>

/** One dispatched annotation, from the server's dispatch log. */
export interface GrafanaAnnotation {
  id: string
  event_id?: string
  hostname: string
  impact_level: string
  impact_number: number
  summary: string
  text: string
  tags: string[]
  dashboard?: string
  status: 'delivered' | 'failed' | 'skipped' | string
  error?: string
  time: string
  time_ms: number
  /** Opens the Monaco diff drawer for the change this annotation describes. */
  deep_link?: string
}

export interface GrafanaResponse extends GrafanaSettings {
  recent_annotations: GrafanaAnnotation[]
  grafana_reachable: boolean
}

export interface GrafanaTestResponse {
  ok: boolean
  url: string
  detail: string
  version?: string
  checked_at: string
}

export type WebhookProvider = 'webhook' | 'slack' | 'pagerduty' | 'teams'

export interface WebhookTestRequest {
  provider: WebhookProvider
  url: string
  /** HMAC signing key (generic webhook) or PagerDuty routing key. */
  secret?: string
  /** `storm` sends a change-storm sample instead of a Level 1 mutation. */
  sample?: 'mutation' | 'storm'
}

export interface WebhookTestResponse {
  ok: boolean
  provider: string
  status: number
  attempts: number
  detail: string
  /** The exact JSON body that was delivered, for inspection. */
  rendered?: string
  /** The HMAC that was sent, so a receiver's author can compare. */
  signature?: string
  tested_at: string
  /** Wall-clock delivery time, matching the row in the delivery log. */
  latency_ms?: number
}

/**
 * One outbound notification channel, mirroring `storage.WebhookChannel`.
 * The secret is never returned: `token` is always empty from the API and
 * `token_set` reports whether one is stored, so the form can show "configured"
 * without ever holding the value.
 */
export interface WebhookChannel {
  provider: WebhookProvider
  url: string
  token: string
  /** Slack's channel label, or a human note. */
  label: string
  /** PagerDuty severity override; empty derives it from the impact level. */
  severity: string
  notify_l1: boolean
  notify_storms: boolean
  enabled: boolean
  token_set: boolean
  updated_at?: string
  /** Newest delivery attempt for this provider, when any exists. */
  last_delivery?: WebhookDelivery
}

/** One row of the outbound delivery log. */
export interface WebhookDelivery {
  id: number
  provider: string
  endpoint?: string
  event_id?: string
  status_code: number
  latency_ms: number
  success: boolean
  attempts: number
  /** True when the row came from a console "Send Test", not a real change. */
  sample: boolean
  error?: string
  created_at: string
}

export interface WebhookIntegrationsResponse {
  channels: WebhookChannel[]
  recent_deliveries: WebhookDelivery[]
}

/** Partial update for one provider's card. Omitted fields keep their value. */
export interface WebhookChannelUpdate {
  provider: WebhookProvider
  url?: string
  token?: string
  label?: string
  severity?: string
  notify_l1?: boolean
  notify_storms?: boolean
  enabled?: boolean
}

/** The unified poller rollup served to Checkmk/Zabbix, rendered in the hub. */
export interface HostSummary {
  host: string
  os: string
  online: boolean
  last_seen_seconds: number
  window: string
  counts: {
    total: number
    l1_critical: number
    l2_grouped: number
    l3_drift: number
    l4_forensic: number
  }
  drift_targets_count: number
  latest_critical: {
    id: string
    occurred_at: string
    target: string
    actor?: string
    tool?: string
    summary: string
    rule_name?: string
    deep_link?: string
  } | null
}

/* -------------------------------------------------------------------------- */
/* Identity, RBAC and enterprise security                                     */
/* -------------------------------------------------------------------------- */

/**
 * RBAC grant. The values match the server's `users.role` CHECK constraint, so a
 * role that cannot be stored cannot be selected here either.
 */
export type Role = 'admin' | 'operator' | 'policy_admin' | 'auditor'

/** Roles the demo switcher offers, in display order. */
export const ROLE_OPTIONS: { id: Role; label: string; description: string }[] = [
  {
    id: 'admin',
    label: 'Administrator',
    description: 'Full access to every console setting and configuration.',
  },
  {
    id: 'operator',
    label: 'SRE Operator',
    description: 'Applies rules and policies; cannot change security or SSO settings.',
  },
  {
    id: 'auditor',
    label: 'Compliance Auditor (Read-Only)',
    description: 'Read-only. Every mutating action is blocked by the server.',
  },
]

/** The signed-in principal, as reported by `GET /api/v1/auth/me`. */
export interface AuthUser {
  id: string
  email: string
  name: string
  initials: string
  role: Role
  role_label: string
  totp_enabled: boolean
  auth_provider: string
  /** Absent when the account has never signed in. */
  last_login_at?: string
  /** Computed server-side: the same predicate the API enforces on writes. */
  can_write: boolean
}

/** The non-secret slice of the org's SSO posture. */
export interface SSOSummary {
  provider: SSOProvider
  enabled: boolean
  /** When true, local password sign-in is disabled for the org. */
  require_sso: boolean
  enforced_domain?: string
}

export interface AuthMeResponse {
  authenticated: boolean
  user: AuthUser
  /** The granted role. Differs from `user.role` while demo-acting as a lesser role. */
  real_role?: Role
  real_role_label?: string
  /** Populated for API-key principals. */
  scopes?: string[]
  auth_method: string
  read_only: boolean
  sso: SSOSummary
  /** True when the role switcher is meaningful (demo deployments). */
  demo_mode: boolean
  /** True when the session was established automatically rather than by sign-in. */
  dev_autologin: boolean
}

export type SSOProvider = 'microsoft_entra' | 'okta' | 'google_workspace' | 'custom_oidc'

/**
 * Build and runtime posture reported by `GET /api/v1/system`.
 *
 * The console cannot know which binary is serving it (a bundle built into a
 * container has no build stamp of its own), so the version and build date come
 * from the server rather than from a constant in TypeScript.
 */
export interface SystemInfo {
  version: string
  commit?: string
  build_date?: string
  go_version: string
  platform: string
  uptime_sec: number
  demo_mode: boolean
  embedded_ui: boolean
  auth_disabled: boolean
  /** "s3" when large diffs are offloaded, "inline" otherwise. */
  storage: string
  database: string
}

export const SSO_PROVIDERS: { id: SSOProvider; label: string; issuerHint: string }[] = [
  {
    id: 'microsoft_entra',
    label: 'Microsoft Entra ID',
    issuerHint: 'https://login.microsoftonline.com/<tenant-id>/v2.0',
  },
  { id: 'okta', label: 'Okta', issuerHint: 'https://<your-org>.okta.com' },
  {
    id: 'google_workspace',
    label: 'Google Workspace',
    issuerHint: 'https://accounts.google.com',
  },
  { id: 'custom_oidc', label: 'Custom OIDC', issuerHint: 'https://idp.example.com/.well-known/openid-configuration' },
]

export interface SSOConfig {
  provider: SSOProvider
  issuer_url: string
  client_id: string
  /** Present only on write; the server never returns the stored secret. */
  client_secret?: string
  /** True when a secret is stored, so the form can render "configured". */
  client_secret_set: boolean
  enforced_domain: string
  auto_provision_role: Role
  require_sso: boolean
  enabled: boolean
  updated_at?: string
}

export type SSOConfigUpdate = Partial<
  Pick<
    SSOConfig,
    | 'provider'
    | 'issuer_url'
    | 'client_id'
    | 'client_secret'
    | 'enforced_domain'
    | 'auto_provision_role'
    | 'require_sso'
    | 'enabled'
  >
>

/** One scoped machine credential. Never carries the secret. */
export interface APIKey {
  id: string
  name: string
  /** Display-only identifier, e.g. `st_live_8f9a`. */
  key_prefix: string
  role: Role
  scopes: string[]
  active: boolean
  last_used_at?: string
  expires_at?: string
  /** Human remaining lifetime, e.g. "in 180 days". */
  expires_in?: string
  revoked_at?: string
  created_at: string
}

export interface APIKeysResponse {
  api_keys: APIKey[]
  /** The server's scope vocabulary, so the form cannot offer an unknown scope. */
  scopes: string[]
}

export interface CreateAPIKeyRequest {
  name: string
  role: Role
  scopes: string[]
  /** 0 means "never expires". */
  expires_in_days: number
}

/** The one-time create response: `token` is the only time the secret exists. */
export interface CreateAPIKeyResponse {
  token: string
  key_prefix: string
  api_key: APIKey
  warning: string
}

/** One agent bootstrap token. The secret is never returned after creation. */
export interface EnrollmentToken {
  id: string
  name: string
  /** Display-only identifier, e.g. `st_enroll_pr0d`. */
  token_prefix: string
  max_uses?: number
  uses_count: number
  active: boolean
  expires_at?: string
  revoked_at?: string
  created_at: string
  bootstrap_url: string
  /** In a list, the token inside these commands is redacted. */
  linux_command: string
  windows_command: string
}

export interface EnrollmentTokensResponse {
  enrollment_tokens: EnrollmentToken[]
}

export interface CreateEnrollmentTokenRequest {
  name: string
  /** 0 means unlimited. */
  max_uses: number
  expires_in_days: number
}

export interface CreateEnrollmentTokenResponse {
  token: string
  token_prefix: string
  enrollment_token: EnrollmentToken
  warning: string
}

/**
 * One entry in the append-only control-plane audit trail. `details` is free-form
 * JSONB, so it is typed loosely and read defensively in the UI.
 */
export interface AuditLogEntry {
  id: number
  occurred_at: string
  actor_email: string
  actor_role: string
  action: string
  target: string
  source_ip: string
  details: Record<string, unknown>
}

export interface AuditLogsResponse {
  audit_logs: AuditLogEntry[]
  count: number
  /** The server's action vocabulary, used to populate the filter dropdown. */
  actions: string[]
}

/** TOTP enrollment payload returned by `POST /api/v1/auth/totp/setup`. */
export interface TOTPSetupResponse {
  secret: string
  /** The `otpauth://` URI the console renders as a QR code. */
  otpauth_uri: string
  issuer: string
  algorithm: string
  digits: number
  period: number
}

export interface TOTPVerifyResponse {
  totp_enabled: boolean
  status: string
}

/* -------------------------------------------------------------------------- */
/* Incident post-mortem ("War Room Export")                                   */
/* -------------------------------------------------------------------------- */

/**
 * The change-control verdict attached to an incident, mirroring
 * `itsm.Compliance` on the server. The set is closed: a verdict the console
 * cannot render is a verdict an auditor cannot act on.
 */
export type Compliance = 'approved' | 'unapproved' | 'expired' | 'not_required'

/** One incident post-mortem bundle, from `GET /api/v1/events/{id}/post-mortem`.
 *
 * Mirrors `postmortem.JSONBundle`. Field-for-field on purpose: the report is a
 * compliance artefact, so a field the console cannot show is a field that may
 * as well not have been gathered. */
export interface PostMortemBundle {
  format: string
  version: number
  /** The rendered Markdown document, so one response serves preview and download. */
  markdown: string
  generated_at: string
  generated_by?: string
  incident_console_url?: string
  event: {
    id: string
    host: string
    time: string
    level: number
    level_label: string
    category?: string
    action?: string
    summary: string
    target_type: string
    path_or_key: string
    rule_name?: string
    rule_tags?: string[]
    classification?: string
    metadata?: Record<string, string>
    kubernetes_context?: string
  }
  window: { from: string; to: string; label: string }
  timeline: {
    id: string
    time: string
    level: number
    summary: string
    path_or_key: string
    actor?: string
    host?: string
    is_incident: boolean
  }[]
  diff?: string
  diff_redacted: boolean
  attribution: {
    actor?: string
    uid?: string
    login_user?: string
    remote_ip?: string
    process?: string
    pid?: number
    ppid?: number
    cmdline?: string
    lineage?: string[]
    source?: string
  }
  blast_radius: {
    risk_summary?: string
    affected_services?: string[]
    rollback_command?: string
    verify_command?: string
    rollback_notes?: string
  }
  monitoring: {
    grafana_annotation_url?: string
    grafana_dashboard_url?: string
    host_summary_url?: string
  }
  control_plane: {
    time: string
    actor: string
    role?: string
    action: string
    target?: string
    source_ip?: string
  }[]
  change_ticket?: ChangeTicket
  compliance?: Compliance
  compliance_reason?: string
}

/* -------------------------------------------------------------------------- */
/* ITSM change-ticket bridge (Jira & ServiceNow)                              */
/* -------------------------------------------------------------------------- */

export type ITSMKind = 'jira' | 'servicenow' | 'manual'
export type EnforcementMode = 'off' | 'warn' | 'required'

/**
 * One connector's configuration. The token is never returned by the API —
 * `token_set` reports whether one is stored — so the form can show "configured"
 * without ever holding the credential.
 */
export interface ITSMConnection {
  url: string
  /** Jira project key, or ServiceNow table name (e.g. "change_request"). */
  project: string
  auth_token?: string
  username?: string
  enabled: boolean
  last_sync_at?: string
  last_sync_ok: boolean
  last_sync_error?: string
  last_sync_count: number
}

export interface ITSMSettings {
  jira: ITSMConnection
  servicenow: ITSMConnection
  enforcement: EnforcementMode
  /** Tolerance applied to each ticket's window, in minutes. */
  window_grace_minutes: number
  /** Impact level at or above which a change needs a ticket. */
  min_level: number
  /** Actors whose changes never require a ticket (e.g. the CMDB account). */
  exempt_actors: string[]
  updated_at?: string
}

/** One posture the server accepts, with its console-facing explanation. */
export interface EnforcementHint {
  value: EnforcementMode
  label: string
  help: string
}

/**
 * The hub-facing view of the bridge: the settings, the closed vocabularies, and
 * the control's real output (unapproved count in the last 24h).
 */
export interface ITSMSettingsView extends ITSMSettings {
  jira_token_set: boolean
  servicenow_token_set: boolean
  enforcements: string[]
  kinds: string[]
  modes: EnforcementHint[]
  unapproved_count: number
}

/**
 * A change request mirrored into StateTrack's local database, mirroring
 * `storage.ChangeTicket`.
 *
 * `status` is the normalized state and `status_label` its human rendering;
 * `authorized` is the server's own predicate, so the badge cannot disagree with
 * the verdict the correlation produced.
 */
export interface ChangeTicket {
  id: string
  kind: ITSMKind | string
  ref: string
  status: string
  status_label: string
  authorized: boolean
  summary: string
  url?: string
  hosts: string[]
  environments: string[]
  paths: string[]
  window_start?: string
  window_end?: string
  requested_by?: string
  created_at: string
  updated_at: string
  /** True when the ticket's window has closed as of now. */
  expired: boolean
}

export interface ITSMResponse {
  settings: ITSMSettingsView
  tickets: ChangeTicket[]
  count: number
}

/** Partial update: omitted fields keep their stored value, and an omitted
 * token keeps the stored one rather than clearing it. */
export interface ITSMSettingsUpdate {
  jira?: Partial<ITSMConnectionUpdate>
  servicenow?: Partial<ITSMConnectionUpdate>
  enforcement?: EnforcementMode
  window_grace_minutes?: number
  min_level?: number
  exempt_actors?: string[]
}

/** The writable slice of one connector. */
export interface ITSMConnectionUpdate {
  url: string
  project: string
  auth_token: string
  username: string
  enabled: boolean
}

/** A ticket written by hand — the air-gapped onboarding path. */
export interface ChangeTicketInput {
  ref: string
  kind?: ITSMKind | string
  status?: string
  summary?: string
  url?: string
  hosts?: string[]
  environments?: string[]
  paths?: string[]
  window_start?: string
  window_end?: string
  requested_by?: string
}

/**
 * One event with its change-control verdict, from
 * `GET /api/v1/events/compliance`. Extends `Event` with the correlation result
 * so the Reports page can filter for unauthorised production edits.
 */
export interface ComplianceEvent extends Event {
  compliance: Compliance
  compliance_reason?: string
  ticket_ref?: string
  ticket_status?: string
}

export interface ComplianceEventsResponse {
  events: ComplianceEvent[]
  count: number
  /** The server's verdict vocabulary, so the filter cannot drift from it. */
  filters: string[]
  /** False when enforcement is off: the verdicts are advisory only. */
  enforced: boolean
}

/**
 * The verdict for a single event, from `GET /api/v1/events/{id}/compliance`.
 *
 * Carries the event alongside its verdict because the Inspector drawer already
 * has the event and would otherwise have to correlate the two by hand — the
 * response is shaped so the drawer can render the badge straight from
 * `verdict`.
 */
export interface EventComplianceResponse {
  event_id: string
  verdict: ComplianceEvent
  /** False when the verdict is advisory (enforcement off) rather than actionable. */
  enforced: boolean
  filters: string[]
}

/* -------------------------------------------------------------------------- */
/* Pluggable AI provider gateway                                              */
/* -------------------------------------------------------------------------- */

/**
 * The closed engine vocabulary, mirroring `ai.Provider` on the server. Kept as
 * a union rather than `string` so the provider selector cannot offer a value the
 * API would reject, and adding an engine is a compile error here rather than a
 * silently missing option in the dropdown.
 */
export type AIProvider = 'deterministic' | 'ollama' | 'azure_openai' | 'openai' | 'anthropic'

/**
 * The org's analysis configuration, mirroring `ai.Settings`. The API accepts a
 * partial update, so every field is optional when saving; the stored credential
 * is never returned (`api_key_set` reports whether one exists).
 */
export interface AISettings {
  provider: AIProvider
  /** Base URL of the model service. Empty means "use the provider default". */
  endpoint: string
  /** OpenAI model id, or the Azure deployment name. */
  model: string
  /** Present only on write; the server never returns the stored secret. */
  api_key?: string
  /** Azure's required `api-version` query parameter. */
  api_version?: string
  /** Gates live calls; a disabled gateway falls back to the deterministic engine. */
  enabled: boolean
  temperature: number
  max_tokens: number
  timeout_seconds: number
  /** Most recent connectivity test, so the badge survives a reload. */
  last_test_at?: string
  last_test_ok: boolean
  last_test_error?: string
  updated_at?: string
}

/**
 * The hub-facing view: the settings plus the closed provider set, a credential
 * presence flag, and the values actually used after applying provider defaults
 * (so the card can show what will run rather than what was left blank).
 */
export interface AISettingsResponse extends AISettings {
  providers: AIProvider[]
  api_key_set: boolean
  /** True when the selected provider transmits the event off-host. */
  needs_network: boolean
  effective_endpoint: string
  effective_model: string
}

export type AISettingsUpdate = Partial<
  Pick<
    AISettings,
    | 'provider'
    | 'endpoint'
    | 'model'
    | 'api_key'
    | 'api_version'
    | 'enabled'
    | 'temperature'
    | 'max_tokens'
    | 'timeout_seconds'
  >
>

/** The connectivity probe result from `POST /api/v1/integrations/ai/test`. */
export interface AITestResponse {
  ok: boolean
  provider: string
  endpoint?: string
  model?: string
  detail: string
  latency_ms: number
  /** A truncated sample of the risk sentence the engine produced. */
  blast_check?: string
  checked_at: string
}

/** The blast-radius vocabulary. A closed set because the console colours it. */
export type BlastRadius = 'Low' | 'Medium' | 'High'

/**
 * The analyzer's answer, from `POST /api/v1/events/{id}/analyze` and the MCP
 * `statetrack_analyze_and_rollback` tool.
 *
 * `provider` is the *effective* engine, which differs from the configured one
 * when a model was unreachable and the offline heuristics answered — `fallback`
 * records that, so the drawer never presents a heuristic as a model's judgement.
 */
export interface Analysis {
  provider: string
  provider_label: string
  model?: string
  risk_summary: string
  blast_radius: BlastRadius | string
  affected_services?: string[]
  rollback_command?: string
  verification_command?: string
  rollback_notes?: string
  fallback: boolean
  fallback_reason?: string
  /** True when the analysis reasoned over a diff with redaction stubs in it. */
  scrubbed: boolean
  generated_at: string
  latency_ms: number
}
