import type {
  AISettingsResponse,
  AISettingsUpdate,
  AITestResponse,
  Analysis,
  APIKeysResponse,
  ApplyAllResponse,
  AuditLogsResponse,
  AuthMeResponse,
  AuthUser,
  ChangeTicket,
  ChangeTicketInput,
  Compliance,
  ComplianceEventsResponse,
  CreateAPIKeyRequest,
  CreateAPIKeyResponse,
  CreateEnrollmentTokenRequest,
  CreateEnrollmentTokenResponse,
  DriftRow,
  EnrollmentTokensResponse,
  Event,
  EventComplianceResponse,
  EventDetail,
  EventFilters,
  EventsPage,
  GrafanaResponse,
  GrafanaSettings,
  GrafanaSettingsUpdate,
  GrafanaTestResponse,
  Host,
  HostSummary,
  ITSMResponse,
  ITSMSettings,
  ITSMSettingsUpdate,
  PolicyRule,
  PostMortemBundle,
  RecommendationsResponse,
  RecommendationStatusFilter,
  Role,
  SSOConfig,
  SSOConfigUpdate,
  SystemInfo,
  TOTPSetupResponse,
  TOTPVerifyResponse,
  WatchRule,
  WatchRuleInput,
  WatchRulesResponse,
  WebhookChannel,
  WebhookChannelUpdate,
  WebhookDelivery,
  WebhookIntegrationsResponse,
  WebhookProvider,
  WebhookTestRequest,
  WebhookTestResponse,
} from '../types'

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`${res.status} ${res.statusText}: ${body}`)
  }
  return res.json() as Promise<T>
}

async function postJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { method: 'POST' })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`${res.status} ${res.statusText}: ${body}`)
  }
  return res.json() as Promise<T>
}

export function fetchHosts(): Promise<{ hosts: Host[] }> {
  return getJSON('/api/v1/hosts')
}

/** The org's console identities, for the Security tab's member list. */
export function fetchUsers(): Promise<{ users: AuthUser[] }> {
  return getJSON('/api/v1/auth/users')
}

/**
 * Discovered workloads awaiting review. `status` defaults to "pending" on the
 * server; "all" clears the filter.
 */
export function fetchRecommendations(
  status: RecommendationStatusFilter = 'pending',
  hostId?: string,
): Promise<RecommendationsResponse> {
  const params = new URLSearchParams()
  if (status) params.set('status', status)
  if (hostId) params.set('host_id', hostId)
  const qs = params.toString()
  return getJSON<RecommendationsResponse>(`/api/v1/recommendations${qs ? `?${qs}` : ''}`)
}

/** Approves one recommendation, returning the materialized policy rule. */
export function applyRecommendation(id: string): Promise<{ status: string; rule: PolicyRule }> {
  return postJSON(`/api/v1/recommendations/${encodeURIComponent(id)}/apply`)
}

export function dismissRecommendation(id: string): Promise<{ status: string }> {
  return postJSON(`/api/v1/recommendations/${encodeURIComponent(id)}/dismiss`)
}

/** Approves every pending recommendation, optionally scoped to one host. */
export function applyAllRecommendations(hostId?: string): Promise<ApplyAllResponse> {
  const qs = hostId ? `?host_id=${encodeURIComponent(hostId)}` : ''
  return postJSON(`/api/v1/recommendations/apply-all${qs}`)
}

export function fetchEvents(filters: EventFilters): Promise<EventsPage> {
  const params = new URLSearchParams()
  if (filters.host_id) params.set('host_id', filters.host_id)
  if (filters.impact_level) params.set('impact_level', String(filters.impact_level))
  if (filters.category) params.set('category', String(filters.category))
  if (filters.actor) params.set('actor', filters.actor)
  if (filters.search) params.set('search', filters.search)
  if (filters.from) params.set('from', filters.from)
  if (filters.to) params.set('to', filters.to)
  if (filters.cursor) params.set('cursor', filters.cursor)
  if (filters.limit) params.set('limit', String(filters.limit))
  if (filters.root_only) params.set('root_only', '1')
  if (filters.annotate) params.set('annotate', filters.annotate)
  const qs = params.toString()
  return getJSON<EventsPage>(`/api/v1/events${qs ? `?${qs}` : ''}`)
}

export function fetchEventDetail(id: string): Promise<EventDetail> {
  return getJSON(`/api/v1/events/${encodeURIComponent(id)}`)
}

export function fetchDrift(hostA: string, hostB: string): Promise<{ drift: DriftRow[] }> {
  return getJSON(
    `/api/v1/drift?host_a=${encodeURIComponent(hostA)}&host_b=${encodeURIComponent(hostB)}`,
  )
}

/* -------------------------------------------------------------------------- */
/* Integrations (Grafana, outbound notifications)                              */
/* -------------------------------------------------------------------------- */

async function sendJSON<T>(
  path: string,
  method: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  })
  const text = await res.text()
  const parsed = text ? safeParse(text) : undefined
  if (!res.ok) {
    // Surface the server's own error message when it sends one: "url must be
    // an absolute URL" is far more useful to the operator than "400".
    const detail =
      (parsed as { error?: string } | undefined)?.error ??
      (parsed as { detail?: string } | undefined)?.detail ??
      `${res.status} ${res.statusText}`
    throw new Error(detail)
  }
  return parsed as T
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return { detail: text }
  }
}

/** Current Grafana integration configuration plus the recent dispatch log. */
export function fetchGrafana(): Promise<GrafanaResponse> {
  return getJSON<GrafanaResponse>('/api/v1/integrations/grafana')
}

/** Partial update: omitted fields keep their current value server-side. */
export function saveGrafana(update: GrafanaSettingsUpdate): Promise<GrafanaSettings> {
  return sendJSON<GrafanaSettings>('/api/v1/integrations/grafana', 'PUT', update)
}

/** Live connectivity check against the configured Grafana URL. */
export function testGrafana(): Promise<GrafanaTestResponse> {
  return sendJSON<GrafanaTestResponse>('/api/v1/integrations/grafana/test', 'POST')
}

/** Sends a sample notification so the operator can validate a channel. */
export function testWebhook(req: WebhookTestRequest): Promise<WebhookTestResponse> {
  return sendJSON<WebhookTestResponse>('/api/v1/integrations/webhooks/test', 'POST', req)
}

/** Every outbound notification channel plus the recent delivery log. */
export function fetchWebhookIntegrations(): Promise<WebhookIntegrationsResponse> {
  return getJSON<WebhookIntegrationsResponse>('/api/v1/integrations/webhooks')
}

/**
 * Saves one provider's card. The body names the provider and omits anything
 * untouched, so saving Teams never rewrites the Slack secret.
 */
export function saveWebhookChannel(update: WebhookChannelUpdate): Promise<WebhookChannel> {
  return sendJSON<WebhookChannel>('/api/v1/integrations/webhooks', 'PUT', update)
}

/**
 * The delivery log on its own, for the hub's auto-refreshing status table.
 * `provider` narrows to one channel; omit it for every provider.
 */
export function fetchWebhookDeliveries(
  provider?: WebhookProvider,
): Promise<{ deliveries: WebhookDelivery[]; count: number }> {
  const qs = provider ? `?provider=${encodeURIComponent(provider)}` : ''
  return getJSON(`/api/v1/integrations/webhooks/deliveries${qs}`)
}

/**
 * The unified poller rollup for one host. Backs the hub's Checkmk and Zabbix
 * "live preview" panes, which render the exact JSON a poller would receive.
 */
export function fetchHostSummary(hostname: string, window = '7d'): Promise<HostSummary> {
  return getJSON<HostSummary>(
    `/api/v1/hosts/${encodeURIComponent(hostname)}/summary?window=${encodeURIComponent(window)}`,
  )
}

export function setForensic(hostId: string): Promise<{
  host_id: string
  forensic_until_ms: number
}> {
  return postJSON(`/api/v1/hosts/${encodeURIComponent(hostId)}/forensic`)
}

/* -------------------------------------------------------------------------- */
/* Identity, RBAC and enterprise security                                      */
/* -------------------------------------------------------------------------- */

/**
 * The signed-in principal. Called on every console bootstrap; an anonymous
 * visitor gets `authenticated: false` with a 200 rather than a 401, so the first
 * paint is the login screen instead of a console error.
 */
export function fetchAuthMe(): Promise<AuthMeResponse> {
  return getJSON<AuthMeResponse>('/api/v1/auth/me')
}

/**
 * Build and runtime posture of the server process.
 *
 * Read rather than hardcoded: a console bundle compiled into a container cannot
 * know which binary is serving it, and "which version am I looking at?" is the
 * first question of every support thread.
 */
export function fetchSystemInfo(): Promise<SystemInfo> {
  return getJSON<SystemInfo>('/api/v1/system')
}

/**
 * Switches the effective role for the RBAC demo. Only ever narrows privilege
 * server-side, and is refused entirely outside demo mode.
 */
export function switchRole(role: Role): Promise<{ role: Role; read_only: boolean }> {
  return sendJSON('/api/v1/auth/switch-role', 'POST', { role })
}

export function login(email: string, password: string, totpCode?: string) {
  return sendJSON<{ token: string; user: AuthUser }>('/api/v1/auth/login', 'POST', {
    email,
    password,
    totp_code: totpCode,
  })
}

export function logout(): Promise<{ status: string }> {
  return sendJSON('/api/v1/auth/logout', 'POST')
}

/** Begins TOTP enrollment: returns the secret and its `otpauth://` URI. */
export function setupTOTP(): Promise<TOTPSetupResponse> {
  return sendJSON<TOTPSetupResponse>('/api/v1/auth/totp/setup', 'POST')
}

/** Completes enrollment with the first 6-digit code (or disables it). */
export function verifyTOTP(code: string, disable = false): Promise<TOTPVerifyResponse> {
  return sendJSON<TOTPVerifyResponse>('/api/v1/auth/totp/verify', 'POST', { code, disable })
}

/** The org's OIDC configuration. The client secret is never returned. */
export function fetchSSO(): Promise<SSOConfig> {
  return getJSON<SSOConfig>('/api/v1/security/sso')
}

/** Partial update: omitted fields keep their stored value. */
export function saveSSO(update: SSOConfigUpdate): Promise<SSOConfig> {
  return sendJSON<SSOConfig>('/api/v1/security/sso', 'PUT', update)
}

export function fetchAPIKeys(): Promise<APIKeysResponse> {
  return getJSON<APIKeysResponse>('/api/v1/security/api-keys')
}

/**
 * Mints a key. The response carries the secret exactly once; nothing on the
 * server can return it again, so the UI must show it before dismissing.
 */
export function createAPIKey(req: CreateAPIKeyRequest): Promise<CreateAPIKeyResponse> {
  return sendJSON<CreateAPIKeyResponse>('/api/v1/security/api-keys', 'POST', req)
}

export function revokeAPIKey(id: string): Promise<{ status: string; id: string; name: string }> {
  return sendJSON(`/api/v1/security/api-keys/${encodeURIComponent(id)}`, 'DELETE')
}

export function fetchEnrollmentTokens(): Promise<EnrollmentTokensResponse> {
  return getJSON<EnrollmentTokensResponse>('/api/v1/security/enrollment-tokens')
}

/** Mints a bootstrap token; the response includes the ready-to-paste commands. */
export function createEnrollmentToken(
  req: CreateEnrollmentTokenRequest,
): Promise<CreateEnrollmentTokenResponse> {
  return sendJSON<CreateEnrollmentTokenResponse>('/api/v1/security/enrollment-tokens', 'POST', req)
}

export function revokeEnrollmentToken(
  id: string,
): Promise<{ status: string; id: string; name: string }> {
  return sendJSON(`/api/v1/security/enrollment-tokens/${encodeURIComponent(id)}`, 'DELETE')
}

/** The control-plane audit trail, newest first. */
export function fetchAuditLogs(params?: {
  action?: string
  actor?: string
  limit?: number
}): Promise<AuditLogsResponse> {
  const qs = new URLSearchParams()
  if (params?.action) qs.set('action', params.action)
  if (params?.actor) qs.set('actor', params.actor)
  if (params?.limit) qs.set('limit', String(params.limit))
  const s = qs.toString()
  return getJSON<AuditLogsResponse>(`/api/v1/security/audit-logs${s ? `?${s}` : ''}`)
}

/* -------------------------------------------------------------------------- */
/* Incident post-mortem ("War Room Export")                                   */
/* -------------------------------------------------------------------------- */

/**
 * Fetches the structured post-mortem bundle for an event.
 *
 * Deliberately a plain fetch rather than `getJSON`: the Markdown variant of the
 * same endpoint returns `text/markdown` with a download disposition, so the
 * console reads the bytes itself in both cases and never has to guess the
 * content type. The bundle embeds the same Markdown, so the preview and the
 * downloaded file cannot differ.
 */
export async function fetchPostMortem(
  eventId: string,
  window?: string,
  signal?: AbortSignal,
): Promise<PostMortemBundle> {
  const qs = new URLSearchParams({ format: 'json' })
  if (window) qs.set('window', window)
  const res = await fetch(
    `/api/v1/events/${encodeURIComponent(eventId)}/post-mortem?${qs.toString()}`,
    { signal },
  )
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(errorFrom(res, body))
  }
  return (await res.json()) as PostMortemBundle
}

/**
 * Fetches the raw Markdown document, which is what a human pastes into Jira.
 *
 * Separate from the JSON call because the endpoint's default disposition is an
 * attachment: asking for Markdown here returns the text, while a plain browser
 * navigation to the same URL downloads it. Both produce identical bytes.
 */
export async function fetchPostMortemMarkdown(eventId: string, window?: string): Promise<string> {
  const qs = new URLSearchParams({ format: 'md', download: '0' })
  if (window) qs.set('window', window)
  const res = await fetch(`/api/v1/events/${encodeURIComponent(eventId)}/post-mortem?${qs.toString()}`)
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(errorFrom(res, body))
  }
  return res.text()
}

/** The direct download URL, used as an anchor href so the browser names the file. */
export function postMortemDownloadUrl(eventId: string, format: 'md' | 'json', window?: string): string {
  const qs = new URLSearchParams({ format, download: '1' })
  if (window) qs.set('window', window)
  return `/api/v1/events/${encodeURIComponent(eventId)}/post-mortem?${qs.toString()}`
}

/**
 * Renders an error from a non-OK response, preferring the server's own message.
 * The post-mortem endpoint answers JSON errors on every path, so a bare status
 * code would throw away the one useful sentence.
 */
function errorFrom(res: Response, body: string): string {
  const parsed = body ? safeParse(body) : undefined
  return (
    (parsed as { error?: string } | undefined)?.error ??
    (body.trim() || `${res.status} ${res.statusText}`)
  )
}

/* -------------------------------------------------------------------------- */
/* ITSM change-ticket bridge (Jira & ServiceNow)                              */
/* -------------------------------------------------------------------------- */

/** The bridge configuration plus the mirrored ticket set. */
export function fetchITSM(): Promise<ITSMResponse> {
  return getJSON<ITSMResponse>('/api/v1/integrations/itsm')
}

/** Partial update. An omitted token keeps the stored credential. */
export function saveITSM(update: ITSMSettingsUpdate): Promise<ITSMSettings> {
  return sendJSON<ITSMSettings>('/api/v1/integrations/itsm', 'PUT', update)
}

/**
 * Stamps a completed sync on a connector. The endpoint does not fetch from the
 * ITSM system itself — correlating from local state is what makes the bridge
 * work in an air-gapped site — so this records the result of a job that ran
 * elsewhere.
 */
export function recordITSMSync(body: {
  kind: string
  imported?: number
  error?: string
}): Promise<{ status: string; kind: string; imported: number }> {
  return sendJSON('/api/v1/integrations/itsm/sync', 'POST', body)
}

/** The mirrored ticket set, optionally filtered by normalized status. */
export function fetchChangeTickets(status?: string): Promise<{ tickets: ChangeTicket[]; count: number }> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : ''
  return getJSON(`/api/v1/change-tickets${qs}`)
}

/** Creates or updates a ticket by hand (the air-gapped onboarding path). */
export function upsertChangeTicket(ticket: ChangeTicketInput): Promise<ChangeTicket> {
  return sendJSON<ChangeTicket>('/api/v1/change-tickets', 'POST', ticket)
}

export function deleteChangeTicket(ref: string): Promise<{ status: string; ref: string }> {
  return sendJSON(`/api/v1/change-tickets/${encodeURIComponent(ref)}`, 'DELETE')
}

/**
 * A page of events annotated with their change-control verdict. Reuses the
 * timeline's own filters so the Reports page's compliance view is the same
 * stream, read through an auditor's lens.
 */
export function fetchComplianceEvents(
  filters: EventFilters & { compliance?: Compliance | '' },
): Promise<ComplianceEventsResponse> {
  const params = new URLSearchParams()
  if (filters.host_id) params.set('host_id', filters.host_id)
  if (filters.impact_level) params.set('impact_level', String(filters.impact_level))
  if (filters.actor) params.set('actor', filters.actor)
  if (filters.search) params.set('search', filters.search)
  if (filters.from) params.set('from', filters.from)
  if (filters.to) params.set('to', filters.to)
  if (filters.compliance) params.set('compliance', filters.compliance)
  if (filters.limit) params.set('limit', String(filters.limit))
  const qs = params.toString()
  return getJSON<ComplianceEventsResponse>(`/api/v1/events/compliance${qs ? `?${qs}` : ''}`)
}

/**
 * The change-control verdict for one event, for the Inspector drawer.
 *
 * A dedicated endpoint rather than reusing the list: the list pages over the
 * timeline, so the event in the drawer may not be on the page it returns, and
 * pulling every page to find it would make opening one event cost the whole
 * feed's correlation.
 */
export function fetchEventCompliance(id: string): Promise<EventComplianceResponse> {
  return getJSON<EventComplianceResponse>(
    `/api/v1/events/${encodeURIComponent(id)}/compliance`,
  )
}

/* -------------------------------------------------------------------------- */
/* Pluggable AI provider gateway & MCP server                                 */
/* -------------------------------------------------------------------------- */

/**
 * Runs the configured AI provider (or the offline heuristics) against one event
 * and returns the risk summary, blast radius and rollback plan.
 *
 * POST rather than GET because the analysis may call out to a model: it is a
 * computation, not a cached resource, and the browser must not treat a
 * deep-linked URL as a stable answer.
 */
export function analyzeEvent(eventId: string, signal?: AbortSignal): Promise<Analysis> {
  return sendJSON<Analysis>(
    `/api/v1/events/${encodeURIComponent(eventId)}/analyze`,
    'POST',
    undefined,
    signal,
  )
}

/** The AI gateway configuration plus the closed provider set and effective values. */
export function fetchAIIntegration(): Promise<AISettingsResponse> {
  return getJSON<AISettingsResponse>('/api/v1/integrations/ai')
}/** Partial update: omitted fields keep their stored value, and an omitted key
 * keeps the credential rather than clearing it. */
export function saveAIIntegration(update: AISettingsUpdate): Promise<AISettingsResponse> {
  return sendJSON<AISettingsResponse>('/api/v1/integrations/ai', 'PUT', update)
}

/** Live connectivity probe against the configured provider. */
export function testAIIntegration(): Promise<AITestResponse> {
  return sendJSON<AITestResponse>('/api/v1/integrations/ai/test', 'POST')
}

/* -------------------------------------------------------------------------- */
/* Custom watched targets (the console's rule builder)                        */
/* -------------------------------------------------------------------------- */

/**
 * Every custom watched target plus the builder's catalog.
 *
 * The catalog (target types, impact levels, default level) ships with the list
 * rather than living in the browser: an example path in the modal has to be one
 * the agent can actually watch, so it must come from the server that validates
 * the rule.
 */
export function fetchWatchRules(params?: {
  targetType?: string
  hostScope?: string
}): Promise<WatchRulesResponse> {
  const qs = new URLSearchParams()
  if (params?.targetType) qs.set('target_type', params.targetType)
  if (params?.hostScope) qs.set('host_scope', params.hostScope)
  const s = qs.toString()
  return getJSON<WatchRulesResponse>(`/api/v1/rules${s ? `?${s}` : ''}`)
}

/** Creates a watched target; the response is the stored rule, decorated. */
export function createWatchRule(input: WatchRuleInput): Promise<WatchRule> {
  return sendJSON<WatchRule>('/api/v1/rules', 'POST', input)
}

export function deleteWatchRule(id: string): Promise<{
  status: string
  id: string
  pattern: string
  rule: WatchRule
}> {
  return sendJSON(`/api/v1/rules/${encodeURIComponent(id)}`, 'DELETE')
}

export type { Event, EventDetail }