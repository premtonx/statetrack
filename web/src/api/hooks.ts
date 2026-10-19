import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type InfiniteData,
} from '@tanstack/react-query'
import {
  analyzeEvent,
  applyAllRecommendations,
  applyRecommendation,
  createAPIKey,
  createEnrollmentToken,
  createWatchRule,
  deleteChangeTicket,
  deleteWatchRule,
  dismissRecommendation,
  fetchAIIntegration,
  fetchAPIKeys,
  fetchAuditLogs,
  fetchAuthMe,
  fetchComplianceEvents,
  fetchDrift,
  fetchEnrollmentTokens,
  fetchEventCompliance,
  fetchEventDetail,
  fetchEvents,
  fetchGrafana,
  fetchHosts,
  fetchHostSummary,
  fetchITSM,
  fetchPostMortem,
  fetchRecommendations,
  fetchSSO,
  fetchSystemInfo,
  fetchUsers,
  fetchWatchRules,
  fetchWebhookDeliveries,
  fetchWebhookIntegrations,
  login,
  logout,
  revokeAPIKey,
  revokeEnrollmentToken,
  saveAIIntegration,
  saveGrafana,
  saveITSM,
  saveSSO,
  saveWebhookChannel,
  setForensic,
  setupTOTP,
  switchRole,
  testAIIntegration,
  testGrafana,
  testWebhook,
  upsertChangeTicket,
  verifyTOTP,
} from './client'
import type {
  AISettingsResponse,
  AISettingsUpdate,
  AITestResponse,
  Analysis,
  ChangeTicket,
  ChangeTicketInput,
  Compliance,
  ComplianceEvent,
  CreateAPIKeyRequest,
  CreateEnrollmentTokenRequest,
  Event,
  EventFilters,
  EventsPage,
  GrafanaAnnotation,
  GrafanaSettings,
  GrafanaSettingsUpdate,
  GrafanaTestResponse,
  Host,
  HostSummary,
  ITSMSettingsUpdate,
  ITSMSettingsView,
  LiveEvent,
  PolicyRule,
  Recommendation,
  RecommendationStatusFilter,
  Role,
  SSOConfigUpdate,
  WatchImpactLevel,
  WatchRule,
  WatchRuleInput,
  WatchTargetType,
  WebhookChannel,
  WebhookChannelUpdate,
  WebhookDelivery,
  WebhookProvider,
  WebhookTestRequest,
} from '../types'
import {
  FALLBACK_AI_SETTINGS,
  FALLBACK_CHANGE_TICKETS,
  FALLBACK_EVENTS,
  FALLBACK_GRAFANA_ANNOTATIONS,
  FALLBACK_GRAFANA_SETTINGS,
  FALLBACK_HOSTS,
  FALLBACK_ITSM_SETTINGS,
  FALLBACK_POLICY_RULES,
  FALLBACK_RECOMMENDATIONS,
  FALLBACK_WATCH_IMPACT_LEVELS,
  FALLBACK_WATCH_RULES,
  FALLBACK_WATCH_TARGET_TYPES,
  FALLBACK_WEBHOOK_CHANNELS,
  fallbackComplianceEvents,
  fallbackDiffFor,
  fallbackEventById,
  fallbackPairwiseDrift,
} from './mockData'
import type { EventDetail } from '../types'

/** Filters minus pagination controls (handled by useInfiniteQuery). */
export type TimelineFilters = Omit<EventFilters, 'cursor' | 'limit'>

export const DEFAULT_LIMIT = 100

export function useHosts() {
  return useQuery({
    queryKey: ['hosts'],
    queryFn: fetchHosts,
    refetchInterval: 15_000,
  })
}

/**
 * Hosts for page-level presentation.
 *
 * A successful response with `[]` means the deployment genuinely has no agents
 * enrolled, and that is what the console must show: no seeded fleet, `0 / 0
 * agents online`, and an onboarding empty state. Sample hosts are only
 * substituted when the API is unreachable *and* this is an explicitly
 * demo-mode build (`STATETRACK_SAMPLE_DATA` in the frontend env), so a
 * production install can never mistake them for real infrastructure.
 * `isLive` is false only in that sample case, letting pages label it honestly.
 */
export function useHostList(): {
  hosts: Host[]
  total: number
  online: number
  offline: number
  isLive: boolean
  isLoading: boolean
  isError: boolean
} {
  const query = useHosts()
  const live = useMemo(
    () => ((query.data?.hosts ?? []) as Host[]).filter((h): h is Host => Boolean(h?.id)),
    [query.data],
  )
  const showSample = live.length === 0 && sampleDataEnabled() && !query.isLoading
  const hosts = useMemo(() => (showSample ? FALLBACK_HOSTS : live), [showSample, live])
  const online = useMemo(() => hosts.filter((h) => h?.status === 'online').length, [hosts])
  return {
    hosts,
    total: hosts.length,
    online,
    offline: hosts.length - online,
    isLive: !showSample,
    isLoading: query.isLoading,
    isError: query.isError,
  }
}

/**
 * True when this build is allowed to render seeded sample rows in place of an
 * empty API response. Off unless `VITE_STATETRACK_SAMPLE_DATA=1`, which only
 * `scripts/dev.ps1 seed` and the public demo deployment set.
 */
export function sampleDataEnabled(): boolean {
  const v = (import.meta.env?.VITE_STATETRACK_SAMPLE_DATA ?? '').toString().toLowerCase()
  return v === '1' || v === 'true'
}

export function useEvents(filters: TimelineFilters) {
  return useInfiniteQuery({
    queryKey: ['events', filters],
    queryFn: ({ pageParam }) =>
      fetchEvents({ ...filters, cursor: pageParam as string, limit: DEFAULT_LIMIT }),
    initialPageParam: '',
    getNextPageParam: (last) => last.next_cursor || undefined,
    placeholderData: (prev) => prev,
  })
}

/**
 * Events for aggregate widgets (dashboard "latest changes", reports tables).
 *
 * An empty response is returned as an empty list, so a clean deployment renders
 * zeroed KPIs and its onboarding empty state. Sample rows are only substituted
 * when `VITE_STATETRACK_SAMPLE_DATA` is set and the API returned nothing.
 */
export function useEventFeed(filters: TimelineFilters, limit = DEFAULT_LIMIT): {
  events: Event[]
  isLoading: boolean
  isError: boolean
  isFallback: boolean
  refetch: () => void
} {
  const query = useQuery({
    queryKey: ['event-feed', filters, limit],
    queryFn: () => fetchEvents({ ...filters, limit }),
    refetchInterval: 30_000,
  })

  const live = useMemo(
    () => (query.data?.events ?? []).filter((e): e is Event => Boolean(e && e.id)),
    [query.data],
  )
  const isFallback = live.length === 0 && sampleDataEnabled() && !query.isLoading

  return {
    events: isFallback ? fallbackEvents(filters, limit) : live,
    isLoading: query.isLoading,
    isError: query.isError,
    isFallback,
    refetch: () => {
      void query.refetch()
    },
  }
}

/** Client-side filter over the seeded fallback timeline. */
function fallbackEvents(filters: TimelineFilters, limit: number): Event[] {
  const from = filters.from ? new Date(filters.from).getTime() : 0
  const to = filters.to ? new Date(filters.to).getTime() : Number.MAX_SAFE_INTEGER
  const q = filters.search?.toLowerCase()
  return FALLBACK_EVENTS.filter((e) => {
    const t = new Date(e.occurred_at).getTime()
    if (t < from || t > to) return false
    if (filters.host_id && e.host_id !== filters.host_id) return false
    if (filters.impact_level && e.impact_level !== filters.impact_level) return false
    if (filters.category && e.category !== filters.category) return false
    if (q && !`${e.summary} ${e.path_or_key}`.toLowerCase().includes(q)) return false
    return true
  })
    .sort((a, b) => new Date(b.occurred_at).getTime() - new Date(a.occurred_at).getTime())
    .slice(0, limit)
}

/**
 * Event detail for the inspector drawer.
 *
 * Live events resolve from `GET /api/v1/events/{id}`. Ids that belong to the
 * seeded preview timeline are resolved locally: the console shows those rows
 * before any agent has reported, and they are client-generated, so the API
 * cannot know them. Falling back here keeps "View" working on both sources
 * instead of surfacing a 404 as "Failed to load event".
 */
export function useEventDetail(id: string | null) {
  return useQuery({
    queryKey: ['event', id],
    queryFn: async (): Promise<EventDetail> => {
      try {
        return await fetchEventDetail(id as string)
      } catch (err) {
        const seeded = fallbackEventById(id as string)
        if (seeded) return { ...seeded, diff: seeded.has_diff ? fallbackDiffFor(seeded) : undefined }
        throw err
      }
    },
    enabled: !!id,
    // Seeded events are static, so a resolved fallback never needs refetching;
    // a failure is surfaced to the drawer's error state as before.
    retry: false,
  })
}

export function useDrift(hostA: string | null, hostB: string | null) {
  return useQuery({
    queryKey: ['drift', hostA, hostB],
    queryFn: () => fetchDrift(hostA as string, hostB as string),
    enabled: !!hostA && !!hostB && hostA !== hostB,
    placeholderData: () =>
      hostA && hostB ? { drift: fallbackPairwiseDrift(hostA, hostB) } : undefined,
  })
}

export function useEnableForensic() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (hostId: string) => setForensic(hostId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hosts'] }),
  })
}

/* -------------------------------------------------------------------------- */
/* Grafana integration                                                        */
/* -------------------------------------------------------------------------- */

export interface GrafanaFeed {
  settings: GrafanaSettings
  annotations: GrafanaAnnotation[]
  /** True when the settings/annotations shown are the seeded preview set. */
  isFallback: boolean
  isLoading: boolean
  isError: boolean
  save: (update: GrafanaSettingsUpdate) => void
  test: () => void
  /** Result of the most recent test, kept in memory for the status pill. */
  testResult: GrafanaTestResponse | null
  isSaving: boolean
  isTesting: boolean
  saveError: string | null
}

/**
 * Grafana integration state: saved settings, the annotation dispatch log, and
 * the save/test actions.
 *
 * Falls back to a seeded configuration when the API is unreachable, so the page
 * renders a complete, realistic form instead of an error state — the same
 * graceful-degradation rule the rest of the console follows. Saving and testing
 * still report their real failures, because silently pretending a save worked
 * would be worse than showing an empty form.
 */
export function useGrafanaIntegration(): GrafanaFeed {
  const qc = useQueryClient()
  const [testResult, setTestResult] = useState<GrafanaTestResponse | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)

  const query = useQuery({
    queryKey: ['grafana-integration'],
    queryFn: fetchGrafana,
    refetchInterval: 60_000,
    retry: false,
  })

  const isFallback = !query.data
  const settings: GrafanaSettings = query.data ?? FALLBACK_GRAFANA_SETTINGS
  const annotations = useMemo(
    () => (query.data?.recent_annotations ?? []).filter((a) => a && a.id),
    [query.data],
  )

  const saveMut = useMutation({
    mutationFn: (update: GrafanaSettingsUpdate) => saveGrafana(update),
    onSuccess: () => {
      setSaveError(null)
      void qc.invalidateQueries({ queryKey: ['grafana-integration'] })
    },
    onError: (err: unknown) => {
      setSaveError(err instanceof Error ? err.message : 'Could not save the integration')
    },
  })

  const testMut = useMutation({
    mutationFn: () => testGrafana(),
    onSuccess: (res) => {
      setTestResult(res)
      // The test is recorded server-side, so refetch to pick up the new
      // last_test_* values and the synthetic log row.
      void qc.invalidateQueries({ queryKey: ['grafana-integration'] })
    },
    onError: (err: unknown) => {
      // A 502 carries a JSON body describing why the provider refused; the
      // client surfaces it as the error message.
      setTestResult({
        ok: false,
        url: settings.url,
        detail: err instanceof Error ? err.message : 'Connection test failed',
        checked_at: new Date().toISOString(),
      })
    },
  })

  return {
    settings,
    annotations:
      isFallback && annotations.length === 0 && sampleDataEnabled()
        ? FALLBACK_GRAFANA_ANNOTATIONS
        : annotations,
    isFallback,
    isLoading: query.isLoading,
    isError: query.isError,
    save: (update) => saveMut.mutate(update),
    test: () => testMut.mutate(),
    testResult,
    isSaving: saveMut.isPending,
    isTesting: testMut.isPending,
    saveError,
  }
}

/**
 * Sends a test notification to a provider and reports the result. Deliberately
 * a plain async function rather than a cached query: each click is a fresh
 * side effect, and the operator expects a new request every time.
 */
export function useWebhookTest() {
  return useMutation({
    mutationFn: (req: WebhookTestRequest) => testWebhook(req),
  })
}

/* -------------------------------------------------------------------------- */
/* Webhook channels (ChatOps, paging & SIEM hub)                               */
/* -------------------------------------------------------------------------- */

export interface WebhookChannelFeed {
  /** One entry per provider, always complete (defaults fill any gap). */
  channels: WebhookChannel[]
  deliveries: WebhookDelivery[]
  /** True when the API is unreachable and the seeded preview set is shown. */
  isFallback: boolean
  isLoading: boolean
  isError: boolean
  save: (update: WebhookChannelUpdate) => void
  isSaving: boolean
  saveError: string | null
  /** Provider whose save most recently succeeded, for the card's "Saved" state. */
  lastSavedProvider: WebhookProvider | null
}

/**
 * Saved notification channels plus their delivery log.
 *
 * Falls back to a seeded set when the API is unreachable so the hub renders
 * complete cards rather than an error state — the same graceful-degradation
 * rule the rest of the console follows. Saving and testing still report their
 * real failures, because pretending a save worked is worse than an empty form.
 */
export function useWebhookChannels(): WebhookChannelFeed {
  const qc = useQueryClient()
  const [saveError, setSaveError] = useState<string | null>(null)
  const [lastSavedProvider, setLastSavedProvider] = useState<WebhookProvider | null>(null)

  const query = useQuery({
    queryKey: ['webhook-integrations'],
    queryFn: fetchWebhookIntegrations,
    refetchInterval: 30_000,
    retry: false,
  })

  const saveMut = useMutation({
    mutationFn: (update: WebhookChannelUpdate) => saveWebhookChannel(update),
    onSuccess: (_saved, update) => {
      setSaveError(null)
      setLastSavedProvider(update.provider)
      void qc.invalidateQueries({ queryKey: ['webhook-integrations'] })
    },
    onError: (err: unknown) => {
      setSaveError(err instanceof Error ? err.message : 'Could not save this channel')
    },
  })

  const channels = useMemo<WebhookChannel[]>(() => {
    const live = query.data?.channels ?? []
    if (live.length > 0) return live
    return FALLBACK_WEBHOOK_CHANNELS
  }, [query.data])

  return {
    channels,
    deliveries: query.data?.recent_deliveries ?? [],
    isFallback: !query.data,
    isLoading: query.isLoading,
    isError: query.isError,
    save: (update) => saveMut.mutate(update),
    isSaving: saveMut.isPending,
    saveError,
    lastSavedProvider,
  }
}

/**
 * The delivery log on its own, polled faster than the configuration because it
 * is the thing an operator watches while clicking "Send Test".
 */
export function useWebhookDeliveries(provider?: WebhookProvider) {
  return useQuery({
    queryKey: ['webhook-deliveries', provider ?? ''],
    queryFn: () => fetchWebhookDeliveries(provider),
    refetchInterval: 15_000,
    retry: false,
  })
}

/**
 * The unified poller rollup for one host. Disabled until a host is chosen, so
 * the hub does not fire a request before the operator picks one.
 */
export function useHostSummary(hostname: string | null, window = '7d') {
  return useQuery<HostSummary>({
    queryKey: ['host-summary', hostname ?? '', window],
    queryFn: () => fetchHostSummary(hostname as string, window),
    enabled: !!hostname,
    retry: false,
  })
}

/* -------------------------------------------------------------------------- */
/* Smart recommendations (auto-discovery & asset tiering)                      */
/* -------------------------------------------------------------------------- */

export interface RecommendationFeed {
  /** Pending recommendations (or all, when `status` is "all"). */
  recommendations: Recommendation[]
  /** Pending count, used by the banner pill. */
  pending: number
  /** Pending count per hostname. */
  byHost: Record<string, number>
  /** Distinct hostnames with pending recommendations, sorted. */
  hostnames: string[]
  /** The subset currently checked for a bulk apply. */
  selectedIds: string[]
  toggle: (id: string) => void
  toggleAll: (checked: boolean) => void
  clearSelection: () => void
  applyOne: (id: string) => void
  dismissOne: (id: string) => void
  applySelected: () => void
  applyAll: () => void
  isMutating: boolean
  /** Rules materialized by the most recent apply. */
  appliedRules: PolicyRule[]
  isFallback: boolean
  isLoading: boolean
  isError: boolean
}

/**
 * Loads discovered-workload recommendations and exposes the review actions
 * (accept one, dismiss one, apply everything). A successful empty response is
 * honoured as empty: a host that has discovered nothing has nothing to
 * recommend, and fabricating that on a production install would push invented
 * rules at an operator. Seeded rows appear only in an explicit sample-data
 * build.
 */
export function useRecommendations(
  status: RecommendationStatusFilter = 'pending',
  hostId?: string,
): RecommendationFeed {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<string[]>([])
  const [appliedRules, setAppliedRules] = useState<PolicyRule[]>([])
  const query = useQuery({
    queryKey: ['recommendations', status, hostId ?? ''],
    queryFn: () => fetchRecommendations(status, hostId),
    refetchInterval: 60_000,
  })

  const live = useMemo(
    () => (query.data?.recommendations ?? []).filter((r): r is Recommendation => Boolean(r?.id)),
    [query.data],
  )
  const isFallback = live.length === 0 && sampleDataEnabled() && !query.isLoading
  const recommendations = useMemo(
    () =>
      isFallback
        ? FALLBACK_RECOMMENDATIONS.filter(
            (r) =>
              (status === 'all' || r.status === status) &&
              (!hostId || r.host_id === hostId),
          )
        : live,
    [isFallback, live, status, hostId],
  )

  // The selected set is derived, not stored: an id that disappeared (applied
  // elsewhere, or filtered out) must never linger in the bulk apply action.
  const selectedIds = useMemo(
    () => selected.filter((id) => (recommendations ?? []).some((r) => r.id === id)),
    [selected, recommendations],
  )

  const invalidate = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ['recommendations'] })
  }, [qc])

  const applyOneMut = useMutation({
    mutationFn: (id: string) => applyRecommendation(id),
    onSuccess: (res) => {
      if (res?.rule) setAppliedRules((prev) => [res.rule as PolicyRule, ...prev])
      invalidate()
    },
  })
  const dismissOneMut = useMutation({
    mutationFn: (id: string) => dismissRecommendation(id),
    onSuccess: invalidate,
  })
  const applyAllMut = useMutation({
    mutationFn: (ids: string[] | undefined) =>
      ids && ids.length > 0 ? applySelectedSequentially(ids) : applyEveryRecommendation(hostId),
    onSuccess: (rules) => {
      if (rules.length > 0) setAppliedRules((prev) => [...rules, ...prev])
      setSelected([])
      invalidate()
    },
  })

  const toggle = useCallback((id: string) => {
    setSelected((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]))
  }, [])
  const toggleAll = useCallback(
    (checked: boolean) => setSelected(checked ? recommendations.map((r) => r.id) : []),
    [recommendations],
  )
  const clearSelection = useCallback(() => setSelected([]), [])

  const byHost = useMemo(() => {
    const out: Record<string, number> = {}
    for (const r of recommendations) {
      if (isFallback && r.status !== 'pending') continue
      const key = r.hostname || r.host_id
      out[key] = (out[key] ?? 0) + 1
    }
    return out
  }, [recommendations, isFallback])

  const hostnames = useMemo(() => Object.keys(byHost).sort(), [byHost])

  return {
    recommendations,
    pending: isFallback
      ? recommendations.filter((r) => r.status === 'pending').length
      : (query.data?.pending ?? recommendations.length),
    byHost,
    hostnames,
    selectedIds,
    toggle,
    toggleAll,
    clearSelection,
    applyOne: (id: string) => applyOneMut.mutate(id),
    dismissOne: (id: string) => dismissOneMut.mutate(id),
    applySelected: () => applyAllMut.mutate(selectedIds),
    applyAll: () => applyAllMut.mutate(undefined),
    isMutating: applyOneMut.isPending || dismissOneMut.isPending || applyAllMut.isPending,
    appliedRules,
    isFallback,
    isLoading: query.isLoading,
    isError: query.isError,
  }
}

/** Applies a hand-picked set one at a time, returning the rules created. */
async function applySelectedSequentially(ids: string[]): Promise<PolicyRule[]> {
  const rules: PolicyRule[] = []
  for (const id of ids) {
    const res = await applyRecommendation(id)
    if (res?.rule) rules.push(res.rule as PolicyRule)
  }
  return rules
}

/**
 * One-click "apply everything". Uses the bulk endpoint when the operator is
 * looking at the whole fleet, and narrows to the visible host when a host
 * filter is active so the button never surprises with cross-host changes.
 */
async function applyEveryRecommendation(hostId?: string): Promise<PolicyRule[]> {
  const res = await applyAllRecommendations(hostId)
  return (res?.rules ?? []) as PolicyRule[]
}

/** Materialized rules, used by the "active policy" summary when needed. */
export function usePolicyRulesFallback(): PolicyRule[] {
  return FALLBACK_POLICY_RULES
}

export type LiveStatus = 'connecting' | 'open' | 'closed'

/**
 * Opens the /api/v1/stream WebSocket and invokes onEvent for every incoming
 * mutation. The callback is held in a ref so reconnects are not triggered by
 * render churn.
 *
 * Reconnection uses exponential backoff (1s → 2s → 4s → … capped at 30s) so a
 * missing backend doesn't spam the network with rapid retry loops; a
 * successful open resets the backoff.
 */
export function useLiveStream(onEvent: (e: LiveEvent) => void): LiveStatus {
  const [status, setStatus] = useState<LiveStatus>('connecting')
  const cb = useRef(onEvent)
  cb.current = onEvent

  useEffect(() => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${proto}://${location.host}/api/v1/stream`
    let ws: WebSocket | null = null
    let closed = false
    let attempt = 0
    let timer: ReturnType<typeof setTimeout> | undefined

    const connect = () => {
      if (closed) return
      setStatus('connecting')
      ws = new WebSocket(url)
      ws.onopen = () => {
        attempt = 0
        setStatus('open')
      }
      ws.onclose = () => {
        if (closed) return
        setStatus('closed')
        const delay = Math.min(1000 * 2 ** attempt, 30_000)
        attempt += 1
        timer = setTimeout(connect, delay)
      }
      ws.onerror = () => {
        // onclose follows and drives the backoff loop.
      }
      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data as string)
          if (data?.type === 'event' && data?.event) {
            cb.current(data.event as LiveEvent)
          }
        } catch {
          /* ignore malformed frames */
        }
      }
    }

    connect()
    return () => {
      closed = true
      if (timer) clearTimeout(timer)
      ws?.close()
    }
  }, [])

  return status
}

/** Map a WS Notification onto the fuller Event shape used by the timeline. */
function liveToEvent(e: LiveEvent): Event {
  return {
    id: e.id,
    host_id: e.host_id,
    hostname: e.hostname,
    parent_event_id: e.parent_event_id,
    occurred_at: e.occurred_at,
    impact_level: e.impact_level,
    category: e.category,
    action: e.action,
    summary: e.summary,
    target_type: e.target_type ?? '',
    path_or_key: e.path_or_key ?? '',
    actor_username: e.actor,
    child_count: 0,
    has_diff: false,
    diff_source: '',
    metadata: e.metadata,
  }
}

function liveMatches(e: LiveEvent, f: TimelineFilters): boolean {
  if (f.host_id && f.host_id !== e.host_id) return false
  if (f.impact_level && Number(e.impact_level) !== f.impact_level) return false
  if (f.category && Number(e.category) !== f.category) return false
  if (f.actor && e.actor !== f.actor) return false
  if (f.search) {
    const q = f.search.toLowerCase()
    const hay = `${e.summary} ${e.path_or_key ?? ''}`.toLowerCase()
    if (!hay.includes(q)) return false
  }
  const t = new Date(e.occurred_at).getTime()
  if (f.from && t < new Date(f.from).getTime()) return false
  if (f.to && t > new Date(f.to).getTime()) return false
  return true
}

/**
 * Live timeline sync: opens the WebSocket and prepends incoming root events
 * into every cached events query whose filters they match — no refetch, so it
 * stays smooth even as thousands of events stream in.
 */
export function useTimelineLive(): LiveStatus {
  const qc = useQueryClient()
  const onEvent = useCallback(
    (e: LiveEvent) => {
      // Child events surface only inside their expanded parent card.
      if (e.parent_event_id) return
      const ev = liveToEvent(e)
      const queries = qc.getQueryCache().findAll({ queryKey: ['events'] })
      for (const query of queries) {
        const filters = query.queryKey[1] as TimelineFilters | undefined
        if (filters && !liveMatches(e, filters)) continue
        qc.setQueryData<InfiniteData<EventsPage>>(query.queryKey, (old) => {
          if (!old || old.pages.length === 0) return old
          const [first, ...rest] = old.pages
          if (!first || !Array.isArray(first.events)) return old
          if (first.events.some((x) => x && x.id === ev.id)) return old
          return {
            pages: [{ ...first, events: [ev, ...first.events] }, ...rest],
            pageParams: old.pageParams,
          }
        })
      }
    },
    [qc],
  )
  return useLiveStream(onEvent)
}

/* -------------------------------------------------------------------------- */
/* Identity, RBAC and enterprise security                                      */
/* -------------------------------------------------------------------------- */

/**
 * The signed-in principal.
 *
 * `staleTime: 0` and refetch-on-focus are deliberate: the role shown in the
 * header is an authorization state, so a session that expired (or was re-issued
 * by another tab) must be reflected on the next interaction rather than held for
 * the default cache window and used to render the wrong read-only state.
 */
export function useAuthMe() {
  return useQuery({
    queryKey: ['auth-me'],
    queryFn: fetchAuthMe,
    staleTime: 0,
    refetchOnWindowFocus: true,
    retry: false,
  })
}

/**
 * The server's own build/runtime posture, for the System Information card.
 *
 * A deployment detail rather than live data, so it is cached for a while: the
 * version does not change without a restart.
 */
export function useSystemInfo() {
  return useQuery({
    queryKey: ['system-info'],
    queryFn: fetchSystemInfo,
    staleTime: 5 * 60_000,
    retry: 1,
  })
}

/**
 * The RBAC demo switcher. Invalidates every cached query on success so pages
 * re-render against the new effective role instead of showing stale write
 * affordances the server would now reject.
 */
export function useSwitchRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (role: Role) => switchRole(role),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['auth-me'] })
      // Role changes the read-only posture of the whole console, so cached
      // security data (which is fetched under a specific role) must be refetched.
      void qc.invalidateQueries({ queryKey: ['api-keys'] })
      void qc.invalidateQueries({ queryKey: ['enrollment-tokens'] })
      void qc.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })
}

export function useLogout() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => logout(),
    onSuccess: () => {
      // Clear everything: a signed-out console must not serve another user's
      // cached event stream and host inventory.
      qc.clear()
      void qc.invalidateQueries({ queryKey: ['auth-me'] })
    },
  })
}

/**
 * Password sign-in.
 *
 * `totpRequired` is a 428 response carrying `totp_required: true`: the
 * credentials were accepted but the account has a second factor, which is why
 * the error is surfaced as a distinct field rather than only as a message the
 * login form would have to pattern-match.
 */
export function useLogin() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { email: string; password: string; totpCode?: string }) =>
      login(v.email, v.password, v.totpCode),
    onSuccess: () => {
      // The session cookie is now set; every cached read was fetched as an
      // anonymous principal and must be refetched under the new one.
      qc.clear()
      void qc.invalidateQueries({ queryKey: ['auth-me'] })
    },
  })
}

export function useSetupTOTP() {
  return useMutation({ mutationFn: () => setupTOTP() })
}

export function useVerifyTOTP() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ code, disable }: { code: string; disable?: boolean }) =>
      verifyTOTP(code, disable),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['auth-me'] })
    },
  })
}

export function useSSOConfig() {
  return useQuery({
    queryKey: ['sso'],
    queryFn: fetchSSO,
    retry: false,
  })
}

export function useSaveSSO() {
  const qc = useQueryClient()
  const [saveError, setSaveError] = useState<string | null>(null)
  const mutation = useMutation({
    mutationFn: (update: SSOConfigUpdate) => saveSSO(update),
    onSuccess: () => {
      setSaveError(null)
      void qc.invalidateQueries({ queryKey: ['sso'] })
      // Enabling SSO changes what /auth/me reports on the login screen.
      void qc.invalidateQueries({ queryKey: ['auth-me'] })
    },
    onError: (err: unknown) => {
      setSaveError(err instanceof Error ? err.message : 'Could not save the SSO configuration')
    },
  })
  return { ...mutation, saveError }
}

export function useAPIKeys() {
  return useQuery({
    queryKey: ['api-keys'],
    queryFn: fetchAPIKeys,
    retry: false,
  })
}

export function useCreateAPIKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: CreateAPIKeyRequest) => createAPIKey(req),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['api-keys'] })
      // A minted key is itself an audited control-plane action.
      void qc.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })
}

export function useRevokeAPIKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => revokeAPIKey(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['api-keys'] })
      void qc.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })
}

export function useEnrollmentTokens() {
  return useQuery({
    queryKey: ['enrollment-tokens'],
    queryFn: fetchEnrollmentTokens,
    retry: false,
  })
}

export function useCreateEnrollmentToken() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: CreateEnrollmentTokenRequest) => createEnrollmentToken(req),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['enrollment-tokens'] })
      void qc.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })
}

export function useRevokeEnrollmentToken() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => revokeEnrollmentToken(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['enrollment-tokens'] })
      void qc.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })
}

/**
 * The control-plane audit trail. Refetched on an interval because the console's
 * own actions append to it: an operator who saves a setting should see the
 * resulting audit row appear without reloading.
 */
export function useAuditLogs(params: { action?: string; actor?: string; limit?: number }) {
  return useQuery({
    queryKey: ['audit-logs', params.action ?? '', params.actor ?? '', params.limit ?? 200],
    queryFn: () => fetchAuditLogs(params),
    refetchInterval: 30_000,
    retry: false,
  })
}

/** The org's console identities, for the Security tab's member list. */
export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: fetchUsers,
    retry: false,
  })
}

/** Roles, in display order, with the labels the server also uses. */
export const ROLE_LABELS: Record<Role, string> = {
  admin: 'Administrator',
  operator: 'SRE Operator',
  policy_admin: 'Policy Admin',
  auditor: 'Compliance Auditor',
}

/* -------------------------------------------------------------------------- */
/* Incident post-mortem ("War Room Export")                                   */
/* -------------------------------------------------------------------------- */

/**
 * The incident bundle for one event.
 *
 * Only fetched once the operator asks for it (`enabled`): assembling a report
 * touches the ticket set, the audit trail and the monitoring config, which is
 * far too much work to do speculatively for every event an operator clicks
 * through while triaging. `staleTime: 0` because the surrounding timeline keeps
 * growing during an incident, and a stale window would understate it.
 */
export function usePostMortem(eventId: string | null, window: string, enabled: boolean) {
  return useQuery({
    queryKey: ['post-mortem', eventId ?? '', window],
    queryFn: ({ signal }) => fetchPostMortem(eventId as string, window, signal),
    enabled: enabled && !!eventId,
    staleTime: 0,
    retry: false,
  })
}

/* -------------------------------------------------------------------------- */
/* ITSM change-ticket bridge (Jira & ServiceNow)                              */
/* -------------------------------------------------------------------------- */

/**
 * The change-control verdict for one event, for the Inspector drawer's badge.
 *
 * Distinct from `useComplianceEvents`: that answers "which changes in this
 * window were unauthorised" for a report, while this answers "was *this* change
 * authorised" for the event an operator already has open. The list endpoint
 * cannot serve the second question, because it pages over the timeline and the
 * open event may not be on the page it returns.
 *
 * `staleTime` is short but non-zero: a verdict changes only when a ticket is
 * edited, and the drawer is opened repeatedly while triaging, so refetching it
 * on every mount would be pure noise.
 */
export function useEventCompliance(eventId: string | null) {
  return useQuery({
    queryKey: ['event-compliance', eventId ?? ''],
    queryFn: () => fetchEventCompliance(eventId as string),
    enabled: !!eventId,
    staleTime: 30_000,
    retry: false,
  })
}

export interface ITSMFeed {
  settings: ITSMSettingsView
  tickets: ChangeTicket[]
  /** True when the API is unreachable and the seeded preview set is shown. */
  isFallback: boolean
  isLoading: boolean
  isError: boolean
  isSaving: boolean
  saveError: string | null
  savedAt: number | null
  save: (update: ITSMSettingsUpdate) => void
  addTicket: (ticket: ChangeTicketInput) => void
  removeTicket: (ref: string) => void
  isMutating: boolean
  ticketError: string | null
}

/**
 * The change-ticket bridge: configuration, the mirrored ticket set, and the
 * actions that change either.
 *
 * Falls back to a seeded configuration so the hub renders a complete form on a
 * cold start — the same graceful-degradation rule the rest of the console
 * follows. Saving still reports its real failure, because pretending a save
 * worked on the one screen an auditor configures is worse than an empty form.
 */
export function useITSMIntegration(): ITSMFeed {
  const qc = useQueryClient()
  const [saveError, setSaveError] = useState<string | null>(null)
  const [ticketError, setTicketError] = useState<string | null>(null)
  const [savedAt, setSavedAt] = useState<number | null>(null)

  const query = useQuery({
    queryKey: ['itsm-integration'],
    queryFn: fetchITSM,
    refetchInterval: 60_000,
    retry: false,
  })

  const isFallback = !query.data
  const settings = query.data?.settings ?? FALLBACK_ITSM_SETTINGS
  const tickets = useMemo<ChangeTicket[]>(
    () => query.data?.tickets ?? (isFallback ? FALLBACK_CHANGE_TICKETS : []),
    [query.data, isFallback],
  )

  const invalidate = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ['itsm-integration'] })
    // The verdict is derived per event, so the compliance views must be
    // recomputed whenever a ticket is added or removed.
    void qc.invalidateQueries({ queryKey: ['compliance-events'] })
  }, [qc])

  const saveMut = useMutation({
    mutationFn: (update: ITSMSettingsUpdate) => saveITSM(update),
    onSuccess: () => {
      setSaveError(null)
      setSavedAt(Date.now())
      invalidate()
    },
    onError: (err: unknown) => {
      setSaveError(err instanceof Error ? err.message : 'Could not save the change-ticket bridge')
    },
  })

  const addMut = useMutation({
    mutationFn: (ticket: ChangeTicketInput) => upsertChangeTicket(ticket),
    onSuccess: () => {
      setTicketError(null)
      invalidate()
    },
    onError: (err: unknown) => {
      setTicketError(err instanceof Error ? err.message : 'Could not save this change ticket')
    },
  })

  const removeMut = useMutation({
    mutationFn: (ref: string) => deleteChangeTicket(ref),
    onSuccess: () => {
      setTicketError(null)
      invalidate()
    },
    onError: (err: unknown) => {
      setTicketError(err instanceof Error ? err.message : 'Could not delete this change ticket')
    },
  })

  return {
    settings,
    tickets,
    isFallback,
    isLoading: query.isLoading,
    isError: query.isError,
    isSaving: saveMut.isPending,
    saveError,
    savedAt,
    save: (update) => saveMut.mutate(update),
    addTicket: (ticket) => addMut.mutate(ticket),
    removeTicket: (ref) => removeMut.mutate(ref),
    isMutating: addMut.isPending || removeMut.isPending,
    ticketError,
  }
}

export interface ComplianceFeed {
  events: ComplianceEvent[]
  /** True when the API returned nothing and the seeded set is shown. */
  isFallback: boolean
  /** False when enforcement is off: verdicts are advisory, not actionable. */
  enforced: boolean
  /** Count per verdict in the current result set. */
  counts: Record<Compliance, number>
  isLoading: boolean
  isError: boolean
}

/**
 * Events annotated with their change-control verdict, for the Reports page's
 * compliance view.
 *
 * This is the endpoint an auditor's filter actually needs, and it is separate
 * from the timeline: computing a verdict per event needs the org's whole ticket
 * set and the enforcement posture, which is far more work than the plain
 * timeline should ever do per request.
 *
 * An empty response stays empty — a fresh deployment has no changes to audit,
 * and showing fabricated verdicts on a compliance report is worse than showing
 * nothing.
 */
export function useComplianceEvents(
  filters: EventFilters & { compliance?: Compliance | '' },
): ComplianceFeed {
  const query = useQuery({
    queryKey: ['compliance-events', filters],
    queryFn: () => fetchComplianceEvents(filters),
    refetchInterval: 30_000,
    retry: false,
  })

  const live = useMemo(
    () => (query.data?.events ?? []).filter((e): e is ComplianceEvent => Boolean(e?.id)),
    [query.data],
  )
  const isFallback = live.length === 0 && sampleDataEnabled() && !query.isLoading
  const events = isFallback ? fallbackComplianceEvents(filters) : live

  const counts = useMemo(() => {
    const out: Record<Compliance, number> = {
      approved: 0,
      unapproved: 0,
      expired: 0,
      not_required: 0,
    }
    for (const e of events) {
      if (e.compliance in out) out[e.compliance] += 1
    }
    return out
  }, [events])

  return {
    events,
    isFallback,
    enforced: query.data?.enforced ?? FALLBACK_ITSM_SETTINGS.enforcement !== 'off',
    counts,
    isLoading: query.isLoading,
    isError: query.isError,
  }
}

/* -------------------------------------------------------------------------- */
/* Pluggable AI provider gateway                                              */
/* -------------------------------------------------------------------------- */

export interface AIAnalysisFeed {
  /** The engine's answer, or null before the first click. */
  analysis: Analysis | null
  isAnalyzing: boolean
  error: string | null
  run: () => void
  reset: () => void
}

/**
 * Runs the AI gateway against one event on demand.
 *
 * Deliberately *not* a cached query: an analysis may call out to a model, so
 * firing it for every event an operator clicks through while triaging would
 * spend money and add latency to every drawer open. The operator asks for it
 * with the "✦ Analyze & Rollback" action, and the result lives only as long as
 * the drawer is open on that event — a new event starts from a clean slate,
 * which also stops a stale answer being read against the wrong change.
 */
export function useEventAnalysis(eventId: string | null): AIAnalysisFeed {
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [error, setError] = useState<string | null>(null)

  // The result belongs to one event: retargeting the drawer must clear it.
  useEffect(() => {
    setAnalysis(null)
    setError(null)
  }, [eventId])

  const mutation = useMutation({
    mutationFn: () => analyzeEvent(eventId as string),
    onSuccess: (res) => {
      setError(null)
      setAnalysis(res)
    },
    onError: (err: unknown) => {
      setAnalysis(null)
      setError(err instanceof Error ? err.message : 'The analyzer could not be reached')
    },
  })

  return {
    analysis,
    isAnalyzing: mutation.isPending,
    error,
    run: () => mutation.mutate(),
    reset: () => {
      setAnalysis(null)
      setError(null)
    },
  }
}

export interface AIFeed {
  settings: AISettingsResponse
  /** True when the API is unreachable and the seeded preview set is shown. */
  isFallback: boolean
  isLoading: boolean
  isError: boolean
  save: (update: AISettingsUpdate) => void
  test: () => void
  /** Result of the most recent test, kept in memory for the badge. */
  testResult: AITestResponse | null
  isSaving: boolean
  isTesting: boolean
  saveError: string | null
  savedAt: number | null
}

/**
 * The AI gateway configuration, its save action and its live connectivity test.
 *
 * Falls back to a seeded configuration when the API is unreachable, so the hub
 * renders a complete form on a cold start — the same graceful-degradation rule
 * the rest of the console follows. Saving and testing still report their real
 * failures, because pretending a save worked is worse than an empty form.
 */
export function useAIIntegration(): AIFeed {
  const qc = useQueryClient()
  const [testResult, setTestResult] = useState<AITestResponse | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [savedAt, setSavedAt] = useState<number | null>(null)

  const query = useQuery({
    queryKey: ['ai-integration'],
    queryFn: fetchAIIntegration,
    refetchInterval: 60_000,
    retry: false,
  })

  const settings = query.data ?? FALLBACK_AI_SETTINGS

  const saveMut = useMutation({
    mutationFn: (update: AISettingsUpdate) => saveAIIntegration(update),
    onSuccess: () => {
      setSaveError(null)
      setSavedAt(Date.now())
      // The endpoint or provider may have changed, which invalidates the stored
      // test result server-side; refetch rather than trust the local copy.
      setTestResult(null)
      void qc.invalidateQueries({ queryKey: ['ai-integration'] })
    },
    onError: (err: unknown) => {
      setSaveError(err instanceof Error ? err.message : 'Could not save the AI configuration')
    },
  })

  const testMut = useMutation({
    mutationFn: () => testAIIntegration(),
    onSuccess: (res) => {
      setTestResult(res)
      void qc.invalidateQueries({ queryKey: ['ai-integration'] })
    },
    onError: (err: unknown) => {
      // A 502 carries the upstream provider's failure; surface it verbatim so
      // an operator can tell a bad URL from a rejected key.
      setTestResult({
        ok: false,
        provider: settings.provider,
        endpoint: settings.effective_endpoint,
        model: settings.effective_model,
        detail: err instanceof Error ? err.message : 'The AI connectivity test failed',
        latency_ms: 0,
        checked_at: new Date().toISOString(),
      })
    },
  })

  return {
    settings,
    isFallback: !query.data,
    isLoading: query.isLoading,
    isError: query.isError,
    save: (update) => saveMut.mutate(update),
    test: () => testMut.mutate(),
    testResult,
    isSaving: saveMut.isPending,
    isTesting: testMut.isPending,
    saveError,
    savedAt,
  }
}

/* -------------------------------------------------------------------------- */
/* Custom watched targets (the console's rule builder)                        */
/* -------------------------------------------------------------------------- */

export interface WatchRulesFeed {
  rules: WatchRule[]
  /** The server's catalog, or the built-in fallback while the API is cold. */
  targetTypes: WatchTargetType[]
  impactLevels: WatchImpactLevel[]
  defaultLevel: number
  count: number
  critical: number
  byType: Record<string, number>
  /** True when the API is unreachable and seeded rules are shown instead. */
  isFallback: boolean
  isLoading: boolean
  isError: boolean
  isCreating: boolean
  isDeleting: boolean
  /** Last create/delete failure, verbatim, so a bad pattern is fixable. */
  mutationError: string | null
  /**
   * Creates a target. `onSuccess` runs only when the server accepted it, so a
   * validation failure leaves the builder open with the server's message
   * rather than closing a form that did not save.
   */
  create: (input: WatchRuleInput, onSuccess?: () => void) => void
  remove: (id: string, onSuccess?: () => void) => void
  clearError: () => void
}

/**
 * The custom watched targets and the actions that change them.
 *
 * Seeded rules are shown only when the API is unreachable, and the caller is
 * expected to label them as preview data: a watched target that looks real but
 * was never pushed to an agent is exactly the confusion this feature must not
 * create. A *successful* empty response is honoured as empty for that reason.
 */
export function useWatchRules(): WatchRulesFeed {
  const qc = useQueryClient()
  const [mutationError, setMutationError] = useState<string | null>(null)

  const query = useQuery({
    queryKey: ['watch-rules'],
    queryFn: () => fetchWatchRules(),
    refetchInterval: 30_000,
    retry: false,
  })

  // Only an unreachable API (not an empty result) triggers the seeded set.
  const isFallback = query.isError && !query.data
  const rules = useMemo<WatchRule[]>(() => {
    if (query.data) return query.data.rules ?? []
    return isFallback ? FALLBACK_WATCH_RULES : []
  }, [query.data, isFallback])

  const invalidate = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ['watch-rules'] })
  }, [qc])

  const createMut = useMutation({
    mutationFn: ({ input }: { input: WatchRuleInput; onSuccess?: () => void }) =>
      createWatchRule(input),
    onSuccess: (_rule, vars) => {
      setMutationError(null)
      invalidate()
      vars.onSuccess?.()
    },
    onError: (err: unknown) => {
      setMutationError(err instanceof Error ? err.message : 'Could not create the watched target')
    },
  })

  const removeMut = useMutation({
    mutationFn: ({ id }: { id: string; onSuccess?: () => void }) => deleteWatchRule(id),
    onSuccess: (_res, vars) => {
      setMutationError(null)
      invalidate()
      vars.onSuccess?.()
    },
    onError: (err: unknown) => {
      setMutationError(err instanceof Error ? err.message : 'Could not remove the watched target')
    },
  })

  const byType = useMemo(() => {
    if (query.data?.by_type) return query.data.by_type
    const out: Record<string, number> = {}
    for (const r of rules) out[r.target_type] = (out[r.target_type] ?? 0) + 1
    return out
  }, [query.data, rules])

  return {
    rules,
    targetTypes: query.data?.target_types ?? FALLBACK_WATCH_TARGET_TYPES,
    impactLevels: query.data?.impact_levels ?? FALLBACK_WATCH_IMPACT_LEVELS,
    defaultLevel: query.data?.default_level ?? 1,
    count: query.data?.count ?? rules.length,
    critical: query.data?.critical ?? rules.filter((r) => r.level === 1).length,
    byType,
    isFallback,
    isLoading: query.isLoading,
    isError: query.isError && !isFallback,
    isCreating: createMut.isPending,
    isDeleting: removeMut.isPending,
    mutationError,
    create: (input, onSuccess) => createMut.mutate({ input, onSuccess }),
    remove: (id, onSuccess) => removeMut.mutate({ id, onSuccess }),
    clearError: () => setMutationError(null),
  }
}
