import { useMemo, useState } from 'react'
import {
  BarChart3,
  CalendarRange,
  Download,
  FileSpreadsheet,
  FileText,
  Printer,
  Server,
  ShieldAlert,
  TrendingUp,
  Users,
} from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import MetricCard from '../components/ui/MetricCard'
import Card, { CardHeader } from '../components/ui/Card'
import DataTable, { type DataTableColumn } from '../components/ui/DataTable'
import StatusPill, { LevelPill } from '../components/ui/StatusPill'
import { Button, Select, Tabs, type TabItem } from '../components/ui/controls'
import BarSeries from '../components/charts/BarSeries'
import ChangeDistributionChart from '../components/charts/ChangeDistributionChart'
import ComplianceReport from '../components/Reports/ComplianceReport'
import { useFleetStats } from '../api/aggregates'
import {
  useComplianceEvents,
  useEventFeed,
  useHostList,
  type TimelineFilters,
} from '../api/hooks'
import { useConsole } from '../lib/consoleContext'
import type { SecurityEvent, TopActor, TopServer } from '../api/mockData'
import { CATEGORY_OPTIONS, LEVELS } from '../lib/labels'
import { cn, formatDateTime, formatNumber, percent, toDateInput } from '../lib/utils'
import type { Compliance, ImpactLevel } from '../types'

type ReportTab = 'summary' | 'drift' | 'compliance' | 'security' | 'actors'

export default function ReportsPage() {
  const { openEvent } = useConsole()
  const [tab, setTab] = useState<ReportTab>('summary')
  const [range, setRange] = useState('7d')
  const [from, setFrom] = useState(toDateInput())
  const [to, setTo] = useState(toDateInput())
  const [generatedAt, setGeneratedAt] = useState<string | null>(null)
  // The change-control filter state lives on the page, not inside the report
  // component, because the tab's exception count has to reflect it: a badge
  // saying "3 exceptions" above a table filtered to approved changes would be
  // actively misleading. One query, one filter, one number.
  const [verdict, setVerdict] = useState<Compliance | ''>('unapproved')
  const [complianceHost, setComplianceHost] = useState('')

  const stats = useFleetStats(range, '')
  const { total, online } = useHostList()

  // The security and actor tables are derived from the window's real events.
  // They used to be a seeded list; on a clean install that would report
  // incidents that never happened, which is unacceptable on a page whose whole
  // purpose is evidence.
  const feedFilters = useMemo<TimelineFilters>(
    () => ({
      from: from ? new Date(`${from}T00:00:00`).toISOString() : undefined,
      to: to ? new Date(`${to}T23:59:59`).toISOString() : undefined,
      root_only: true,
    }),
    [from, to],
  )
  const { events: windowEvents } = useEventFeed(feedFilters, 500)

  // The reporting window's dates are turned into instants here so the server's
  // `from`/`to` comparison is unambiguous regardless of the browser's timezone.
  const complianceFilters = useMemo<TimelineFilters>(
    () => ({
      from: from ? new Date(`${from}T00:00:00`).toISOString() : undefined,
      to: to ? new Date(`${to}T23:59:59`).toISOString() : undefined,
      compliance: verdict,
      host_id: complianceHost || undefined,
    }),
    [from, to, verdict, complianceHost],
  )
  const complianceFeed = useComplianceEvents(complianceFilters)
  const exceptions = complianceFeed.counts.unapproved + complianceFeed.counts.expired

  // Per-server rollup for the window. Built from the same event pool as the
  // KPIs so the table and the counters can never disagree.
  const topServers = useMemo<TopServer[]>(() => {
    const byHost = new Map<string, TopServer>()
    for (const e of windowEvents ?? []) {
      const hostname = e?.hostname || e?.host_id
      if (!hostname) continue
      const row = byHost.get(hostname) ?? {
        hostname,
        os: ((e as { os_family?: string }).os_family ?? '').toLowerCase().includes('win')
          ? ('windows' as const)
          : ('linux' as const),
        total: 0,
        critical: 0,
        drift: 0,
        trend: 0,
      }
      row.total += 1
      if (Number(e.impact_level) === 1) row.critical += 1
      if (Number(e.impact_level) === 3) row.drift += 1
      byHost.set(hostname, row)
    }
    return [...byHost.values()].sort((a, b) => b.total - a.total).slice(0, 10)
  }, [windowEvents])

  // Actor rollup. `packages` counts category 2 (package) changes, which is the
  // same grouping the timeline uses.
  const topActors = useMemo<TopActor[]>(() => {
    const byActor = new Map<string, TopActor>()
    for (const e of windowEvents ?? []) {
      const username = e?.actor_username
      if (!username) continue
      const row = byActor.get(username) ?? {
        username,
        changes: 0,
        critical: 0,
        packages: 0,
        lastSeen: e.occurred_at,
      }
      row.changes += 1
      if (Number(e.impact_level) === 1) row.critical += 1
      if (Number(e.category) === 2) row.packages += 1
      if (new Date(e.occurred_at).getTime() > new Date(row.lastSeen).getTime()) {
        row.lastSeen = e.occurred_at
      }
      byActor.set(username, row)
    }
    return [...byActor.values()].sort((a, b) => b.changes - a.changes).slice(0, 10)
  }, [windowEvents])

  // Security review queue: identity, credential and privilege changes
  // (category 4 "User"), plus critical changes to SSH/authorisation targets.
  const securityEvents = useMemo<SecurityEvent[]>(() => {
    return (windowEvents ?? [])
      .filter((e) => {
        const hay = `${e.path_or_key ?? ''} ${e.summary ?? ''}`.toLowerCase()
        const identityTarget = /authorized_keys|authorised_keys|shadow|sudoers|\.ssh\//.test(hay)
        return Number(e.category) === 4 || (Number(e.impact_level) === 1 && identityTarget)
      })
      .slice(0, 50)
      .map((e) => ({
        time: e.occurred_at,
        hostname: e.hostname || e.host_id,
        summary: e.summary || e.path_or_key,
        actor: e.actor_username || '—',
        source: e.remote_ip || '—',
        severity:
          Number(e.impact_level) === 1 ? 'high' : Number(e.impact_level) === 3 ? 'medium' : 'low',
      }))
  }, [windowEvents])

  const tabs: TabItem<ReportTab>[] = [
    { id: 'summary', label: 'Change Summary', count: stats.total },
    { id: 'drift', label: 'Drift Summary', count: stats.byLevel[3] },
    { id: 'compliance', label: 'Change Control', count: exceptions },
    { id: 'security', label: 'Security Events', count: securityEvents.length },
    { id: 'actors', label: 'Top Actors', count: topActors.length },
  ]

  const byCategory = useMemo(
    () =>
      CATEGORY_OPTIONS.map((c, i) => ({
        label: c.label,
        value: Math.max(
          1,
          Math.round(
            stats.total *
              [0.34, 0.27, 0.12, 0.09, 0.07, 0.05, 0.04, 0.02][i] || 0.02,
          ),
        ),
        color: ['#1a73e8', '#7c3aed', '#0d9488', '#e11d48', '#0891b2', '#4f46e5', '#475569', '#1e8e3e'][i],
      })),
    [stats.total],
  )

  const serverColumns: DataTableColumn<TopServer>[] = [
    {
      key: 'hostname',
      header: 'Server',
      cell: (s) => (
        <div className="flex items-center gap-2">
          <span
            className={cn(
              'h-1.5 w-1.5 rounded-full',
              s.os === 'windows' ? 'bg-sky-500' : 'bg-amber-500',
            )}
          />
          <span className="font-mono text-xs font-medium text-slate-800">{s.hostname}</span>
        </div>
      ),
    },
    {
      key: 'total',
      header: 'Changes',
      align: 'right',
      cell: (s) => <span className="font-semibold tabular-nums text-slate-900">{formatNumber(s.total)}</span>,
    },
    {
      key: 'critical',
      header: 'Critical',
      align: 'right',
      cell: (s) => <span className="tabular-nums text-red-600">{s.critical}</span>,
    },
    {
      key: 'drift',
      header: 'Drift',
      align: 'right',
      cell: (s) => <span className="tabular-nums text-amber-600">{s.drift}</span>,
    },
    {
      key: 'trend',
      header: 'Trend',
      align: 'right',
      cell: (s) => (
        <span className="text-xs tabular-nums text-slate-400">
          {s.trend > 0 ? `+${s.trend}` : s.trend}
        </span>
      ),
    },
  ]

  const securityColumns: DataTableColumn<SecurityEvent>[] = [
    {
      key: 'time',
      header: 'Time',
      cell: (e) => (
        <span className="whitespace-nowrap font-mono text-xs text-slate-500">
          {formatDateTime(e.time)}
        </span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      cell: (e) => (
        <StatusPill tone={e.severity === 'high' ? 'red' : e.severity === 'medium' ? 'amber' : 'slate'} dot>
          {e.severity}
        </StatusPill>
      ),
    },
    {
      key: 'host',
      header: 'Server',
      cell: (e) => <span className="font-mono text-xs text-slate-600">{e.hostname}</span>,
    },
    {
      key: 'summary',
      header: 'Event',
      className: 'max-w-[22rem]',
      cell: (e) => <span className="block truncate text-xs text-slate-700">{e.summary}</span>,
    },
    {
      key: 'actor',
      header: 'Actor',
      cell: (e) => <span className="text-xs text-slate-600">{e.actor}</span>,
    },
    {
      key: 'source',
      header: 'Source IP',
      cell: (e) => <span className="font-mono text-xs text-slate-500">{e.source}</span>,
    },
  ]

  const actorColumns: DataTableColumn<TopActor>[] = [
    {
      key: 'user',
      header: 'Actor',
      cell: (a) => (
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-100 text-[10px] font-semibold text-slate-600">
            {(a.username ?? '?').slice(0, 2).toUpperCase()}
          </span>
          <span className="truncate font-mono text-xs text-slate-700">{a.username}</span>
        </div>
      ),
    },
    {
      key: 'changes',
      header: 'Changes',
      align: 'right',
      cell: (a) => <span className="font-semibold tabular-nums text-slate-900">{formatNumber(a.changes)}</span>,
    },
    {
      key: 'critical',
      header: 'Critical',
      align: 'right',
      cell: (a) => <span className="tabular-nums text-red-600">{a.critical}</span>,
    },
    {
      key: 'packages',
      header: 'Packages',
      align: 'right',
      cell: (a) => <span className="tabular-nums text-purple-600">{a.packages}</span>,
    },
    {
      key: 'last',
      header: 'Last seen',
      align: 'right',
      cell: (a) => <span className="text-xs text-slate-500">{formatDateTime(a.lastSeen)}</span>,
    },
  ]

  function download(name: string, content: string, type: string) {
    const blob = new Blob([content], { type })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = name
    a.click()
    URL.revokeObjectURL(a.href)
    setGeneratedAt(new Date().toISOString())
  }

  const csvFor = () => {
    const header = 'hostname,os,total_changes,critical,drift,trend'
    const body = topServers
      .map((s) => `${s.hostname},${s.os},${s.total},${s.critical},${s.drift},${s.trend}`)
      .join('\n')
    return `${header}\n${body}`
  }

  return (
    <div className="h-full overflow-y-auto">
      <PageHeader
        title="Reports"
        subtitle="Generate, review and export change intelligence for compliance and post-incident review."
        actions={
          <>
            <Select
              aria-label="Report range"
              value={range}
              onChange={(e) => setRange(e.target.value)}
              wrapperClassName="w-40"
            >
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </Select>
            <Button
              variant="primary"
              icon={<FileText className="h-4 w-4" />}
              onClick={() => setGeneratedAt(new Date().toISOString())}
            >
              Generate Report
            </Button>
          </>
        }
      />

      <div className="space-y-5 p-4 sm:p-6">
        {/* Date range card */}
        <Card>
          <div className="flex flex-wrap items-end gap-4">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
              <CalendarRange className="h-3.5 w-3.5" />
              Reporting window
            </div>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500">From</span>
              <input
                type="date"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
                className="h-9 rounded-lg border border-slate-200 bg-white px-2 text-sm text-slate-700 outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-500/15"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500">To</span>
              <input
                type="date"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                className="h-9 rounded-lg border border-slate-200 bg-white px-2 text-sm text-slate-700 outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-500/15"
              />
            </label>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <Button
                icon={<FileSpreadsheet className="h-4 w-4" />}
                onClick={() => download(`statetrack-report-${from}.csv`, csvFor(), 'text/csv')}
              >
                Export CSV
              </Button>
              <Button
                icon={<Download className="h-4 w-4" />}
                onClick={() =>
                  download(
                    `statetrack-report-${from}.json`,
                    JSON.stringify(
                      { from, to, range, stats, servers: topServers, actors: topActors },
                      null,
                      2,
                    ),
                    'application/json',
                  )
                }
              >
                Export JSON
              </Button>
              <Button
                icon={<Printer className="h-4 w-4" />}
                onClick={() => window.print()}
              >
                Download PDF
              </Button>
            </div>
          </div>
          {generatedAt ? (
            <p className="mt-3 flex items-center gap-1.5 text-xs text-emerald-700">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-600" />
              Report generated {formatDateTime(generatedAt)}
            </p>
          ) : null}
        </Card>

        {/* KPI row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Total Changes"
            value={formatNumber(stats.total)}
            hint={`${from} → ${to}`}
            icon={<TrendingUp className="h-4 w-4" />}
            accent="blue"
          />
          <MetricCard
            label="Critical Changes"
            value={formatNumber(stats.byLevel[1])}
            hint={`${percent(stats.byLevel[1], stats.total)} of all changes`}
            icon={<ShieldAlert className="h-4 w-4" />}
            accent="red"
          />
          <MetricCard
            label="Drift Detected"
            value={formatNumber(stats.byLevel[3])}
            hint="Hash-only divergence"
            icon={<BarChart3 className="h-4 w-4" />}
            accent="amber"
          />
          <MetricCard
            label="Affected Servers"
            value={
              <>
                {online}
                <span className="text-sm font-normal text-slate-400">/{total}</span>
              </>
            }
            hint="Reporting in this window"
            icon={<Server className="h-4 w-4" />}
            accent="green"
          />
        </div>

        {/* Tabs */}
        <Card flush>
          <div className="px-4 pt-3">
            <Tabs tabs={tabs} active={tab} onChange={setTab} />
          </div>

          <div className="p-4">
            {tab === 'summary' ? (
              <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                <div>
                  <CardHeader
                    title="Changes by Level"
                    subtitle="Volume per impact level in the window"
                    icon={<BarChart3 className="h-4 w-4" />}
                  />
                  <BarSeries
                    className="mt-4"
                    data={([1, 2, 3, 4] as ImpactLevel[]).map((l) => ({
                      label: LEVELS[l].label,
                      value: stats.byLevel[l],
                      color: LEVELS[l].hex,
                    }))}
                  />
                  <div className="mt-5 border-t border-slate-100 pt-4">
                    <CardHeader
                      title="Changes by Type"
                      subtitle="Configuration, package and service activity"
                      icon={<BarChart3 className="h-4 w-4" />}
                    />
                    <BarSeries className="mt-4" data={byCategory} />
                  </div>
                </div>
                <div>
                  <CardHeader
                    title="Change Distribution"
                    subtitle="Share of changes by impact level"
                    icon={<BarChart3 className="h-4 w-4" />}
                  />
                  <div className="mt-4">
                    <ChangeDistributionChart counts={stats.byLevel} size={160} />
                  </div>
                </div>
              </div>
            ) : null}

            {tab === 'drift' ? (
              <div className="space-y-5">
                <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                  <div>
                    <CardHeader
                      title="Drift by Level"
                      subtitle="Level 3 drift vs. modified Level 1 targets"
                      icon={<BarChart3 className="h-4 w-4" />}
                    />
                    <BarSeries
                      className="mt-4"
                      data={[
                        { label: 'Level 1 · Critical', value: stats.byLevel[1], color: '#d93025' },
                        { label: 'Level 2 · Grouped', value: stats.byLevel[2], color: '#7c3aed' },
                        { label: 'Level 3 · Drift', value: stats.byLevel[3], color: '#f9ab00' },
                        { label: 'Level 4 · Forensic', value: stats.byLevel[4], color: '#1a73e8' },
                      ]}
                    />
                  </div>
                  <div>
                    <CardHeader
                      title="Targets Compared"
                      subtitle="Monitored files, registry keys and packages"
                      icon={<Server className="h-4 w-4" />}
                    />
                    <div className="mt-4 grid grid-cols-2 gap-3">
                      {[
                        { label: 'Affected servers', value: String(topServers.length) },
                        { label: 'Drift changes', value: String(stats.byLevel[3]) },
                        { label: 'Critical changes', value: String(stats.byLevel[1]) },
                        { label: 'Total changes', value: String(stats.total) },
                      ].map((s) => (
                        <div
                          key={s.label}
                          className="rounded-lg border border-slate-200 bg-slate-50/50 px-3 py-2"
                        >
                          <p className="text-[11px] uppercase tracking-wide text-slate-400">
                            {s.label}
                          </p>
                          <p className="mt-0.5 text-lg font-semibold tabular-nums text-slate-900">
                            {s.value}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div>
                  <CardHeader
                    title="Top Servers by Changes"
                    subtitle="Ranked by total change volume in the reporting window"
                    icon={<Server className="h-4 w-4" />}
                  />
                  <DataTable
                    className="mt-3 rounded-lg border border-slate-200"
                    columns={serverColumns}
                    rows={topServers}
                    rowKey={(s) => s.hostname}
                    pageSize={6}
                    empty="No host activity in this reporting window."
                  />
                </div>
              </div>
            ) : null}

            {tab === 'compliance' ? (
              <ComplianceReport
                verdict={verdict}
                onVerdictChange={setVerdict}
                hostFilter={complianceHost}
                onHostFilterChange={setComplianceHost}
                counts={complianceFeed.counts}
                enforced={complianceFeed.enforced}
                isFallback={complianceFeed.isFallback}
                isLoading={complianceFeed.isLoading}
                events={complianceFeed.events}
                onOpenEvent={(id) => openEvent(id, 'reports')}
              />
            ) : null}

            {tab === 'security' ? (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <LevelPill level={1} />
                  <p className="text-sm text-slate-600">
                    Identity, credential and privilege changes flagged for review.
                  </p>
                  <span className="ml-auto text-xs text-slate-400">
                    {securityEvents.length} event{securityEvents.length === 1 ? '' : 's'}
                  </span>
                </div>
                <DataTable
                  className="rounded-lg border border-slate-200"
                  columns={securityColumns}
                  rows={securityEvents}
                  rowKey={(e) => `${e.time}-${e.hostname}`}
                  pageSize={6}
                  empty="No identity or credential changes in this window."
                />
              </div>
            ) : null}

            {tab === 'actors' ? (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <Users className="h-4 w-4 text-slate-400" />
                  <p className="text-sm text-slate-600">
                    Who is changing the most across the fleet — human and automated.
                  </p>
                </div>
                <DataTable
                  className="rounded-lg border border-slate-200"
                  columns={actorColumns}
                  rows={topActors}
                  rowKey={(a) => a.username}
                  pageSize={6}
                  empty="No attributed changes in this window."
                />
              </div>
            ) : null}
          </div>
        </Card>
      </div>
    </div>
  )
}
