import { useMemo, useState } from 'react'
import {
  Cpu,
  MoreHorizontal,
  Plus,
  Power,
  PowerOff,
  Radio,
  Search,
  Server as ServerIcon,
} from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import MetricCard from '../components/ui/MetricCard'
import Card from '../components/ui/Card'
import DataTable, { type DataTableColumn } from '../components/ui/DataTable'
import StatusPill, { StatusDot } from '../components/ui/StatusPill'
import { Button, IconButton, Select, TextInput } from '../components/ui/controls'
import { useEnableForensic, useHostList, useRecommendations } from '../api/hooks'
import { useReadOnly } from '../lib/authContext'
import RecommendationBanner from '../components/Recommendations/RecommendationBanner'
import RecommendationsDrawer from '../components/Recommendations/RecommendationsDrawer'
import WatchedTargetsCard from '../components/Watchers/WatchedTargetsCard'
import { useConsole } from '../lib/consoleContext'
import { cn, timeAgo } from '../lib/utils'
import type { Host } from '../types'

/** Linux penguin / Windows flag glyph used in the server name column. */
function OSGlyph({ os }: { os: string }) {
  const windows = (os ?? '').toLowerCase().includes('win')
  return (
    <span
      className={cn(
        'flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-[13px] font-bold',
        windows ? 'bg-sky-50 text-sky-600' : 'bg-amber-50 text-amber-700',
      )}
      title={windows ? 'Windows' : 'Linux'}
    >
      {windows ? (
        <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" aria-hidden>
          <path
            fill="currentColor"
            d="M3 5.5 10.2 4.5v7.1H3V5.5Zm0 13 7.2 1v-7h-7.2v6Zm8.4 1.2L21.5 21V12.4h-10.1v7.3Zm0-15.4v7.3h10.1V3l-10.1 1.3Z"
          />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" aria-hidden>
          <path
            fill="currentColor"
            d="M12 2c1.7 2 2.6 3.6 2.6 5.1 0 1-.3 1.7-1 2.4-.6.6-.9 1.3-.9 2 0 .9.5 1.6 1.4 2.3.3.2.4.5.4.9 0 .6-.3 1.1-.9 1.5-.6.4-1 1-1.2 1.9l-.4 2.9c-2-1.2-3-2.7-3-4.4 0-1 .2-2 .7-2.9-.9-.1-1.8-.6-2.6-1.4C5.5 10.7 5 8.2 5.6 4.6 7 6 8.2 6.9 9.2 7.3 9.7 5.2 10.6 3.4 12 2Z"
          />
        </svg>
      )}
    </span>
  )
}

export default function ServersPage() {
  const { hosts, total, online, offline, isLive } = useHostList()
  const { hostId, setHostId, goTo } = useConsole()
  const forensic = useEnableForensic()
  const readOnly = useReadOnly()

  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [os, setOs] = useState('all')
  const [page, setPage] = useState(1)

  // Recommendations are scoped to the server the operator reacted from, so
  // the drawer opens pre-filtered when triggered from a table row.
  const [recHost, setRecHost] = useState('')
  const [showRecommendations, setShowRecommendations] = useState(false)
  const recommendations = useRecommendations('pending')

  const openRecommendations = (hostname = '') => {
    setRecHost(hostname)
    setShowRecommendations(true)
  }

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (hosts ?? []).filter((h) => {
      if (status !== 'all' && h?.status !== status) return false
      if (os === 'linux' && !(h?.os_family ?? '').toLowerCase().includes('linux')) return false
      if (os === 'windows' && !(h?.os_family ?? '').toLowerCase().includes('win')) return false
      if (q) {
        const hay = `${h?.hostname ?? ''} ${h?.os_version ?? ''} ${h?.id ?? ''}`.toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [hosts, query, status, os])

  const columns = useMemo<DataTableColumn<Host>[]>(
    () => [
      {
        key: 'name',
        header: 'Name',
        cell: (h) => (
          <div className="flex items-center gap-2.5">
            <OSGlyph os={h.os_family} />
            <div className="min-w-0">
              <button
                onClick={() => {
                  setHostId(h.id)
                  goTo('timeline')
                }}
                className="block truncate font-mono text-sm font-medium text-slate-800 hover:text-blue-700"
              >
                {h.hostname}
              </button>
              <span className="block truncate text-[11px] text-slate-400">{h.id.slice(0, 8)}</span>
            </div>
          </div>
        ),
      },
      {
        key: 'ip',
        header: 'IP Address',
        cell: () => <span className="font-mono text-xs text-slate-500">—</span>,
      },
      {
        key: 'os',
        header: 'OS',
        cell: (h) => (
          <div className="min-w-0">
            <span className="block truncate text-xs text-slate-700">{h.os_version || 'Unknown'}</span>
            <span className="block text-[11px] capitalize text-slate-400">{h.os_family}</span>
          </div>
        ),
      },
      {
        key: 'agent',
        header: 'Agent Version',
        cell: (h) => (
          <StatusPill tone="slate" mono>
            {h.agent_version || '—'}
          </StatusPill>
        ),
      },
      {
        key: 'status',
        header: 'Status',
        cell: (h) => <StatusDot online={h.status === 'online'} />,
      },
      {
        key: 'recommendations',
        header: 'Recommendations',
        cell: (h) => {
          const count = recommendations.byHost[h.hostname] ?? 0
          if (!count) {
            return <span className="text-xs text-slate-300">—</span>
          }
          return (
            <button
              onClick={(e) => {
                e.stopPropagation()
                openRecommendations(h.hostname)
              }}
              className="inline-flex items-center gap-1.5 rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-xs font-medium text-blue-700 transition-colors hover:bg-blue-100"
              title={`Review ${count} discovered workload rule(s) for ${h.hostname}`}
            >
              💡 {count} suggested
            </button>
          )
        },
      },
      {
        key: 'seen',
        header: 'Last Seen',
        cell: (h) => (
          <span className="text-xs text-slate-500" title={h.last_seen_at}>
            {h.status === 'online' ? timeAgo(h.last_seen_at) : '—'}
          </span>
        ),
      },
      {
        key: 'actions',
        header: '',
        align: 'right',
        cell: (h) => (
          <div className="flex items-center justify-end gap-1">
            <IconButton
              label={
                readOnly
                  ? 'Read-only session — cannot start forensic capture'
                  : `Start forensic capture on ${h.hostname}`
              }
              disabled={readOnly}
              onClick={(e) => {
                e.stopPropagation()
                forensic.mutate(h.id)
              }}
            >
              <Radio className="h-3.5 w-3.5" />
            </IconButton>
            <IconButton
              label={`Open timeline for ${h.hostname}`}
              onClick={(e) => {
                e.stopPropagation()
                setHostId(h.id)
                goTo('timeline')
              }}
            >
              <MoreHorizontal className="h-3.5 w-3.5" />
            </IconButton>
          </div>
        ),
      },
    ],
    [forensic, goTo, setHostId, recommendations.byHost, readOnly],
  )

  return (
    <div className="h-full overflow-y-auto">
      <PageHeader
        title="Servers"
        subtitle="Manage and monitor all connected servers and agents"
        actions={
          <>
            <TextInput
              value={query}
              onChange={(e) => {
                setQuery(e.target.value)
                setPage(1)
              }}
              placeholder="Search servers…"
              icon={<Search className="h-4 w-4" />}
              wrapperClassName="w-56"
              aria-label="Search servers"
            />
            <Button variant="primary" icon={<Plus className="h-4 w-4" />}>
              Add Server
            </Button>
          </>
        }
      />

      <div className="space-y-5 p-4 sm:p-6">
        <RecommendationBanner
          pending={recommendations.pending}
          hostnames={recommendations.hostnames}
          onReview={() => openRecommendations('')}
        />

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Total Servers"
            value={total}
            hint="Enrolled hosts"
            icon={<ServerIcon className="h-4 w-4" />}
            accent="blue"
          />
          <MetricCard
            label="Online"
            value={online}
            hint="Heartbeat < 15m"
            icon={<Power className="h-4 w-4" />}
            accent="green"
          />
          <MetricCard
            label="Offline"
            value={offline}
            hint={offline > 0 ? 'Needs attention' : 'All agents reporting'}
            icon={<PowerOff className="h-4 w-4" />}
            accent="red"
          />
          <MetricCard
            label="Agents"
            value={total}
            hint="v0.9.8 – v1.0.0"
            icon={<Cpu className="h-4 w-4" />}
            accent="purple"
          />
        </div>

        <Card flush>
          <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
            <div className="min-w-0 flex-1">
              <h2 className="text-sm font-semibold text-slate-900">Server Inventory</h2>
              <p className="text-xs text-slate-500">
                {isLive
                  ? total === 0
                    ? 'No servers enrolled yet'
                    : `${rows.length} of ${total} servers shown`
                  : 'Showing sample data — this build is not connected to a live server'}
              </p>
            </div>
            <Select
              aria-label="Status filter"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value)
                setPage(1)
              }}
              wrapperClassName="w-36"
            >
              <option value="all">All statuses</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
            </Select>
            <Select
              aria-label="OS filter"
              value={os}
              onChange={(e) => {
                setOs(e.target.value)
                setPage(1)
              }}
              wrapperClassName="w-36"
            >
              <option value="all">All platforms</option>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
            </Select>
            {hostId ? (
              <Button size="sm" onClick={() => setHostId('')}>
                Clear host filter
              </Button>
            ) : null}
          </div>

          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(h) => h.id}
            onRowClick={(h) => setHostId(h.id)}
            pageSize={8}
            page={page}
            onPage={setPage}
            empty={
              total === 0
                ? 'No servers enrolled yet — copy the Linux or Windows install command under Settings → Agents to connect your first host.'
                : 'No servers match the current filters.'
            }
          />
        </Card>

        {/* Custom watched targets. The list lives under the inventory because a
            watched target is always scoped to a host (or the whole fleet), so
            this is where an operator goes after finding the server. */}
        <WatchedTargetsCard />
      </div>

      {showRecommendations ? (
        <RecommendationsDrawer
          feed={recommendations}
          hostFilter={recHost || undefined}
          onClearHostFilter={() => setRecHost('')}
          onClose={() => setShowRecommendations(false)}
        />
      ) : null}
    </div>
  )
}
