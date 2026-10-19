import { Fragment, useMemo, useState } from 'react'
import { useQueries } from '@tanstack/react-query'
import { GitCompare, Layers, RefreshCw, Server, SlidersHorizontal, X } from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import Card, { CardHeader } from '../components/ui/Card'
import { Button, SegmentedControl, Select, TextInput } from '../components/ui/controls'
import { HostPill } from '../components/Timeline/HostPill'
import { fetchDrift } from '../api/client'
import { sampleDataEnabled, useHostList } from '../api/hooks'
import {
  DRIFT_MATRIX_HOSTS,
  FALLBACK_DRIFT_MATRIX,
  type DriftCellStatus,
  type DriftMatrixRow,
} from '../api/mockData'
import { useConsole } from '../lib/consoleContext'
import { cn } from '../lib/utils'

const STATUS_META: Record<
  DriftCellStatus,
  { label: string; chip: string; dot: string }
> = {
  sync: {
    label: 'In sync',
    chip: 'border-emerald-200 bg-emerald-50 text-emerald-700',
    dot: 'bg-emerald-600',
  },
  drift: {
    label: 'Drift',
    chip: 'border-amber-200 bg-amber-50 text-amber-700',
    dot: 'bg-amber-500',
  },
  modified: {
    label: 'Modified',
    chip: 'border-blue-200 bg-blue-50 text-blue-700',
    dot: 'bg-blue-600',
  },
  missing: {
    label: 'Not present',
    chip: 'border-slate-200 bg-slate-50 text-slate-400',
    dot: 'bg-slate-300',
  },
}

function StatusBadge({ status }: { status: DriftCellStatus }) {
  const meta = STATUS_META[status] ?? STATUS_META.missing
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
        meta.chip,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', meta.dot)} />
      {meta.label}
    </span>
  )
}

interface MatrixColumn {
  id: string
  hostname: string
  os: 'linux' | 'windows' | 'kubernetes'
}

/**
 * Cross-host drift matrix.
 *
 * Two sources, one shape. When agents are enrolled the matrix is built from the
 * real pairwise drift endpoint (`GET /api/v1/drift`), compared star-fashion
 * against the first selected host, so every cell is a hash comparison the server
 * actually made. The seeded matrix appears only in an explicit sample-data build
 * (`VITE_STATETRACK_SAMPLE_DATA=1`); a clean deployment shows an enrolment
 * prompt instead of an invented comparison.
 */
export default function DriftPage() {
  const { hosts } = useHostList()
  const { setHostId, goTo } = useConsole()

  const [groupBy, setGroupBy] = useState<'category' | 'type'>('category')
  const [category, setCategory] = useState('all')
  const [level, setLevel] = useState('all')
  const [query, setQuery] = useState('')
  const [compareMode, setCompareMode] = useState<'all' | 'divergent'>('all')
  const [selected, setSelected] = useState<string | null>(null)

  const sample = sampleDataEnabled()

  const columns = useMemo<MatrixColumn[]>(() => {
    const live = (hosts ?? []).filter((h) => h && h.hostname)
    if (live.length > 0) {
      return live.slice(0, 6).map((h) => ({
        id: h.id,
        hostname: h.hostname,
        os: (h.os_family ?? '').toLowerCase().includes('win')
          ? ('windows' as const)
          : ('linux' as const),
      }))
    }
    return sample ? DRIFT_MATRIX_HOSTS : []
  }, [hosts, sample])

  const liveMode = !sample && columns.length >= 2
  const baseline = columns[0]

  // One pairwise query per additional host, compared against the baseline.
  // useQueries (rather than a hook in a loop) keeps the hook order stable as
  // the fleet grows.
  const pairs = useMemo(
    () => (liveMode ? columns.slice(1).map((c) => ({ a: baseline?.id ?? '', b: c.id })) : []),
    [liveMode, columns, baseline],
  )
  const driftQueries = useQueries({
    queries: pairs.map((p) => ({
      queryKey: ['drift', p.a, p.b],
      queryFn: () => fetchDrift(p.a, p.b),
      enabled: Boolean(p.a && p.b && p.a !== p.b),
      refetchInterval: 60_000,
    })),
  })

  /** Merges the pairwise responses into matrix rows keyed by target path. */
  const liveMatrix = useMemo<DriftMatrixRow[]>(() => {
    if (!liveMode) return []
    const rows = new Map<string, DriftMatrixRow>()
    const baseId = baseline?.id ?? ''

    driftQueries.forEach((q, i) => {
      const other = pairs[i]?.b
      if (!other || !q.data) return
      for (const d of q.data.drift ?? []) {
        if (!d?.path_or_key) continue
        const cells: Record<string, DriftCellStatus> = {}

        // Only on one side means absent on the other; equal hashes are in sync;
        // anything else is a real divergence between the two hosts.
        if (d.only_on === 'a') {
          cells[baseId] = 'modified'
          cells[other] = 'missing'
        } else if (d.only_on === 'b') {
          cells[baseId] = 'missing'
          cells[other] = 'modified'
        } else if (d.hash_a && d.hash_b && d.hash_a === d.hash_b) {
          cells[baseId] = 'sync'
          cells[other] = 'sync'
        } else {
          cells[baseId] = 'drift'
          cells[other] = 'drift'
        }

        const existing = rows.get(d.path_or_key)
        if (existing) {
          Object.assign(existing.cells, cells)
        } else {
          rows.set(d.path_or_key, {
            path_or_key: d.path_or_key,
            target_type: d.target_type || 'file',
            category: d.target_type || 'Other',
            cells,
          })
        }
      }
    })

    return [...rows.values()].sort((a, b) => a.path_or_key.localeCompare(b.path_or_key))
  }, [liveMode, driftQueries, pairs, baseline])

  const matrix = liveMode ? liveMatrix : sample ? FALLBACK_DRIFT_MATRIX : []

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (matrix ?? []).filter((row) => {
      if (q && !row.path_or_key.toLowerCase().includes(q)) return false
      if (category !== 'all' && row.category !== category) return false
      if (level === 'divergent' && !Object.values(row.cells).includes('drift')) return false
      if (level === 'changed' && !Object.values(row.cells).includes('modified')) return false
      return true
    })
  }, [matrix, category, level, query])

  const grouped = useMemo(() => {
    const key = groupBy === 'category' ? 'category' : 'target_type'
    const map = new Map<string, DriftMatrixRow[]>()
    for (const row of rows) {
      const k = String(row[key as keyof DriftMatrixRow] ?? 'Other')
      const list = map.get(k) ?? []
      list.push(row)
      map.set(k, list)
    }
    return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]))
  }, [groupBy, rows])

  const categories = useMemo(
    () => Array.from(new Set(matrix.map((r) => r.category))).sort(),
    [matrix],
  )

  const divergentCount = useMemo(
    () =>
      matrix.reduce(
        (a, r) => a + Object.values(r.cells).filter((c) => c === 'drift').length,
        0,
      ),
    [matrix],
  )

  const hasEnoughHosts = (hosts ?? []).length >= 2

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Drift Matrix"
        subtitle="Compare configuration files, registry keys and packages across every server side by side."
        actions={
          <>
            <Button
              icon={<RefreshCw className="h-4 w-4" />}
              onClick={() => driftQueries.forEach((q) => void q.refetch())}
              disabled={!liveMode}
            >
              Recompute
            </Button>
            <Button
              variant="primary"
              icon={<GitCompare className="h-4 w-4" />}
              onClick={() => {
                const first = columns[0]
                if (first) {
                  setHostId(first.id)
                  goTo('timeline')
                }
              }}
            >
              Compare
            </Button>
          </>
        }
      />

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3 border-b border-slate-200 bg-white px-4 py-3 sm:px-6">
        <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
          <SlidersHorizontal className="h-3.5 w-3.5" />
          Filters
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">Group by</span>
          <SegmentedControl
            options={[
              { id: 'category', label: 'Category' },
              { id: 'type', label: 'Type' },
            ]}
            value={groupBy}
            onChange={setGroupBy}
          />
        </div>

        <Select
          aria-label="Category"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          wrapperClassName="w-40"
        >
          <option value="all">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </Select>

        <Select
          aria-label="Drift level"
          value={level}
          onChange={(e) => setLevel(e.target.value)}
          wrapperClassName="w-44"
        >
          <option value="all">All states</option>
          <option value="divergent">Contains drift</option>
          <option value="changed">Contains modifications</option>
        </Select>

        <TextInput
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter paths…"
          icon={<Server className="h-4 w-4" />}
          wrapperClassName="w-56"
          aria-label="Filter target paths"
        />

        <div className="ml-auto flex items-center gap-3">
          <span className="text-xs text-slate-500">
            <span className="font-semibold text-amber-700">{divergentCount}</span> drifted cells
          </span>
          <SegmentedControl
            options={[
              { id: 'all', label: 'All cells' },
              { id: 'divergent', label: 'Divergence only' },
            ]}
            value={compareMode}
            onChange={setCompareMode}
          />
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto bg-slate-50 p-4 sm:p-6">
        <Card flush>
          <div className="flex items-center gap-3 border-b border-slate-200 px-4 py-3">
            <CardHeader
              className="w-full"
              title="Cross-node comparison"
              subtitle={`${columns.length} servers · ${rows.length} monitored targets`}
              icon={<Layers className="h-4 w-4" />}
            />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/70">
                  <th className="sticky left-0 z-10 min-w-[18rem] bg-slate-50/70 px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                    Target path / key
                  </th>
                  {columns.map((c) => (
                    <th
                      key={c.id}
                      className="min-w-[9.5rem] px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-slate-500"
                    >
                      <span className="flex items-center gap-1.5">
                        <span
                          className={cn(
                            'h-1.5 w-1.5 rounded-full',
                            c.os === 'windows' ? 'bg-sky-500' : 'bg-amber-500',
                          )}
                        />
                        <span className="font-mono normal-case tracking-normal text-slate-600">
                          {c.hostname}
                        </span>
                      </span>
                    </th>
                  ))}
                  <th className="px-4 py-2 text-right text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                    Inspector
                  </th>
                </tr>
              </thead>
              <tbody>
                {grouped.map(([group, groupRows]) => (
                  <Fragment key={group}>
                    <tr className="border-b border-slate-200 bg-slate-100/70">
                      <td
                        colSpan={columns.length + 2}
                        className="px-4 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500"
                      >
                        {group} · {groupRows.length}
                      </td>
                    </tr>
                    {groupRows.map((row, i) => (
                      <tr
                        key={row.path_or_key}
                        className={cn(
                          'border-b border-slate-100 transition-colors last:border-0 hover:bg-blue-50/40',
                          i % 2 === 1 && 'bg-slate-50/30',
                          selected === row.path_or_key && 'bg-blue-50/60',
                        )}
                      >
                        <td className="sticky left-0 z-10 max-w-[26rem] bg-white px-4 py-2.5">
                          <button
                            onClick={() =>
                              setSelected((s) => (s === row.path_or_key ? null : row.path_or_key))
                            }
                            className="block max-w-full truncate text-left font-mono text-xs text-slate-800 hover:text-blue-700"
                            title={row.path_or_key}
                          >
                            {row.path_or_key}
                          </button>
                          <span className="mt-0.5 flex items-center gap-1.5 text-[11px] capitalize text-slate-400">
                            {row.target_type}
                          </span>
                        </td>
                        {columns.map((c) => {
                          const status = row.cells[c.id] ?? 'missing'
                          if (compareMode === 'divergent' && status !== 'drift') {
                            return (
                              <td key={c.id} className="px-3 py-2.5">
                                <span className="text-xs text-slate-300">·</span>
                              </td>
                            )
                          }
                          return (
                            <td key={c.id} className="px-3 py-2.5">
                              <StatusBadge status={status} />
                            </td>
                          )
                        })}
                        <td className="px-4 py-2.5 text-right">
                          <Button
                            size="sm"
                            onClick={() => {
                              const drifted = columns.find(
                                (c) => (row.cells[c.id] ?? 'missing') === 'drift',
                              )
                              const first = drifted ?? columns[0]
                              if (first) {
                                setHostId(first.id)
                                goTo('timeline')
                              }
                            }}
                          >
                            Inspect
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>

          {rows.length === 0 ? (
            <div className="px-4 py-12 text-center text-sm text-slate-500">
              {hasEnoughHosts ? (
                'No drift targets match the current filters.'
              ) : (
                <>
                  <p className="font-medium">No servers enrolled yet</p>
                  <p className="mx-auto mt-1 max-w-md text-xs leading-5 text-slate-400">
                    Copy the Linux or Windows install command under Settings → Agents to connect
                    your first host. Drift is computed between two or more enrolled servers.
                  </p>
                  <button
                    onClick={() => goTo('settings', { settingsTab: 'agents' })}
                    className="mt-3 rounded-lg bg-blue-600 px-3.5 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700"
                  >
                    Open agent setup
                  </button>
                </>
              )}
            </div>
          ) : null}
        </Card>

        {/* Legend */}
        <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-slate-200/80 bg-white px-4 py-3 shadow-xs">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Legend</span>
          {(Object.keys(STATUS_META) as DriftCellStatus[]).map((s) => (
            <span key={s} className="flex items-center gap-2 text-xs text-slate-600">
              <StatusBadge status={s} />
            </span>
          ))}
        </div>

        {/* Selected target detail */}
        {selected ? (
          <Card className="mt-4">
            <CardHeader
              title={selected}
              subtitle="Target detail"
              icon={<Layers className="h-4 w-4" />}
              actions={
                <Button size="sm" onClick={() => setSelected(null)} icon={<X className="h-3.5 w-3.5" />}>
                  Close
                </Button>
              }
            />
            <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {columns.map((c) => {
                const row = matrix.find((r) => r.path_or_key === selected)
                const status = row?.cells[c.id] ?? 'missing'
                return (
                  <div
                    key={c.id}
                    className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50/50 px-3 py-2"
                  >
                    <HostPill hostname={c.hostname} os={c.os} />
                    <StatusBadge status={status} />
                  </div>
                )
              })}
            </div>
          </Card>
        ) : null}
      </div>
    </div>
  )
}
