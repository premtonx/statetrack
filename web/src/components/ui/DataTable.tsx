import { ChevronLeft, ChevronRight } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'

export interface DataTableColumn<T> {
  key: string
  header: ReactNode
  /** Cell renderer. Returning null renders an em dash. */
  cell: (row: T) => ReactNode
  /** Extra classes applied to both the header and body cell. */
  className?: string
  align?: 'left' | 'right' | 'center'
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[]
  rows: T[]
  rowKey: (row: T, index: number) => string
  onRowClick?: (row: T) => void
  /** Renders a highlight tint behind a row (e.g. critical events). */
  rowClassName?: (row: T) => string | undefined
  empty?: ReactNode
  loading?: boolean
  /** Optional client-side pagination. */
  pageSize?: number
  page?: number
  onPage?: (page: number) => void
  className?: string
}

const ALIGN: Record<'left' | 'right' | 'center', string> = {
  left: 'text-left',
  right: 'text-right',
  center: 'text-center',
}

/**
 * Dense, striped data table with hover states and optional pagination —
 * the standard tabular surface for the console.
 */
export default function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  rowClassName,
  empty,
  loading,
  pageSize,
  page = 1,
  onPage,
  className,
}: DataTableProps<T>) {
  const total = rows.length
  const paged = pageSize ? rows.slice((page - 1) * pageSize, page * pageSize) : rows
  const pageCount = pageSize ? Math.max(1, Math.ceil(total / pageSize)) : 1

  return (
    <div className={cn('overflow-hidden', className)}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50/70">
              {columns.map((c) => (
                <th
                  key={c.key}
                  scope="col"
                  className={cn(
                    'whitespace-nowrap px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500',
                    ALIGN[c.align ?? 'left'],
                    c.className,
                  )}
                >
                  {c.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading &&
              Array.from({ length: 5 }, (_, i) => (
                <tr key={`skeleton-${i}`} className="border-b border-slate-100">
                  {columns.map((c) => (
                    <td key={c.key} className="px-3 py-3">
                      <span className="block h-3 w-full max-w-[10rem] animate-pulse rounded bg-slate-100" />
                    </td>
                  ))}
                </tr>
              ))}

            {!loading &&
              (paged ?? []).map((row, i) => (
                <tr
                  key={rowKey(row, i)}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    'border-b border-slate-100 transition-colors last:border-0',
                    i % 2 === 1 && 'bg-slate-50/40',
                    onRowClick && 'cursor-pointer hover:bg-blue-50/50',
                    rowClassName?.(row),
                  )}
                >
                  {columns.map((c) => {
                    const content = c.cell(row)
                    return (
                      <td
                        key={c.key}
                        className={cn(
                          'px-3 py-2.5 align-middle text-slate-600',
                          ALIGN[c.align ?? 'left'],
                          c.className,
                        )}
                      >
                        {content ?? <span className="text-slate-300">—</span>}
                      </td>
                    )
                  })}
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {!loading && total === 0 ? (
        <div className="px-4 py-10 text-center text-sm text-slate-400">
          {empty ?? 'Nothing to show yet.'}
        </div>
      ) : null}

      {!loading && pageSize && total > pageSize ? (
        <div className="flex items-center justify-between border-t border-slate-200 px-3 py-2 text-xs text-slate-500">
          <span>
            {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => onPage?.(Math.max(1, page - 1))}
              disabled={page <= 1}
              aria-label="Previous page"
              className="flex h-7 w-7 items-center justify-center rounded-md border border-slate-200 text-slate-500 transition-colors hover:bg-slate-50 disabled:opacity-40"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <span className="px-1 tabular-nums">
              {page} / {pageCount}
            </span>
            <button
              onClick={() => onPage?.(Math.min(pageCount, page + 1))}
              disabled={page >= pageCount}
              aria-label="Next page"
              className="flex h-7 w-7 items-center justify-center rounded-md border border-slate-200 text-slate-500 transition-colors hover:bg-slate-50 disabled:opacity-40"
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
