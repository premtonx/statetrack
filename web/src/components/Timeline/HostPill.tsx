import { Server } from 'lucide-react'
import { cn } from '../../lib/utils'

/** Rounded host pill used in timeline rows, tables and the inspector header. */
export function HostPill({
  hostname,
  os,
  className,
}: {
  hostname?: string
  os?: string
  className?: string
}) {
  if (!hostname) return null
  const windows = os?.toLowerCase().includes('win') || hostname.toLowerCase().startsWith('win')
  return (
    <span
      className={cn(
        'inline-flex max-w-[12rem] items-center gap-1.5 whitespace-nowrap rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-600',
        className,
      )}
      title={`${hostname}${windows ? ' · Windows' : ''}`}
    >
      <Server className="h-3 w-3 shrink-0 text-slate-400" />
      <span className="truncate font-mono">{hostname}</span>
    </span>
  )
}

export default HostPill
