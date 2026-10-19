import { ChevronRight, Fingerprint, Globe, Terminal, User } from 'lucide-react'
import type { Event } from '../../types'

function Chip({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode
  label: string
  value?: string | number
}) {
  if (!value) return null
  return (
    <span className="flex items-center gap-1.5 rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300">
      {icon}
      <span className="text-slate-400">{label}</span>
      <span className="font-mono font-medium">{value}</span>
    </span>
  )
}

/**
 * Visual breadcrumb of execution ancestry, e.g.
 * `SSH 203.0.113.7 → sshd → bash → sudo → vim [28411]`, plus identity chips
 * for the effective user, login UID, and session IP.
 */
export default function LineageBar({ event }: { event: Event }) {
  const ancestors = event.process_lineage ?? []
  const writer = event.process_name ?? ''
  const chain = [...ancestors, writer].filter(Boolean)

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-1 gap-y-1 rounded-md border border-slate-200 bg-slate-50 px-2.5 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-800/50">
        {event.remote_ip && (
          <span className="flex items-center gap-1 text-sky-600 dark:text-sky-300">
            <Globe className="h-3 w-3" />
            SSH {event.remote_ip}
          </span>
        )}
        {chain.map((proc, i) => {
          const last = i === chain.length - 1
          return (
            <span key={`${proc}-${i}`} className="flex items-center gap-1">
              {(i > 0 || event.remote_ip) && (
                <ChevronRight className="h-3 w-3 text-slate-300 dark:text-slate-600" />
              )}
              <Terminal className="h-3 w-3 text-slate-400" />
              <span className={last ? 'font-semibold text-slate-800 dark:text-slate-100' : ''}>
                {proc}
              </span>
              {last && event.pid ? (
                <span className="text-slate-400">[{event.pid}]</span>
              ) : null}
            </span>
          )
        })}
        {chain.length === 0 && !event.remote_ip && (
          <span className="text-slate-400">No process lineage recorded</span>
        )}
      </div>

      <div className="flex flex-wrap gap-1.5">
        <Chip
          icon={<User className="h-3 w-3 text-slate-400" />}
          label="Effective"
          value={event.actor_username}
        />
        <Chip
          icon={<Fingerprint className="h-3 w-3 text-slate-400" />}
          label="Login UID"
          value={event.login_uid}
        />
        <Chip
          icon={<Globe className="h-3 w-3 text-slate-400" />}
          label="Session IP"
          value={event.remote_ip}
        />
        <Chip
          icon={<Terminal className="h-3 w-3 text-slate-400" />}
          label="PID"
          value={event.pid}
        />
      </div>
      {event.cmdline && (
        <div className="truncate rounded-md bg-slate-900 px-2.5 py-1.5 font-mono text-[11px] text-slate-200 dark:bg-slate-950">
          $ {event.cmdline}
        </div>
      )}
    </div>
  )
}
