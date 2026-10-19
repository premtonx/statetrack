import { ShieldCheck, Smartphone, Users } from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import StatusPill from '../ui/StatusPill'
import RoleBadge from './RoleBadge'
import { useUsers } from '../../api/hooks'
import { formatDateTime, timeAgo } from '../../lib/utils'

/**
 * The organization's console identities.
 *
 * Read-only by design: changing someone's role is an administrative act the
 * suite deliberately routes through the identity provider (SSO auto-provision)
 * rather than an inline dropdown, so there is one place a grant can change and
 * one audit row that explains it.
 */
export default function MembersCard() {
  const { data, isLoading, isError } = useUsers()
  const users = data?.users ?? []

  return (
    <Card>
      <CardHeader
        title="Console Members"
        subtitle="Identities that can sign in to this console"
        icon={<Users className="h-4 w-4" />}
        actions={<StatusPill tone="slate">{users.length} member{users.length === 1 ? '' : 's'}</StatusPill>}
      />

      {isError ? (
        <p className="mt-4 text-xs text-red-700">Could not load console members.</p>
      ) : isLoading ? (
        <div className="mt-4 space-y-2">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-10 animate-pulse rounded-lg bg-slate-100" />
          ))}
        </div>
      ) : (
        <ul className="mt-4 divide-y divide-slate-100">
          {users.map((u) => (
            <li key={u.id} className="flex items-center gap-3 py-2.5">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-100 text-[11px] font-semibold text-slate-600">
                {u.initials}
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-medium text-slate-800">{u.name || u.email}</p>
                <p className="truncate text-[11px] text-slate-400">{u.email}</p>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                {u.totp_enabled ? (
                  <span
                    title="Two-factor authentication enabled"
                    className="inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700"
                  >
                    <Smartphone className="h-3 w-3" /> 2FA
                  </span>
                ) : null}
                {u.auth_provider === 'oidc' ? (
                  <span
                    title="Signs in through single sign-on"
                    className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-600"
                  >
                    <ShieldCheck className="h-3 w-3" /> SSO
                  </span>
                ) : null}
                <RoleBadge role={u.role} />
              </div>
              <span
                className="hidden shrink-0 text-[11px] text-slate-400 lg:block"
                title={u.last_login_at ? formatDateTime(u.last_login_at) : 'Never signed in'}
              >
                {u.last_login_at ? timeAgo(u.last_login_at) : 'never'}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
