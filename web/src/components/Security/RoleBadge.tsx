import StatusPill, { type PillTone } from '../ui/StatusPill'
import { ROLE_LABELS } from '../../api/hooks'
import type { Role } from '../../types'

/**
 * Role colours, shared by the audit log, the member list and the API-key table
 * so "who was this?" reads the same in every surface.
 *
 * The mapping is by privilege, not by aesthetics: administrator is brand blue
 * (the primary actor), operator is neutral, policy admin is the level-2 purple
 * the console already uses for grouped transactions, and auditor is amber
 * because a read-only reviewer is the one identity with no write authority.
 */
const ROLE_TONES: Record<Role, PillTone> = {
  admin: 'blue',
  operator: 'slate',
  policy_admin: 'purple',
  auditor: 'amber',
}

export function roleTone(role: string): PillTone {
  return ROLE_TONES[role as Role] ?? 'slate'
}

export function roleLabel(role: string): string {
  return ROLE_LABELS[role as Role] ?? role ?? '—'
}

/** Compact RBAC badge used in tables and the audit trail. */
export default function RoleBadge({ role, short }: { role: string; short?: boolean }) {
  const label = roleLabel(role)
  return (
    <StatusPill tone={roleTone(role)}>
      {short && role === 'auditor' ? 'Auditor' : short && role === 'admin' ? 'Admin' : label}
    </StatusPill>
  )
}
