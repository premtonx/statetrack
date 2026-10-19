import type { ImpactLevel } from '../types'

/**
 * Level semantics (see .cursorrules):
 *   L1 Critical  → Google Red    #d93025
 *   L2 Grouped   → Brand Purple  #7c3aed
 *   L3 Drift     → Google Amber  #f9ab00
 *   L4 Forensic  → Google Blue   #1a73e8
 */
export interface LevelStyle {
  /** Short chip label, e.g. "L1". */
  short: string
  /** Pill label used in tables and the timeline, e.g. "Level 1". */
  pill: string
  /** Descriptive label, e.g. "L1 Critical". */
  label: string
  /** Human name of the level, e.g. "Critical". */
  name: string
  /** Tailwind classes for a pill badge. */
  badge: string
  /** Tailwind classes for a solid dot. */
  dot: string
  /** Tailwind classes for a soft row tint. */
  tint: string
  /** Hex used by the SVG/CSS charts. */
  hex: string
  emoji: string
}

export const LEVELS: Record<ImpactLevel, LevelStyle> = {
  1: {
    short: 'L1',
    pill: 'Level 1',
    label: 'L1 Critical',
    name: 'Critical',
    badge: 'bg-red-50 text-red-700 border-red-200',
    dot: 'bg-red-600',
    tint: 'bg-red-50/40',
    hex: '#d93025',
    emoji: '🔴',
  },
  2: {
    short: 'L2',
    pill: 'Level 2',
    label: 'L2 Grouped',
    name: 'Grouped',
    badge: 'bg-purple-50 text-purple-700 border-purple-200',
    dot: 'bg-purple-600',
    tint: 'bg-purple-50/30',
    hex: '#7c3aed',
    emoji: '📦',
  },
  3: {
    short: 'L3',
    pill: 'Level 3',
    label: 'L3 Drift',
    name: 'Drift',
    badge: 'bg-amber-50 text-amber-700 border-amber-200',
    dot: 'bg-amber-500',
    tint: 'bg-amber-50/30',
    hex: '#f9ab00',
    emoji: '🟡',
  },
  4: {
    short: 'L4',
    pill: 'Level 4',
    label: 'L4 Forensic',
    name: 'Forensic',
    badge: 'bg-blue-50 text-blue-700 border-blue-200',
    dot: 'bg-blue-600',
    tint: 'bg-blue-50/30',
    hex: '#1a73e8',
    emoji: '🔵',
  },
}

export function levelStyle(level: number): LevelStyle {
  return LEVELS[level as ImpactLevel] ?? LEVELS[3]
}

/** Ordered level ids — used by charts and legends. */
export const LEVEL_ORDER: ImpactLevel[] = [1, 2, 3, 4]

export interface CategoryStyle {
  label: string
  /** Tag pill shown on the right of a timeline row. */
  tag: string
  badge: string
  hex: string
}

const CATEGORY_STYLES: Record<number, CategoryStyle> = {
  1: {
    label: 'Config',
    tag: 'Config change',
    badge: 'bg-blue-50 text-blue-700 border-blue-200',
    hex: '#1a73e8',
  },
  2: {
    label: 'Package',
    tag: 'Package update',
    badge: 'bg-purple-50 text-purple-700 border-purple-200',
    hex: '#7c3aed',
  },
  3: {
    label: 'Service',
    tag: 'Service',
    badge: 'bg-teal-50 text-teal-700 border-teal-200',
    hex: '#0d9488',
  },
  4: {
    label: 'User',
    tag: 'Security',
    badge: 'bg-rose-50 text-rose-700 border-rose-200',
    hex: '#e11d48',
  },
  5: {
    label: 'Registry',
    tag: 'Registry',
    badge: 'bg-cyan-50 text-cyan-700 border-cyan-200',
    hex: '#0891b2',
  },
  6: {
    label: 'Network',
    tag: 'Network',
    badge: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    hex: '#4f46e5',
  },
  7: {
    label: 'Process',
    tag: 'Process',
    badge: 'bg-slate-100 text-slate-700 border-slate-200',
    hex: '#475569',
  },
  8: {
    label: 'Agent Health',
    tag: 'Agent',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    hex: '#1e8e3e',
  },
}

const UNSPECIFIED_CATEGORY: CategoryStyle = {
  label: 'Unspecified',
  tag: 'Unspecified',
  badge: 'bg-slate-100 text-slate-600 border-slate-200',
  hex: '#94a3b8',
}

export function categoryStyle(category: number): CategoryStyle {
  return CATEGORY_STYLES[category] ?? UNSPECIFIED_CATEGORY
}

export function categoryName(category: number): string {
  return categoryStyle(category).label
}

export const ACTIONS: Record<number, string> = {
  1: 'Created',
  2: 'Modified',
  3: 'Deleted',
  4: 'Restarted',
  5: 'Started',
  6: 'Stopped',
  7: 'Upgraded',
  8: 'Throttled',
}

export function actionName(action: number): string {
  return ACTIONS[action] ?? 'Unspecified'
}

/** Parses the `(+12 -3)` suffix the agent appends to change summaries. */
export function parseLineDiff(summary?: string): { added: number; removed: number } | null {
  if (!summary) return null
  const m = summary.match(/\(\s*\+(\d+)\s+-(\d+)\s*\)/)
  if (!m) return null
  const added = Number(m[1])
  const removed = Number(m[2])
  if (!Number.isFinite(added) || !Number.isFinite(removed)) return null
  return { added, removed }
}

/** Compact `+12 -3` label for tables. */
export function lineDiffLabel(
  added?: number,
  removed?: number,
): { added: number; removed: number } | null {
  if (typeof added !== 'number' && typeof removed !== 'number') return null
  return { added: added ?? 0, removed: removed ?? 0 }
}

export const IMPACT_OPTIONS: { value: ImpactLevel; label: string }[] = [
  { value: 1, label: 'Level 1 · Critical' },
  { value: 2, label: 'Level 2 · Grouped' },
  { value: 3, label: 'Level 3 · Drift' },
  { value: 4, label: 'Level 4 · Forensic' },
]

export const CATEGORY_OPTIONS: { value: number; label: string }[] = [
  { value: 1, label: 'Config' },
  { value: 2, label: 'Package' },
  { value: 3, label: 'Service' },
  { value: 4, label: 'User' },
  { value: 5, label: 'Registry' },
  { value: 6, label: 'Network' },
  { value: 7, label: 'Process' },
  { value: 8, label: 'Agent Health' },
]

/** Event-type filter options, including the "all" sentinel at value 0. */
export const CATEGORY_FILTER_OPTIONS: { value: number; label: string }[] = [
  { value: 0, label: 'All Event Types' },
  ...CATEGORY_OPTIONS,
]

export const RANGES: { value: string; label: string; short: string; seconds: number }[] = [
  { value: '15m', label: 'Last 15 minutes', short: '15m', seconds: 15 * 60 },
  { value: '1h', label: 'Last 1 hour', short: '1h', seconds: 3600 },
  { value: '24h', label: 'Last 24 hours', short: '24h', seconds: 24 * 3600 },
  { value: '7d', label: 'Last 7 days', short: '7d', seconds: 7 * 24 * 3600 },
  { value: '30d', label: 'Last 30 days', short: '30d', seconds: 30 * 24 * 3600 },
]

/** Date-range options for the timeline toolbar (excludes the live 15m preset). */
export const TIMELINE_RANGES = RANGES

/** Ranges offered by aggregate widgets (dashboard/report selectors). */
export const AGGREGATE_RANGES = RANGES.filter((r) => r.value !== '15m')

export function rangeLabel(value: string): string {
  return RANGES.find((r) => r.value === value)?.label ?? 'Last 24 hours'
}

/* -------------------------------------------------------------------------- */
/* Discovered workload types (auto-discovery & asset tiering)                  */
/* -------------------------------------------------------------------------- */

export interface WorkloadStyle {
  /** Human label, e.g. "IIS site". */
  label: string
  /** Short uppercase token for dense cards. */
  token: string
  /** Emoji glyph used as a lightweight, dependency-free icon. */
  glyph: string
  /** Tailwind classes for the icon tile. */
  tile: string
  /** Tailwind classes for the type pill. */
  badge: string
}

const WORKLOAD_STYLES: Record<string, WorkloadStyle> = {
  iis_site: {
    label: 'IIS site',
    token: 'IIS',
    glyph: '🪟',
    tile: 'bg-sky-50 text-sky-600',
    badge: 'bg-sky-50 text-sky-700 border-sky-200',
  },
  mssql_instance: {
    label: 'SQL Server',
    token: 'MSSQL',
    glyph: '🗄️',
    tile: 'bg-rose-50 text-rose-600',
    badge: 'bg-rose-50 text-rose-700 border-rose-200',
  },
  nginx_vhost: {
    label: 'Nginx vhost',
    token: 'NGINX',
    glyph: '🟩',
    tile: 'bg-emerald-50 text-emerald-600',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  },
  apache_vhost: {
    label: 'Apache vhost',
    token: 'APACHE',
    glyph: '🪶',
    tile: 'bg-orange-50 text-orange-600',
    badge: 'bg-orange-50 text-orange-700 border-orange-200',
  },
  postgres_db: {
    label: 'PostgreSQL',
    token: 'POSTGRES',
    glyph: '🐘',
    tile: 'bg-indigo-50 text-indigo-600',
    badge: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  },
  redis: {
    label: 'Redis',
    token: 'REDIS',
    glyph: '🧱',
    tile: 'bg-red-50 text-red-600',
    badge: 'bg-red-50 text-red-700 border-red-200',
  },
  docker: {
    label: 'Docker',
    token: 'DOCKER',
    glyph: '🐳',
    tile: 'bg-blue-50 text-blue-600',
    badge: 'bg-blue-50 text-blue-700 border-blue-200',
  },
  k8s_configmap: {
    label: 'K8s ConfigMap',
    token: 'CONFIGMAP',
    glyph: '🗺️',
    tile: 'bg-sky-50 text-sky-600',
    badge: 'bg-sky-50 text-sky-700 border-sky-200',
  },
  k8s_secret: {
    label: 'K8s Secret',
    token: 'SECRET',
    glyph: '🔐',
    tile: 'bg-violet-50 text-violet-600',
    badge: 'bg-violet-50 text-violet-700 border-violet-200',
  },
  k8s_deployment: {
    label: 'K8s Deployment',
    token: 'DEPLOYMENT',
    glyph: '⎈',
    tile: 'bg-indigo-50 text-indigo-600',
    badge: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  },
  k8s_statefulset: {
    label: 'K8s StatefulSet',
    token: 'STATEFULSET',
    glyph: '⎈',
    tile: 'bg-indigo-50 text-indigo-600',
    badge: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  },
  k8s_ingress: {
    label: 'K8s Ingress',
    token: 'INGRESS',
    glyph: '⎈',
    tile: 'bg-cyan-50 text-cyan-600',
    badge: 'bg-cyan-50 text-cyan-700 border-cyan-200',
  },
  rabbitmq: {
    label: 'RabbitMQ',
    token: 'RABBITMQ',
    glyph: '🐇',
    tile: 'bg-orange-50 text-orange-600',
    badge: 'bg-orange-50 text-orange-700 border-orange-200',
  },
  msmq: {
    label: 'MSMQ',
    token: 'MSMQ',
    glyph: '📨',
    tile: 'bg-slate-100 text-slate-600',
    badge: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  haproxy: {
    label: 'HAProxy',
    token: 'HAPROXY',
    glyph: '🔀',
    tile: 'bg-emerald-50 text-emerald-600',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  },
  caddy_site: {
    label: 'Caddy site',
    token: 'CADDY',
    glyph: '🪶',
    tile: 'bg-teal-50 text-teal-600',
    badge: 'bg-teal-50 text-teal-700 border-teal-200',
  },
  mysql_instance: {
    label: 'MySQL / MariaDB',
    token: 'MYSQL',
    glyph: '🐬',
    tile: 'bg-blue-50 text-blue-600',
    badge: 'bg-blue-50 text-blue-700 border-blue-200',
  },
  kafka: {
    label: 'Kafka',
    token: 'KAFKA',
    glyph: '📮',
    tile: 'bg-purple-50 text-purple-600',
    badge: 'bg-purple-50 text-purple-700 border-purple-200',
  },
}

const UNKNOWN_WORKLOAD: WorkloadStyle = {
  label: 'Workload',
  token: 'WORKLOAD',
  glyph: '📦',
  tile: 'bg-slate-100 text-slate-600',
  badge: 'bg-slate-100 text-slate-600 border-slate-200',
}

export function workloadStyle(type?: string): WorkloadStyle {
  const key = (type ?? '').trim().toLowerCase()
  return WORKLOAD_STYLES[key] ?? UNKNOWN_WORKLOAD
}

/* -------------------------------------------------------------------------- */
/* Change-control compliance (ITSM change-ticket bridge)                       */
/* -------------------------------------------------------------------------- */

export interface ComplianceStyle {
  label: string
  /** Tailwind classes for the pill. */
  badge: string
  /** Tailwind classes for the leading dot. */
  dot: string
  /** One-sentence explanation, used as the pill's tooltip. */
  help: string
}

/**
 * Presentation for the change-control verdict.
 *
 * `unapproved` and `expired` are both violations, but they are coloured and
 * worded differently on purpose: the remedies differ (raise a ticket versus
 * extend the window), and a reviewer who cannot tell them apart at a glance
 * will chase the wrong one.
 */
const COMPLIANCE_STYLES: Record<string, ComplianceStyle> = {
  approved: {
    label: 'Change Approved',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    dot: 'bg-emerald-600',
    help: 'An approved change ticket covers this change.',
  },
  unapproved: {
    label: 'Unapproved Change',
    badge: 'bg-red-50 text-red-700 border-red-200',
    dot: 'bg-red-600',
    help: 'No approved change ticket covers this change while enforcement is active.',
  },
  expired: {
    label: 'Change Window Expired',
    badge: 'bg-amber-50 text-amber-700 border-amber-200',
    dot: 'bg-amber-500',
    help: 'A ticket covers this target but its authorised window had already closed.',
  },
  not_required: {
    label: 'No Change Required',
    badge: 'bg-slate-100 text-slate-600 border-slate-200',
    dot: 'bg-slate-400',
    help: 'This change is below the ticket threshold, or enforcement is off.',
  },
}

const UNKNOWN_COMPLIANCE: ComplianceStyle = {
  label: 'Not Evaluated',
  badge: 'bg-slate-100 text-slate-600 border-slate-200',
  dot: 'bg-slate-300',
  help: 'Change-ticket enforcement is not active for this deployment.',
}

export function complianceStyle(compliance?: string): ComplianceStyle {
  const key = (compliance ?? '').trim().toLowerCase()
  return COMPLIANCE_STYLES[key] ?? UNKNOWN_COMPLIANCE
}

/** True for a verdict an auditor should see. */
export function isComplianceViolation(compliance?: string): boolean {
  const key = (compliance ?? '').trim().toLowerCase()
  return key === 'unapproved' || key === 'expired'
}

/** Filter options for the reports compliance view, in display order. */
export const COMPLIANCE_FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All changes' },
  { value: 'unapproved', label: 'Unauthorised changes' },
  { value: 'expired', label: 'Expired windows' },
  { value: 'approved', label: 'Authorised changes' },
  { value: 'not_required', label: 'No ticket required' },
]
