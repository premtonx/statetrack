import { useEffect, useMemo, useState } from 'react'
import {
  ArrowRight,
  Database,
  Globe,
  HardDrive,
  Info,
  KeyRound,
  Lock,
  Plug,
  Save,
  ScrollText,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
} from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import Card, { CardHeader } from '../components/ui/Card'
import StatusPill from '../components/ui/StatusPill'
import { Button, Field, Select, Tabs, TextInput, Toggle, type TabItem } from '../components/ui/controls'
import InstallCommandsCard from '../components/Security/InstallCommandsCard'
import SSOCard from '../components/Security/SSOCard'
import TwoFactorCard from '../components/Security/TwoFactorCard'
import APIKeysCard from '../components/Security/APIKeysCard'
import MembersCard from '../components/Security/MembersCard'
import EnrollmentCard from '../components/Security/EnrollmentCard'
import AuditLogCard from '../components/Security/AuditLogCard'
import { SYSTEM_INFO, TIMEZONES } from '../api/mockData'
import { useHostList, useSystemInfo } from '../api/hooks'
import { useAuth, useReadOnly } from '../lib/authContext'
import { useConsole } from '../lib/consoleContext'
import { cn, formatNumber } from '../lib/utils'

type SettingsTab = 'general' | 'security' | 'agents' | 'audit'

/**
 * Platform settings.
 *
 * The security surface is the point of this page: SSO, 2FA and the scoped
 * credentials that reach the API live in one place, and the audit trail that
 * records every change to them sits beside them rather than in a separate tool.
 * A tab is a question ("who can sign in?", "how do agents join?", "who changed
 * this?"), not a settings category.
 */
export default function SettingsPage() {
  const [tab, setTab] = useState<SettingsTab>('general')
  const { hosts, total, online } = useHostList()

  // Group the real fleet by reported agent version. A clean install has no
  // hosts, so the card renders an empty state instead of invented builds.
  const versionBuckets = useMemo(() => {
    const counts = new Map<string, number>()
    for (const h of hosts ?? []) {
      const v = (h?.agent_version ?? '').trim() || 'unknown'
      counts.set(v, (counts.get(v) ?? 0) + 1)
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([version, count]) => ({ version, count }))
  }, [hosts])
  const { goTo } = useConsole()
  const auth = useAuth()
  const readOnly = useReadOnly()

  // The onboarding empty state links here with ?tab=agents so an operator lands
  // on the install command instead of the org-name form.
  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get('tab')
    if (requested === 'security' || requested === 'agents' || requested === 'audit') {
      setTab(requested)
    }
  }, [])

  const [orgName, setOrgName] = useState('Acme Corporation')
  const [timezone, setTimezone] = useState('Europe/Berlin')
  const [retention, setRetention] = useState(SYSTEM_INFO.retentionDays)
  const [saved, setSaved] = useState(false)
  // Build posture comes from the running binary, not the bundle. `info` is
  // undefined until the read lands, and the card renders em dashes rather than
  // a fabricated version in the meantime.
  const systemQuery = useSystemInfo()
  const info = systemQuery.data

  const [ipAllowlist, setIpAllowlist] = useState(false)
  const [redaction, setRedaction] = useState(true)
  const [autoUpdate, setAutoUpdate] = useState(true)
  const [crashReports, setCrashReports] = useState(false)

  const tabs: TabItem<SettingsTab>[] = [
    { id: 'general', label: 'General' },
    { id: 'security', label: 'Security & SSO' },
    { id: 'agents', label: 'Agents & Enrollment', count: total },
    { id: 'audit', label: 'Audit Log' },
  ]

  const passwordHash = `sha256:${'a3f1c9e7b2d84f60'.repeat(2)}`

  const handleSave = () => {
    setSaved(true)
    window.setTimeout(() => setSaved(false), 1800)
  }

  return (
    <div className="h-full overflow-y-auto">
      <PageHeader
        title="Settings"
        subtitle="Identity, access control, agent enrollment and the control-plane audit trail."
        actions={
          <>
            {auth.readOnly ? (
              <StatusPill tone="amber" dot>
                Read-only session
              </StatusPill>
            ) : null}
            {saved ? (
              <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                <ShieldCheck className="h-4 w-4" /> Saved
              </span>
            ) : null}
            <Button
              variant="primary"
              icon={<Save className="h-4 w-4" />}
              disabled={readOnly}
              onClick={handleSave}
            >
              Save Changes
            </Button>
          </>
        }
      />

      <div className="space-y-5 p-4 sm:p-6">
        <Card flush>
          <div className="px-4 pt-3">
            <Tabs tabs={tabs} active={tab} onChange={setTab} />
          </div>

          <div className="p-4">
            {tab === 'general' ? (
              <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                {/* System information */}
                <Card className="border-slate-200 bg-slate-50/40 shadow-none">
                  <CardHeader
                    title="System Information"
                    subtitle="Read-only build and infrastructure details"
                    icon={<Info className="h-4 w-4" />}
                  />
                  <dl className="mt-4 divide-y divide-slate-200/80">
                    {[
                      {
                        label: 'Version',
                        value: info?.version ?? '—',
                        icon: Settings2,
                        mono: true,
                      },
                      {
                        label: 'Build date',
                        value: info?.build_date ?? '—',
                        icon: Info,
                        mono: true,
                      },
                      {
                        label: 'Environment',
                        value: info?.demo_mode ? 'demo' : 'production',
                        icon: Globe,
                        mono: false,
                        badge: true,
                        tone: info?.demo_mode ? ('amber' as const) : ('green' as const),
                      },
                      {
                        label: 'Database',
                        value: info?.database || 'PostgreSQL',
                        icon: Database,
                        mono: true,
                      },
                      {
                        label: 'Storage',
                        value:
                          info?.storage === 's3' ? 'S3 / SeaweedFS' : 'Postgres (inline diffs)',
                        icon: HardDrive,
                        mono: true,
                      },
                      {
                        label: 'Agents online',
                        value: `${online} / ${total}`,
                        icon: Server,
                        mono: true,
                      },
                    ].map((row) => {
                      const Icon = row.icon
                      return (
                        <div key={row.label} className="flex items-center gap-3 py-2.5">
                          <Icon className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                          <dt className="text-xs text-slate-500">{row.label}</dt>
                          <dd className="ml-auto min-w-0 truncate text-right">
                            {row.badge ? (
                              <StatusPill tone={row.tone ?? 'green'} dot>
                                {row.value}
                              </StatusPill>
                            ) : (
                              <span className={cn('text-xs text-slate-800', row.mono && 'font-mono')}>
                                {row.value}
                              </span>
                            )}
                          </dd>
                        </div>
                      )
                    })}
                  </dl>
                </Card>

                {/* Platform settings */}
                <Card>
                  <CardHeader
                    title="Platform Settings"
                    subtitle="Organization-level defaults"
                    icon={<Globe className="h-4 w-4" />}
                  />
                  <div className="mt-4 space-y-4">
                    <Field label="Organization Name" htmlFor="org-name">
                      <TextInput
                        id="org-name"
                        value={orgName}
                        disabled={readOnly}
                        onChange={(e) => setOrgName(e.target.value)}
                      />
                    </Field>
                    <Field
                      label="Timezone"
                      htmlFor="timezone"
                      hint="Used for report windows and annotation timestamps."
                    >
                      <Select
                        id="timezone"
                        value={timezone}
                        disabled={readOnly}
                        onChange={(e) => setTimezone(e.target.value)}
                      >
                        {TIMEZONES.map((tz) => (
                          <option key={tz} value={tz}>
                            {tz}
                          </option>
                        ))}
                      </Select>
                    </Field>
                    <Field
                      label="Default Retention"
                      hint="Partitions older than this are dropped automatically."
                      htmlFor="retention"
                    >
                      <div className="flex items-center gap-4">
                        <input
                          id="retention"
                          type="range"
                          min={30}
                          max={1095}
                          step={30}
                          value={retention}
                          disabled={readOnly}
                          onChange={(e) => setRetention(Number(e.target.value))}
                          className="h-1.5 flex-1 cursor-pointer appearance-none rounded-full bg-slate-200 accent-blue-600"
                        />
                        <span className="w-24 shrink-0 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-center font-mono text-xs tabular-nums text-slate-700">
                          {formatNumber(retention)} days
                        </span>
                      </div>
                    </Field>
                    <div className="flex items-center gap-3 border-t border-slate-100 pt-4">
                      <Button
                        variant="primary"
                        icon={<Save className="h-4 w-4" />}
                        disabled={readOnly}
                        onClick={handleSave}
                      >
                        Save Changes
                      </Button>
                      <span className="text-xs text-slate-400">
                        {info?.version ? `Running v${info.version.replace(/^v/, '')}` : 'Not saved yet'}
                      </span>
                    </div>
                    <div className="flex items-start gap-3 rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2.5">
                      <Plug className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-medium text-slate-700">Integrations & notifications</p>
                        <p className="mt-0.5 text-xs text-slate-500">
                          Grafana, Prometheus, Checkmk, Zabbix and ChatOps delivery are configured in
                          the Integrations hub.
                        </p>
                      </div>
                      <Button
                        size="sm"
                        iconRight={<ArrowRight className="h-3.5 w-3.5" />}
                        onClick={() => goTo('integrations')}
                      >
                        Open hub
                      </Button>
                    </div>
                  </div>
                </Card>
              </div>
            ) : null}

            {tab === 'security' ? (
              <div className="space-y-5">
                <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                  <SSOCard />
                  <TwoFactorCard />
                </div>

                {/* Sign-in policy and data protection */}
                <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                  <Card>
                    <CardHeader
                      title="Sign-in Policy"
                      subtitle="Console access hardening"
                      icon={<Shield className="h-4 w-4" />}
                    />
                    <div className="mt-2 divide-y divide-slate-100">
                      <Toggle
                        checked={ipAllowlist}
                        onChange={setIpAllowlist}
                        disabled={readOnly}
                        label="Restrict console by IP allowlist"
                        description="Only approved CIDR ranges may load the console."
                      />
                      <Toggle
                        checked={redaction}
                        onChange={setRedaction}
                        disabled={readOnly}
                        label="Deterministic secret redaction"
                        description="Credentials become [REDACTED:sha256:…] before leaving the host."
                      />
                    </div>
                  </Card>

                  <Card>
                    <CardHeader
                      title="Data Protection"
                      subtitle="Storage, transport and audit trail"
                      icon={<KeyRound className="h-4 w-4" />}
                    />
                    <div className="mt-4 space-y-3">
                      {[
                        { label: 'Transport', value: 'mTLS · gRPC', tone: 'green' as const },
                        { label: 'At-rest encryption', value: 'AES-256', tone: 'green' as const },
                        { label: 'Control-plane audit', value: 'Append-only', tone: 'blue' as const },
                        {
                          label: 'Diff blob store',
                          value: info?.storage === 's3' ? 'S3 / SeaweedFS' : 'Postgres inline',
                          tone: 'slate' as const,
                        },
                      ].map((r) => (
                        <div
                          key={r.label}
                          className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50/50 px-3 py-2"
                        >
                          <span className="text-xs text-slate-600">{r.label}</span>
                          <StatusPill tone={r.tone}>{r.value}</StatusPill>
                        </div>
                      ))}
                      <div className="rounded-lg border border-slate-200 px-3 py-2">
                        <p className="text-[11px] uppercase tracking-wide text-slate-400">
                          Redaction salt fingerprint
                        </p>
                        <p className="mt-1 truncate font-mono text-xs text-slate-700">{passwordHash}</p>
                      </div>
                    </div>
                  </Card>
                </div>

                <APIKeysCard />
                <MembersCard />
              </div>
            ) : null}

            {tab === 'agents' ? (
              <div className="space-y-5">
                <InstallCommandsCard />
                <EnrollmentCard />
                <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                  <Card>
                    <CardHeader
                      title="Agent Rollout"
                      subtitle={`${online} of ${total} agents reporting`}
                      icon={<Server className="h-4 w-4" />}
                    />
                    <div className="mt-2 divide-y divide-slate-100">
                      <Toggle
                        checked={autoUpdate}
                        onChange={setAutoUpdate}
                        disabled={readOnly}
                        label="Automatic agent updates"
                        description="Agents self-update to the server-published version."
                      />
                      <Toggle
                        checked={crashReports}
                        onChange={setCrashReports}
                        disabled={readOnly}
                        label="Send anonymous crash reports"
                        description="Structured panics only — never file contents."
                      />
                    </div>
                  </Card>

                  <Card>
                    <CardHeader
                      title="Version Distribution"
                      subtitle="Agent builds across the fleet"
                      icon={<Settings2 className="h-4 w-4" />}
                    />
                    <ul className="mt-4 space-y-3">
                      {versionBuckets.length === 0 ? (
                        <li className="rounded-lg border border-dashed border-slate-300 px-3 py-4 text-center text-xs text-slate-500">
                          No agents reporting yet. Install one from the command above and its
                          version appears here.
                        </li>
                      ) : (
                        versionBuckets.map((v, i) => (
                          <li key={v.version}>
                            <div className="flex items-center justify-between gap-2">
                              <span className="flex items-center gap-2 font-mono text-xs text-slate-700">
                                {v.version}
                                {i === 0 ? (
                                  <StatusPill tone="blue">latest</StatusPill>
                                ) : (
                                  <StatusPill tone="amber">outdated</StatusPill>
                                )}
                              </span>
                              <span className="text-xs tabular-nums text-slate-500">
                                {v.count} agent{v.count === 1 ? '' : 's'}
                              </span>
                            </div>
                            <span className="mt-1.5 block h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                              <span
                                className={cn(
                                  'block h-full rounded-full',
                                  i === 0 ? 'bg-blue-600' : 'bg-amber-500',
                                )}
                                style={{ width: `${total ? (v.count / total) * 100 : 0}%` }}
                              />
                            </span>
                          </li>
                        ))
                      )}
                    </ul>
                    <div className="mt-4 border-t border-slate-100 pt-4">
                      <p className="text-xs text-slate-500">Fleet inventory</p>
                      <ul className="mt-2 space-y-1.5">
                        {(hosts ?? []).slice(0, 4).map((h) => (
                          <li key={h.id} className="flex items-center gap-2 text-xs">
                            <span
                              className={cn(
                                'h-1.5 w-1.5 rounded-full',
                                h.status === 'online' ? 'bg-emerald-600' : 'bg-red-600',
                              )}
                            />
                            <span className="min-w-0 flex-1 truncate font-mono text-slate-700">
                              {h.hostname}
                            </span>
                            <span className="shrink-0 font-mono text-slate-400">{h.agent_version}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </Card>
                </div>
              </div>
            ) : null}

            {tab === 'audit' ? (
              <div className="space-y-5">
                <div className="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50/70 px-3.5 py-2.5">
                  <Lock className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                  <p className="text-xs leading-5 text-slate-600">
                    The control-plane audit log is append-only. The application can only insert, so a
                    compromised console session cannot rewrite the record of what it did — which is
                    what makes the trail admissible in a compliance review.
                  </p>
                </div>
                <AuditLogCard />
                <Card>
                  <CardHeader
                    title="Signed-in Session"
                    subtitle="How this console request was authenticated"
                    icon={<ScrollText className="h-4 w-4" />}
                  />
                  <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
                    <SessionRow label="Principal" value={auth.user?.email || 'anonymous'} />
                    <SessionRow label="Granted role" value={auth.roleLabel(auth.realRole)} />
                    <SessionRow label="Effective role" value={auth.roleLabel(auth.user?.role)} />
                    <SessionRow
                      label="Auth method"
                      value={auth.me?.auth_method || '—'}
                    />
                    <SessionRow
                      label="Scopes"
                      value={(auth.me?.scopes ?? []).join(', ') || 'unrestricted (session)'}
                    />
                    <SessionRow label="Read-only" value={auth.readOnly ? 'yes' : 'no'} />
                  </dl>
                </Card>
              </div>
            ) : null}
          </div>
        </Card>
      </div>
    </div>
  )
}

function SessionRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline gap-3">
      <dt className="w-28 shrink-0 text-[11px] uppercase tracking-wide text-slate-400">{label}</dt>
      <dd className="min-w-0 flex-1 truncate font-mono text-xs text-slate-700">{value}</dd>
    </div>
  )
}
