import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  MessageSquare,
  RefreshCw,
  Save,
  Send,
  ShieldCheck,
  Siren,
  Webhook,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader, SectionTitle } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import StatusPill from '../ui/StatusPill'
import { Button, Field, Select, TextInput, Toggle } from '../ui/controls'
import { useWebhookChannels, useWebhookTest } from '../../api/hooks'
import { useReadOnly } from '../../lib/authContext'
import type {
  WebhookChannel,
  WebhookChannelUpdate,
  WebhookDelivery,
  WebhookProvider,
  WebhookTestResponse,
} from '../../types'
import { formatDateTime, cn } from '../../lib/utils'

/**
 * Per-provider presentation: the icon, the credential field, and the copy that
 * explains what the operator is pasting where.
 *
 * Kept as data rather than four near-identical JSX blocks so the four cards
 * cannot drift in which fields they render — the actual failure mode of a
 * hand-written provider matrix.
 */
interface ProviderSpec {
  provider: WebhookProvider
  title: string
  subtitle: string
  icon: typeof MessageSquare
  /** Credential field label. Empty means the provider needs no secret. */
  secretLabel?: string
  secretPlaceholder?: string
  secretHint?: string
  urlLabel: string
  urlPlaceholder: string
  urlHint?: string
  /** Shown above the trigger checkboxes. */
  triggerHint: string
}

const SPECS: ProviderSpec[] = [
  {
    provider: 'teams',
    title: 'Microsoft Teams',
    subtitle: 'MessageCard delivered to a channel incoming webhook or Workflows URL',
    icon: MessageSquare,
    urlLabel: 'Incoming Webhook / Workflows URL',
    urlPlaceholder: 'https://outlook.office.com/webhook/…',
    urlHint:
      'Teams → channel → Connectors → Incoming Webhook, or a Power Automate "When a Teams webhook request is received" URL.',
    triggerHint: 'Which changes are posted to this channel.',
  },
  {
    provider: 'slack',
    title: 'Slack',
    subtitle: 'Block Kit message with a one-click Inspect Diff button',
    icon: MessageSquare,
    urlLabel: 'Webhook URL',
    // Ellipsis rather than a token-shaped example: a fake but well-formed
    // webhook URL in source trips secret scanners for a string that was never a
    // credential.
    urlPlaceholder: 'https://hooks.slack.com/services/…',
    secretLabel: 'Channel',
    secretPlaceholder: '#infra-alerts',
    secretHint: 'Display only — shown on the card so the target channel is obvious.',
    triggerHint: 'Which changes are posted to this channel.',
  },
  {
    provider: 'pagerduty',
    title: 'PagerDuty',
    subtitle: 'Events API v2 trigger, deduplicated per change so a retry does not re-page',
    icon: Siren,
    urlLabel: 'Events API v2 endpoint',
    urlPlaceholder: 'https://events.pagerduty.com/v2/enqueue',
    secretLabel: 'Routing Key',
    secretPlaceholder: 'R0UT1NGK3Y…',
    secretHint: 'Service → Integrations → Events API v2 → Integration Key.',
    triggerHint: 'Which changes open an incident.',
  },
  {
    provider: 'webhook',
    title: 'Generic SIEM Webhook',
    subtitle: 'Signed JSON for Splunk, Microsoft Sentinel, QRadar or any log shipper',
    icon: Webhook,
    urlLabel: 'Target URL',
    urlPlaceholder: 'https://siem.example.com/ingest/statetrack',
    secretLabel: 'HMAC-SHA256 Secret',
    secretPlaceholder: 'leave blank to send unsigned',
    secretHint: 'Compute the digest over the raw request body to verify authenticity.',
    triggerHint: 'Which changes are forwarded to the collector.',
  },
]

const SIGNATURE_HEADER = 'X-StateTrack-Signature: sha256=<hmac>'

/**
 * ChatOps, Paging & SIEM tab.
 *
 * Four provider cards plus the delivery log. Each card saves only its own
 * fields, so saving Teams never rewrites the Slack or PagerDuty secret, and a
 * "Send Test" posts through the same dispatcher a real change would use — which
 * is the only way to actually prove credentials work.
 */
export default function ChatOpsTab() {
  const feed = useWebhookChannels()

  return (
    <div className="space-y-5">
      <SectionTitle
        hint="Every outbound notification channel. Each card saves independently and can send a real test."
        actions={
          <div className="flex items-center gap-2">
            {feed.isFallback ? (
              <StatusPill tone="amber" dot>
                Preview data
              </StatusPill>
            ) : null}
            {feed.saveError ? (
              <span className="flex items-center gap-1.5 text-xs font-medium text-red-700">
                <XCircle className="h-3.5 w-3.5" /> {feed.saveError}
              </span>
            ) : feed.lastSavedProvider ? (
              <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                <CheckCircle2 className="h-3.5 w-3.5" /> Saved
              </span>
            ) : null}
          </div>
        }
      >
        Channels
      </SectionTitle>

      {feed.isError && !feed.isFallback ? (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Could not load the saved channels. Showing defaults — saving will overwrite what is
            stored.
          </span>
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {SPECS.map((spec) => (
          <ChannelCard
            key={spec.provider}
            spec={spec}
            channel={(feed.channels ?? []).find((c) => c.provider === spec.provider)}
            onSave={feed.save}
            isSaving={feed.isSaving}
          />
        ))}
      </div>

      <DeliveryLog deliveries={feed.deliveries} />
    </div>
  )
}

function ChannelCard({
  spec,
  channel,
  onSave,
  isSaving,
}: {
  spec: ProviderSpec
  channel: WebhookChannel | undefined
  onSave: (update: WebhookChannelUpdate) => void
  isSaving: boolean
}) {
  const Icon = spec.icon
  const test = useWebhookTest()
  const readOnly = useReadOnly()
  const [result, setResult] = useState<WebhookTestResponse | null>(null)

  // Local form state, reseeded when the server's copy changes. A partial save
  // would otherwise write back the stale values the form is still holding.
  const [url, setUrl] = useState(channel?.url ?? '')
  const [secret, setSecret] = useState('')
  const [enabled, setEnabled] = useState(channel?.enabled ?? false)
  const [notifyL1, setNotifyL1] = useState(channel?.notify_l1 ?? true)
  const [notifyStorms, setNotifyStorms] = useState(channel?.notify_storms ?? true)
  const [severity, setSeverity] = useState(channel?.severity || 'critical')

  useEffect(() => {
    if (!channel) return
    setUrl(channel.url)
    setEnabled(channel.enabled)
    setNotifyL1(channel.notify_l1)
    setNotifyStorms(channel.notify_storms)
    setSeverity(channel.severity || 'critical')
    // The secret is intentionally NOT reseeded: the API never returns it, so
    // there is nothing to seed and echoing a masked value back on save would
    // overwrite a working credential with "…abcd".
  }, [channel])

  const lastDelivery = channel?.last_delivery
  // A test in flight outranks the stored result; otherwise show the newest
  // recorded attempt so the badge reflects reality before anything is clicked.
  const status = test.data ?? result ?? null
  const healthy = status?.ok ?? (lastDelivery ? lastDelivery.success : null)
  const dirty =
    url !== (channel?.url ?? '') ||
    enabled !== (channel?.enabled ?? false) ||
    notifyL1 !== (channel?.notify_l1 ?? true) ||
    notifyStorms !== (channel?.notify_storms ?? true) ||
    secret.trim() !== '' ||
    (spec.provider === 'pagerduty' && severity !== (channel?.severity || 'critical'))

  const handleSave = () => {
    const update: WebhookChannelUpdate = {
      provider: spec.provider,
      url: url.trim(),
      enabled,
      notify_l1: notifyL1,
      notify_storms: notifyStorms,
    }
    // Omitted when blank: an absent token keeps the stored one, whereas an empty
    // string would clear it.
    if (secret.trim()) update.token = secret.trim()
    if (spec.provider === 'slack') update.label = secret.trim()
    if (spec.provider === 'pagerduty') update.severity = severity
    onSave(update)
    setSecret('')
  }

  const handleTest = () => {
    // Prefer a target saved server-side; otherwise the inline one. The request
    // deliberately does not send the stored secret back — the server reads it
    // from the database, so the value never has to leave the backend.
    const target = url.trim() === (channel?.url ?? '') ? undefined : url.trim()
    test.mutate(
      {
        provider: spec.provider,
        url: target ?? '',
        secret: secret.trim() || undefined,
        sample: 'mutation',
      },
      { onSuccess: (res) => setResult(res) },
    )
  }

  return (
    <Card className="flex flex-col">
      <CardHeader
        title={spec.title}
        subtitle={spec.subtitle}
        icon={<Icon className="h-4 w-4" />}
        actions={
          <div className="flex items-center gap-2">
            {healthy === false ? (
              <StatusPill tone="red" dot>
                Delivery failing
              </StatusPill>
            ) : healthy === true ? (
              <StatusPill tone="green" dot>
                Last delivery ok
              </StatusPill>
            ) : null}
            {enabled ? (
              <StatusPill tone="green" dot>
                Enabled
              </StatusPill>
            ) : (
              <StatusPill tone="slate" dot>
                Disabled
              </StatusPill>
            )}
          </div>
        }
      />

      <div className="mt-4 flex-1 space-y-4">
        <Field label={spec.urlLabel} hint={spec.urlHint} htmlFor={`${spec.provider}-url`}>
          <TextInput
            id={`${spec.provider}-url`}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={spec.urlPlaceholder}
            className="font-mono text-xs"
          />
        </Field>

        {spec.secretLabel ? (
          <Field
            label={spec.secretLabel}
            hint={
              spec.provider === 'webhook' ? (
                <span className="flex flex-wrap items-center gap-1.5">
                  <span>{spec.secretHint}</span>
                  <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[10px] text-slate-600">
                    {SIGNATURE_HEADER}
                  </span>
                </span>
              ) : (
                spec.secretHint
              )
            }
            htmlFor={`${spec.provider}-secret`}
          >
            <TextInput
              id={`${spec.provider}-secret`}
              type={spec.provider === 'webhook' ? 'password' : 'text'}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={
                channel?.token_set ? 'stored — leave blank to keep' : spec.secretPlaceholder
              }
              className="font-mono text-xs"
            />
          </Field>
        ) : null}

        {spec.provider === 'pagerduty' ? (
          <Field
            label="Severity"
            hint="Maps onto the Events API severity. Leave as-is to escalate in PagerDuty instead."
            htmlFor="pagerduty-severity"
          >
            <Select
              id="pagerduty-severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {['critical', 'error', 'warning', 'info'].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </Field>
        ) : null}

        <div className="border-t border-slate-100 pt-2">
          <p className="py-2 text-xs font-medium text-slate-700">Triggers</p>
          <div className="divide-y divide-slate-100">
            <Toggle
              checked={notifyL1}
              onChange={setNotifyL1}
              label="Level 1 Critical"
              description="Config, identity and service changes."
            />
            <Toggle
              checked={notifyStorms}
              onChange={setNotifyStorms}
              label="Change Storms"
              description="Agent circuit-breaker activations."
            />
          </div>
          <p className="pt-1 text-[11px] text-slate-400">{spec.triggerHint}</p>
        </div>

        <div className="border-t border-slate-100 pt-2">
          <Toggle
            checked={enabled}
            onChange={setEnabled}
            label="Enable this channel"
            description={
              url.trim()
                ? 'Deliveries continue even after the console is closed.'
                : 'A target URL is required before this can be enabled.'
            }
            disabled={!url.trim() && !enabled}
          />
        </div>

        {/* Test result */}
        {status ? (
          <div
            className={cn(
              'flex items-start gap-2 rounded-lg border px-3 py-2 text-xs',
              status.ok
                ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
                : 'border-red-200 bg-red-50 text-red-800',
            )}
          >
            {status.ok ? (
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            ) : (
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            )}
            <div className="min-w-0">
              <div className="font-medium">
                {status.ok ? 'Delivered' : 'Delivery failed'} · HTTP {status.status || '—'} ·{' '}
                {status.attempts} attempt{status.attempts === 1 ? '' : 's'}
                {'latency_ms' in status && typeof status.latency_ms === 'number'
                  ? ` · ${status.latency_ms} ms`
                  : ''}
              </div>
              <div className="break-words">{status.detail}</div>
              {'signature' in status && status.signature ? (
                <div className="mt-1 break-all font-mono text-[10px] text-slate-600">
                  {status.signature}
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        {test.isError ? (
          <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
            <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>{test.error instanceof Error ? test.error.message : 'Request failed'}</span>
          </div>
        ) : null}

        {test.data?.rendered ? (
          <details className="rounded-lg border border-slate-200 bg-slate-50">
            <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-slate-700">
              Payload that was sent
            </summary>
            <pre className="max-h-72 overflow-auto px-3 pb-3 font-mono text-[10px] leading-relaxed text-slate-700">
              {test.data.rendered}
            </pre>
          </details>
        ) : null}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-4">
        <Button
          variant="primary"
          icon={isSaving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          disabled={readOnly || isSaving || !dirty}
          onClick={handleSave}
          title={readOnly ? 'Read-only session — saving is disabled' : undefined}
        >
          {isSaving ? 'Saving…' : 'Save'}
        </Button>
        <Button
          icon={
            test.isPending ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />
          }
          disabled={readOnly || test.isPending || (!url.trim() && !channel?.url)}
          onClick={handleTest}
          title={
            readOnly
              ? 'Read-only session — sending a test is disabled'
              : url.trim()
                ? 'Sends a sample change using this URL'
                : 'Sends a sample change using the saved configuration'
          }
        >
          {test.isPending ? 'Sending…' : `Send Test to ${spec.title.split(' ')[0]}`}
        </Button>
        {lastDelivery ? (
          <span className="ml-auto flex items-center gap-1.5 text-[11px] text-slate-400">
            {lastDelivery.success ? (
              <CheckCircle2 className="h-3 w-3 text-emerald-600" />
            ) : (
              <XCircle className="h-3 w-3 text-red-600" />
            )}
            Last {formatDateTime(lastDelivery.created_at)}
          </span>
        ) : null}
      </div>
    </Card>
  )
}

/* -------------------------------------------------------------------------- */
/* Delivery log                                                               */
/* -------------------------------------------------------------------------- */

const PROVIDER_TONE: Record<string, 'blue' | 'purple' | 'amber' | 'cyan' | 'slate'> = {
  teams: 'blue',
  slack: 'purple',
  pagerduty: 'amber',
  webhook: 'cyan',
}

function DeliveryLog({ deliveries }: { deliveries: WebhookDelivery[] }) {
  const rows = useMemo(() => deliveries ?? [], [deliveries])

  const columns: DataTableColumn<WebhookDelivery>[] = useMemo(
    () => [
      {
        key: 'time',
        header: 'Timestamp',
        cell: (d) => (
          <span className="whitespace-nowrap font-mono text-xs tabular-nums text-slate-500">
            {formatDateTime(d.created_at)}
          </span>
        ),
      },
      {
        key: 'provider',
        header: 'Provider',
        cell: (d) => (
          <div className="flex items-center gap-1.5">
            <StatusPill tone={PROVIDER_TONE[d.provider] ?? 'slate'} mono>
              {d.provider}
            </StatusPill>
            {d.sample ? <StatusPill tone="slate">test</StatusPill> : null}
          </div>
        ),
      },
      {
        key: 'status',
        header: 'HTTP',
        cell: (d) => (
          <span
            className={cn(
              'font-mono text-xs tabular-nums',
              d.success ? 'text-emerald-700' : 'text-red-700',
            )}
          >
            {d.status_code || '—'}
          </span>
        ),
      },
      {
        key: 'latency',
        header: 'Latency',
        align: 'right',
        cell: (d) => (
          <span className="font-mono text-xs tabular-nums text-slate-600">
            {d.latency_ms} ms
          </span>
        ),
      },
      {
        key: 'attempts',
        header: 'Attempts',
        align: 'right',
        cell: (d) => <span className="text-xs tabular-nums text-slate-500">{d.attempts}</span>,
      },
      {
        key: 'result',
        header: 'Result',
        cell: (d) =>
          d.success ? (
            <StatusPill tone="green" dot>
              Delivered
            </StatusPill>
          ) : (
            <span className="flex items-center gap-1.5">
              <StatusPill tone="red" dot>
                Failed
              </StatusPill>
              {d.error ? (
                <span className="max-w-[18rem] truncate text-[11px] text-slate-500" title={d.error}>
                  {d.error}
                </span>
              ) : null}
            </span>
          ),
      },
    ],
    [],
  )

  return (
    <Card flush>
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
        <CardHeader
          className="min-w-0 flex-1"
          title="Recent Webhook Deliveries"
          subtitle="Real sends and console tests, newest first"
          icon={<BellRing className="h-4 w-4" />}
        />
        <div className="flex items-center gap-2">
          <StatusPill tone="green" dot>
            {(rows ?? []).filter((d) => d.success).length} delivered
          </StatusPill>
          <StatusPill tone={(rows ?? []).some((d) => !d.success) ? 'red' : 'slate'} dot>
            {(rows ?? []).filter((d) => !d.success).length} failed
          </StatusPill>
        </div>
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(d) => String(d.id)}
        pageSize={8}
        empty="No deliveries yet. Save a channel and send a test."
      />
      <p className="flex items-center gap-1.5 border-t border-slate-100 px-4 py-2.5 text-[11px] text-slate-400">
        <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
        Signing secrets are never logged or returned to the browser.
      </p>
    </Card>
  )
}
