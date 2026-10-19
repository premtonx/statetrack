import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCopy,
  Cpu,
  Download,
  Network,
  RefreshCw,
  Save,
  ShieldCheck,
  Sparkles,
  Terminal,
  TestTube2,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader, SectionTitle } from '../ui/Card'
import StatusPill from '../ui/StatusPill'
import { Button, Field, Select, TextInput, Toggle } from '../ui/controls'
import { CodeBlock } from './AssetActions'
import { useAIIntegration } from '../../api/hooks'
import { useReadOnly } from '../../lib/authContext'
import { copyText, downloadText } from '../../lib/integrationAssets'
import { cn, formatDateTime } from '../../lib/utils'
import type { AIProvider, AISettingsResponse, AITestResponse } from '../../types'

/**
 * Per-provider presentation for the AI card.
 *
 * Kept as data rather than five near-identical JSX blocks so the providers
 * cannot drift in which fields they render — the actual failure mode of a
 * hand-written provider matrix. `needsKey` and `needsEndpoint` describe what the
 * engine requires; the server enforces the same rules, so a form that hides an
 * irrelevant field cannot disagree with a 400.
 */
interface ProviderSpec {
  id: AIProvider
  label: string
  subtitle: string
  endpointLabel: string
  endpointPlaceholder: string
  modelLabel: string
  modelPlaceholder: string
  needsKey: boolean
  needsEndpoint: boolean
  needsAPIVersion: boolean
  /** Where the model runs, in one phrase, for the "who sees my data" question. */
  residency: string
  keyHint: string
}

const PROVIDERS: ProviderSpec[] = [
  {
    id: 'deterministic',
    label: 'Built-in Offline Heuristics',
    subtitle: 'No model, no key, no network — derived from the event and its scrubbed diff',
    endpointLabel: 'Endpoint',
    endpointPlaceholder: '',
    modelLabel: 'Engine',
    modelPlaceholder: '',
    needsKey: false,
    needsEndpoint: false,
    needsAPIVersion: false,
    residency: 'Nothing leaves this deployment.',
    keyHint: '',
  },
  {
    id: 'ollama',
    label: 'Local Ollama',
    subtitle: 'OpenAI-compatible endpoint on your own network — works air-gapped',
    endpointLabel: 'Ollama base URL',
    endpointPlaceholder: 'http://localhost:11434/v1',
    modelLabel: 'Model',
    modelPlaceholder: 'llama3.1',
    needsKey: false,
    needsEndpoint: true,
    needsAPIVersion: false,
    residency: 'Stays on your network. No external internet access required.',
    keyHint: 'Optional — set a key only if your Ollama proxy requires one.',
  },
  {
    id: 'azure_openai',
    label: 'Azure OpenAI',
    subtitle: 'A deployment inside your own Azure tenant, using the api-key header',
    endpointLabel: 'Resource endpoint',
    endpointPlaceholder: 'https://my-resource.openai.azure.com',
    modelLabel: 'Deployment name',
    modelPlaceholder: 'gpt-4o-deployment',
    needsKey: true,
    needsEndpoint: true,
    needsAPIVersion: true,
    residency: 'Sent to your Azure OpenAI resource in your tenant.',
    keyHint: 'Resource key, sent as the api-key header.',
  },
  {
    id: 'openai',
    label: 'OpenAI',
    subtitle: 'The public OpenAI API, authenticated with a bearer key',
    endpointLabel: 'API base URL',
    endpointPlaceholder: 'https://api.openai.com/v1',
    modelLabel: 'Model',
    modelPlaceholder: 'gpt-4o-mini',
    needsKey: true,
    needsEndpoint: true,
    needsAPIVersion: false,
    residency: 'Sent to OpenAI. Review your data-handling agreement first.',
    keyHint: 'Bearer token, stored encrypted and never returned.',
  },
  {
    id: 'anthropic',
    label: 'Anthropic',
    subtitle: 'The Anthropic Messages API, authenticated with an x-api-key header',
    endpointLabel: 'API base URL',
    endpointPlaceholder: 'https://api.anthropic.com',
    modelLabel: 'Model',
    modelPlaceholder: 'claude-3-5-sonnet-latest',
    needsKey: true,
    needsEndpoint: true,
    needsAPIVersion: false,
    residency: 'Sent to Anthropic. Review your data-handling agreement first.',
    keyHint: 'API key, sent as the x-api-key header.',
  },
]

function specFor(provider: AIProvider): ProviderSpec {
  return PROVIDERS.find((p) => p.id === provider) ?? PROVIDERS[0]
}

/**
 * AI & MCP Server tab.
 *
 * Two audiences on one screen, which is deliberate: the model that answers the
 * Inspector drawer's "Analyze & Rollback", and the MCP server that lets an
 * engineer drive StateTrack from Cursor or Claude Desktop. Both are "the AI
 * surface" of the product, both are opt-in, and neither puts anything on the
 * main dashboard.
 */
export default function AIMcpTab() {
  const readOnly = useReadOnly()
  const feed = useAIIntegration()
  const { settings } = feed

  const spec = specFor(settings.provider)

  return (
    <div className="space-y-5">
      <SectionTitle
        hint="Choose the engine behind the Inspector's Analyze & Rollback, and connect a desktop client to the MCP server."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {feed.isFallback ? (
              <StatusPill tone="amber" dot>
                Preview data
              </StatusPill>
            ) : null}
            <EngineBadge settings={settings} testResult={feed.testResult} />
          </div>
        }
      >
        AI Provider &amp; MCP Server
      </SectionTitle>

      {feed.isError && !feed.isFallback ? (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Could not load the saved AI configuration. Showing defaults — saving will overwrite what
            is stored.
          </span>
        </div>
      ) : null}

      <ProviderCard spec={spec} settings={settings} feed={feed} readOnly={readOnly} />
      <McpClientSetupCard />
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Engine badge                                                                */
/* -------------------------------------------------------------------------- */

function EngineBadge({
  settings,
  testResult,
}: {
  settings: AISettingsResponse
  testResult: AITestResponse | null
}) {
  const ok = testResult?.ok ?? (settings.last_test_ok || null)
  const spec = specFor(settings.provider)
  if (settings.provider === 'deterministic') {
    return (
      <StatusPill tone="slate" dot>
        Offline heuristics — always available
      </StatusPill>
    )
  }
  if (ok === true) {
    return (
      <StatusPill tone="green" dot>
        {spec.label} reachable
      </StatusPill>
    )
  }
  if (ok === false) {
    return (
      <StatusPill tone="red" dot>
        {spec.label} unreachable
      </StatusPill>
    )
  }
  return (
    <StatusPill tone="blue" dot>
      {spec.label} — not verified
    </StatusPill>
  )
}

/* -------------------------------------------------------------------------- */
/* Provider card                                                               */
/* -------------------------------------------------------------------------- */

function ProviderCard({
  spec,
  settings,
  feed,
  readOnly,
}: {
  spec: ProviderSpec
  settings: AISettingsResponse
  feed: ReturnType<typeof useAIIntegration>
  readOnly: boolean
}) {
  const [provider, setProvider] = useState<AIProvider>(settings.provider)
  const [endpoint, setEndpoint] = useState(settings.endpoint)
  const [model, setModel] = useState(settings.model)
  const [apiVersion, setApiVersion] = useState(settings.api_version ?? '')
  const [key, setKey] = useState('')
  const [enabled, setEnabled] = useState(settings.enabled)

  // Reseed the form when the server's copy changes. The key is intentionally NOT
  // reseeded: the API never returns it, and echoing a masked value back on save
  // would overwrite a working credential.
  useEffect(() => {
    setProvider(settings.provider)
    setEndpoint(settings.endpoint)
    setModel(settings.model)
    setApiVersion(settings.api_version ?? '')
    setEnabled(settings.enabled)
  }, [settings])

  const dirty =
    provider !== settings.provider ||
    endpoint !== settings.endpoint ||
    model !== settings.model ||
    apiVersion !== (settings.api_version ?? '') ||
    enabled !== settings.enabled ||
    key.trim() !== ''

  const test = feed.testResult

  const handleSave = () => {
    feed.save({
      provider,
      endpoint: endpoint.trim(),
      model: model.trim(),
      api_version: apiVersion.trim(),
      enabled,
      // Omitted when blank: an absent key keeps the stored one, whereas an empty
      // string would clear it.
      ...(key.trim() ? { api_key: key.trim() } : {}),
    })
    setKey('')
  }

  return (
    <Card>
      <CardHeader
        title="Analysis engine"
        subtitle="Runs when an operator clicks ✦ Analyze & Rollback in the Inspector drawer"
        icon={<Sparkles className="h-4 w-4" />}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {settings.api_key_set ? (
              <StatusPill tone="green" dot>
                Key stored
              </StatusPill>
            ) : spec.needsKey ? (
              <StatusPill tone="amber" dot>
                No key
              </StatusPill>
            ) : null}
            <StatusPill tone={settings.needs_network ? 'blue' : 'slate'} dot>
              {settings.needs_network ? 'Sends data to model' : 'Fully local'}
            </StatusPill>
          </div>
        }
      />

      <div className="mt-4 grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="space-y-4">
          <Field
            label="Provider"
            hint={spec.subtitle}
            htmlFor="ai-provider"
          >
            <Select
              id="ai-provider"
              value={provider}
              onChange={(e) => setProvider(e.target.value as AIProvider)}
              disabled={readOnly}
            >
              {PROVIDERS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </Select>
          </Field>

          {spec.needsEndpoint ? (
            <Field label={spec.endpointLabel} htmlFor="ai-endpoint">
              <TextInput
                id="ai-endpoint"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder={spec.endpointPlaceholder}
                className="font-mono text-xs"
                disabled={readOnly}
              />
            </Field>
          ) : null}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {spec.needsEndpoint || spec.id === 'ollama' ? (
              <Field label={spec.modelLabel} htmlFor="ai-model">
                <TextInput
                  id="ai-model"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder={spec.modelPlaceholder}
                  className="font-mono text-xs"
                  disabled={readOnly}
                />
              </Field>
            ) : null}
            {spec.needsAPIVersion ? (
              <Field
                label="API version"
                hint="Required by Azure OpenAI (e.g. 2024-10-21)."
                htmlFor="ai-api-version"
              >
                <TextInput
                  id="ai-api-version"
                  value={apiVersion}
                  onChange={(e) => setApiVersion(e.target.value)}
                  placeholder="2024-10-21"
                  className="font-mono text-xs"
                  disabled={readOnly}
                />
              </Field>
            ) : null}
          </div>

          {spec.needsKey || spec.id === 'ollama' ? (
            <Field
              label="API key"
              hint={
                settings.api_key_set
                  ? 'A key is stored. Leaving this blank keeps it.'
                  : spec.keyHint || 'Stored encrypted at rest and never returned by the API.'
              }
              htmlFor="ai-key"
            >
              <TextInput
                id="ai-key"
                type="password"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder={settings.api_key_set ? '••••••••  (unchanged)' : 'Paste the credential'}
                className="font-mono text-xs"
                disabled={readOnly}
              />
            </Field>
          ) : null}

          <div className="border-t border-slate-100 pt-2">
            <Toggle
              checked={enabled}
              onChange={setEnabled}
              disabled={readOnly}
              label="Enable live model calls"
              description="When off, the analyzer uses the built-in offline heuristics without attempting the network — a way to pause a misbehaving model without deleting its configuration."
            />
          </div>

          <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-3">
            <Button
              variant="primary"
              size="sm"
              icon={
                feed.isSaving ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Save className="h-3.5 w-3.5" />
                )
              }
              disabled={readOnly || feed.isSaving || !dirty}
              onClick={handleSave}
            >
              {feed.isSaving ? 'Saving…' : 'Save'}
            </Button>
            <Button
              size="sm"
              icon={
                feed.isTesting ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <TestTube2 className="h-3.5 w-3.5" />
                )
              }
              disabled={readOnly || feed.isTesting}
              onClick={feed.test}
              title="Runs the real provider path against a synthetic change"
            >
              {feed.isTesting ? 'Testing…' : 'Test AI Connection'}
            </Button>
            {feed.saveError ? (
              <span className="flex items-center gap-1.5 text-xs font-medium text-red-700">
                <XCircle className="h-3.5 w-3.5" /> {feed.saveError}
              </span>
            ) : feed.savedAt ? (
              <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                <CheckCircle2 className="h-3.5 w-3.5" /> Saved
              </span>
            ) : (
              <span className="text-xs text-slate-400">{dirty ? 'Unsaved changes' : 'No changes'}</span>
            )}
          </div>

          {test ? <TestResult result={test} /> : null}
        </div>

        {/* What actually runs, and where the data goes. */}
        <aside className="space-y-3 rounded-lg border border-slate-200 bg-slate-50/60 p-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              Effective configuration
            </p>
            <dl className="mt-2 space-y-2 text-[11px]">
              <div>
                <dt className="text-slate-400">Endpoint</dt>
                <dd className="break-all font-mono text-slate-700">
                  {settings.effective_endpoint || '—'}
                </dd>
              </div>
              <div>
                <dt className="text-slate-400">Model</dt>
                <dd className="font-mono text-slate-700">{settings.effective_model || '—'}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Timeout</dt>
                <dd className="font-mono text-slate-700">{settings.timeout_seconds}s per analysis</dd>
              </div>
            </dl>
          </div>
          <div className="border-t border-slate-200 pt-3">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              <Network className="h-3 w-3" /> Data residency
            </p>
            <p className="mt-1 text-[11px] leading-relaxed text-slate-500">{spec.residency}</p>
          </div>
          <div className="border-t border-slate-200 pt-3">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
              <ShieldCheck className="h-3 w-3" /> Zero-secret guarantee
            </p>
            <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
              Only the already-scrubbed diff is ever sent. Secrets were replaced with{' '}
              <span className="font-mono">[REDACTED:sha256:…]</span> stubs at the host.
            </p>
          </div>
        </aside>
      </div>
    </Card>
  )
}

function TestResult({ result }: { result: AITestResponse }) {
  return (
    <div
      className={cn(
        'flex items-start gap-2 rounded-lg border px-3 py-2 text-xs',
        result.ok
          ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
          : 'border-red-200 bg-red-50 text-red-800',
      )}
    >
      {result.ok ? (
        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      ) : (
        <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      )}
      <div className="min-w-0">
        <div className="font-medium">
          {result.ok ? 'Connection verified' : 'Connection failed'}
          {result.latency_ms > 0 ? ` · ${result.latency_ms} ms` : ''} ·{' '}
          {formatDateTime(result.checked_at)}
        </div>
        <div className="break-words">{result.detail}</div>
        {result.blast_check ? (
          <div className="mt-1 rounded border border-black/5 bg-white/60 px-2 py-1 font-mono text-[10px] leading-relaxed">
            sample → {result.blast_check}
          </div>
        ) : null}
      </div>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* MCP client setup                                                            */
/* -------------------------------------------------------------------------- */

/**
 * The MCP tool surface, mirroring `mcp.ToolNames` on the server. Listed here so
 * an engineer can see what their assistant will be able to do before wiring up
 * a client, without reading the docs.
 */
const MCP_TOOLS = [
  { name: 'statetrack_list_changes', hint: 'Find the change behind an incident' },
  { name: 'statetrack_get_diff', hint: 'Scrubbed diff + actor lineage' },
  { name: 'statetrack_get_host_summary', hint: 'Online status, drift and recent critical change' },
  { name: 'statetrack_analyze_and_rollback', hint: 'Blast radius + rollback command' },
  { name: 'statetrack_export_postmortem', hint: 'Markdown incident bundle' },
]

function McpClientSetupCard() {
  const [copied, setCopied] = useState<string | null>(null)

  // The MCP endpoint is the console's own origin, so the snippet is correct
  // whether the operator is on :5173 behind the dev proxy or a production host.
  const base = typeof window === 'undefined' ? 'http://localhost:8080' : window.location.origin

  const mcpConfig = useMemo(
    () =>
      JSON.stringify(
        {
          mcpServers: {
            statetrack: {
              command: 'statetrack-mcp',
              env: {
                STATETRACK_URL: base.replace(/\/api\/v1\/?$/, ''),
                STATETRACK_API_KEY: 'st_live_...',
              },
            },
          },
        },
        null,
        2,
      ),
    [base],
  )

  const httpConfig = useMemo(
    () =>
      JSON.stringify(
        {
          mcpServers: {
            statetrack: {
              url: `${base.replace(/\/$/, '')}/api/v1/mcp`,
              headers: { Authorization: 'Bearer st_live_...' },
            },
          },
        },
        null,
        2,
      ),
    [base],
  )

  useEffect(() => {
    if (!copied) return
    const t = window.setTimeout(() => setCopied(null), 1800)
    return () => window.clearTimeout(t)
  }, [copied])

  const copy = async (id: string, text: string) => {
    setCopied((await copyText(text)) ? id : null)
  }

  return (
    <Card>
      <CardHeader
        title="MCP Client Setup"
        subtitle="Point Cursor, Claude Desktop or Windsurf at the StateTrack MCP server"
        icon={<Cpu className="h-4 w-4" />}
        actions={
          <StatusPill tone="purple" dot>
            JSON-RPC 2.0 · read:mcp
          </StatusPill>
        }
      />

      <div className="mt-4 space-y-4">
        <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
          <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600" />
          <span>
            Create an API key with the <span className="font-mono text-slate-700">read:mcp</span>{' '}
            scope in <span className="font-medium text-slate-600">Settings → Security</span>, then
            paste it into the config below. The key is the only credential the client needs; create
            it there and never commit it.
          </span>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <p className="flex items-center gap-1.5 text-xs font-semibold text-slate-700">
                <Terminal className="h-3.5 w-3.5 text-slate-400" />
                Cursor · <span className="font-mono">.cursor/mcp.json</span>
              </p>
              <Button
                size="sm"
                icon={
                  copied === 'cursor' ? <CheckCircle2 className="h-3.5 w-3.5" /> : <ClipboardCopy className="h-3.5 w-3.5" />
                }
                onClick={() => copy('cursor', mcpConfig)}
              >
                {copied === 'cursor' ? 'Copied' : 'Copy'}
              </Button>
            </div>
            <CodeBlock code={mcpConfig} language="json" label="stdio proxy" maxHeight="max-h-64" />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <p className="flex items-center gap-1.5 text-xs font-semibold text-slate-700">
                <Terminal className="h-3.5 w-3.5 text-slate-400" />
                Claude Desktop · <span className="font-mono">claude_desktop_config.json</span>
              </p>
              <Button
                size="sm"
                icon={
                  copied === 'claude' ? <CheckCircle2 className="h-3.5 w-3.5" /> : <ClipboardCopy className="h-3.5 w-3.5" />
                }
                onClick={() => copy('claude', mcpConfig)}
              >
                {copied === 'claude' ? 'Copied' : 'Copy'}
              </Button>
            </div>
            <CodeBlock code={mcpConfig} language="json" label="stdio proxy" maxHeight="max-h-64" />
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <p className="flex items-center gap-1.5 text-xs font-semibold text-slate-700">
              <Network className="h-3.5 w-3.5 text-slate-400" />
              Hosted HTTP transport — <span className="font-mono">POST {base.replace(/\/$/, '')}/api/v1/mcp</span>
            </p>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                icon={<Download className="h-3.5 w-3.5" />}
                onClick={() => downloadText('statetrack-mcp.json', httpConfig, 'application/json')}
              >
                Download
              </Button>
              <Button
                size="sm"
                icon={
                  copied === 'http' ? <CheckCircle2 className="h-3.5 w-3.5" /> : <ClipboardCopy className="h-3.5 w-3.5" />
                }
                onClick={() => copy('http', httpConfig)}
              >
                {copied === 'http' ? 'Copied' : 'Copy'}
              </Button>
            </div>
          </div>
          <CodeBlock code={httpConfig} language="json" label="http" maxHeight="max-h-56" />
          <p className="text-[11px] leading-relaxed text-slate-400">
            For air-gapped sites, point <span className="font-mono">STATETRACK_URL</span> at the
            local server and install the <span className="font-mono">statetrack-mcp</span> binary
            from your release bundle. Both transports execute the same tool code, so a client gets
            the same answer however it connected.
          </p>
        </div>

        <div className="rounded-lg border border-slate-200">
          <div className="border-b border-slate-200 bg-slate-50/70 px-3 py-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Exposed tools ({MCP_TOOLS.length})
            </p>
          </div>
          <ul className="divide-y divide-slate-100">
            {MCP_TOOLS.map((t) => (
              <li key={t.name} className="flex items-center gap-3 px-3 py-2">
                <span className="font-mono text-xs font-medium text-slate-800">{t.name}</span>
                <span className="ml-auto truncate text-[11px] text-slate-400">{t.hint}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Card>
  )
}

export { PROVIDERS }
