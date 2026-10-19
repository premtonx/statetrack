import { useState } from 'react'
import {
  Check,
  Copy,
  KeyRound,
  Loader2,
  Plus,
  ShieldAlert,
  Trash2,
  TriangleAlert,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import StatusPill from '../ui/StatusPill'
import Modal from '../ui/Modal'
import { Button, Field, IconButton, Select, TextInput } from '../ui/controls'
import RoleBadge from './RoleBadge'
import { copyText } from '../../lib/clipboard'
import { useReadOnly } from '../../lib/authContext'
import { ROLE_LABELS, useAPIKeys, useCreateAPIKey, useRevokeAPIKey } from '../../api/hooks'
import { ROLE_OPTIONS, type APIKey, type CreateAPIKeyResponse, type Role } from '../../types'
import { cn, formatDateTime, timeAgo } from '../../lib/utils'

/** The scope vocabulary, with the sentence that explains why it exists. */
const SCOPE_HELP: Record<string, string> = {
  'read:summary': 'Poller rollups — Checkmk, Zabbix, Icinga and Datadog.',
  'read:annotations': 'Grafana annotation markers and the events feed.',
  'read:mcp': 'Agent-facing MCP read endpoints.',
  'admin:write': 'Mutating endpoints. A key without it is read-only regardless of role.',
}

const EXPIRY_OPTIONS = [0, 30, 90, 180, 365]

function expiryLabel(days: number): string {
  return days === 0 ? 'Never expires' : `${days} days`
}

/**
 * Scoped machine credentials.
 *
 * One rule shapes the whole card: the secret is shown exactly once, in the mint
 * response, and never again. There is deliberately no "reveal" action on an
 * existing row, because the server only stores a SHA-256 hash — so the row
 * offers revoke-and-recreate instead, which is also the more auditable rotation.
 */
export default function APIKeysCard() {
  const readOnly = useReadOnly()
  const { data, isLoading, isError } = useAPIKeys()
  const create = useCreateAPIKey()
  const revoke = useRevokeAPIKey()

  const [mintOpen, setMintOpen] = useState(false)
  const [name, setName] = useState('')
  const [role, setRole] = useState<Role>('operator')
  const [scopes, setScopes] = useState<string[]>(['read:summary'])
  const [days, setDays] = useState(180)
  const [mintError, setMintError] = useState<string | null>(null)
  const [minted, setMinted] = useState<CreateAPIKeyResponse | null>(null)
  const [revoking, setRevoking] = useState<APIKey | null>(null)

  const keys = data?.api_keys ?? []
  const vocabulary = data?.scopes ?? Object.keys(SCOPE_HELP)

  const resetMint = () => {
    setName('')
    setRole('operator')
    setScopes(['read:summary'])
    setDays(180)
    setMintError(null)
    setMinted(null)
  }

  const toggleScope = (scope: string) => {
    setScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    )
  }

  const submitMint = () => {
    setMintError(null)
    create.mutate(
      { name: name.trim(), role, scopes, expires_in_days: days },
      {
        onSuccess: (res) => setMinted(res),
        onError: (err: unknown) =>
          setMintError(err instanceof Error ? err.message : 'Could not mint the key'),
      },
    )
  }

  const columns: DataTableColumn<APIKey>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (k) => (
        <div className="min-w-0">
          <p className="truncate text-xs font-medium text-slate-800">{k.name}</p>
          <p className="mt-0.5 font-mono text-[11px] text-slate-400">{k.key_prefix}…</p>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      cell: (k) => <RoleBadge role={k.role} short />,
    },
    {
      key: 'scopes',
      header: 'Scopes',
      cell: (k) => (
        <div className="flex flex-wrap gap-1">
          {(k.scopes ?? []).length === 0 ? (
            <span className="text-[11px] text-slate-400">none</span>
          ) : (
            (k.scopes ?? []).map((s) => (
              <span
                key={s}
                className={cn(
                  'rounded border px-1.5 py-0.5 font-mono text-[10px]',
                  s === 'admin:write'
                    ? 'border-red-200 bg-red-50 text-red-700'
                    : 'border-slate-200 bg-slate-50 text-slate-600',
                )}
              >
                {s}
              </span>
            ))
          )}
        </div>
      ),
    },
    {
      key: 'last_used',
      header: 'Last used',
      cell: (k) =>
        k.last_used_at ? (
          <span className="whitespace-nowrap text-[11px] text-slate-500" title={formatDateTime(k.last_used_at)}>
            {timeAgo(k.last_used_at)}
          </span>
        ) : (
          <span className="text-[11px] text-slate-400">never</span>
        ),
    },
    {
      key: 'expires',
      header: 'Expires',
      cell: (k) =>
        k.expires_in ? (
          <span className="whitespace-nowrap text-[11px] text-slate-500">{k.expires_in}</span>
        ) : (
          <span className="text-[11px] text-amber-700">never</span>
        ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (k) =>
        k.active ? (
          <StatusPill tone="green" dot>
            Active
          </StatusPill>
        ) : k.revoked_at ? (
          <StatusPill tone="slate" dot>
            Revoked
          </StatusPill>
        ) : (
          <StatusPill tone="amber" dot>
            Expired
          </StatusPill>
        ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (k) => (
        <IconButton
          label={`Revoke ${k.name}`}
          disabled={readOnly || !k.active || revoke.isPending}
          onClick={() => setRevoking(k)}
          className="hover:border-red-200 hover:bg-red-50 hover:text-red-600"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </IconButton>
      ),
    },
  ]

  return (
    <>
      <Card flush>
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
          <CardHeader
            className="min-w-0 flex-1"
            title="Scoped API Keys"
            subtitle="Machine credentials for pollers, dashboards and automation"
            icon={<KeyRound className="h-4 w-4" />}
          />
          <Button
            variant="primary"
            size="sm"
            disabled={readOnly}
            onClick={() => {
              resetMint()
              setMintOpen(true)
            }}
            icon={<Plus className="h-3.5 w-3.5" />}
          >
            Create key
          </Button>
        </div>

        {isError ? (
          <div className="flex items-start gap-2 border-b border-red-200 bg-red-50 px-4 py-2 text-xs text-red-800">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>Could not load API keys.</span>
          </div>
        ) : null}

        <DataTable
          columns={columns}
          rows={keys}
          rowKey={(k) => k.id}
          loading={isLoading}
          empty="No API keys yet. Create one for your monitoring poller or dashboard."
        />
      </Card>

      {/* Mint form. */}
      <Modal
        open={mintOpen && !minted}
        onClose={() => setMintOpen(false)}
        title="Create API key"
        description="The secret is shown once, immediately after creation."
        footer={
          <>
            <Button onClick={() => setMintOpen(false)}>Cancel</Button>
            <Button
              variant="primary"
              disabled={!name.trim() || scopes.length === 0 || create.isPending}
              onClick={submitMint}
              icon={create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
            >
              {create.isPending ? 'Creating…' : 'Create key'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name" hint="Shown in the audit trail — name it after the system that uses it." htmlFor="key-name">
            <TextInput
              id="key-name"
              value={name}
              autoFocus
              onChange={(e) => setName(e.target.value)}
              placeholder="Checkmk & Zabbix Poller"
            />
          </Field>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Role" htmlFor="key-role">
              <Select id="key-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {ROLE_OPTIONS.map((r) => (
                  <option key={r.id} value={r.id}>
                    {ROLE_LABELS[r.id]}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Expiry" htmlFor="key-expiry">
              <Select id="key-expiry" value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
                {EXPIRY_OPTIONS.map((d) => (
                  <option key={d} value={d}>
                    {expiryLabel(d)}
                  </option>
                ))}
              </Select>
            </Field>
          </div>

          <div>
            <p className="text-xs font-medium text-slate-700">Scopes</p>
            <div className="mt-2 space-y-1.5">
              {vocabulary.map((s) => {
                const on = scopes.includes(s)
                return (
                  <label
                    key={s}
                    className={cn(
                      'flex cursor-pointer items-start gap-2.5 rounded-lg border px-2.5 py-2 transition-colors',
                      on ? 'border-blue-300 bg-blue-50/60' : 'border-slate-200 hover:bg-slate-50',
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={() => toggleScope(s)}
                      className="mt-0.5 h-3.5 w-3.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500/30"
                    />
                    <span className="min-w-0 flex-1">
                      <span
                        className={cn(
                          'block font-mono text-[11px] font-medium',
                          s === 'admin:write' ? 'text-red-700' : 'text-slate-700',
                        )}
                      >
                        {s}
                      </span>
                      <span className="mt-0.5 block text-[11px] leading-snug text-slate-500">
                        {SCOPE_HELP[s] ?? 'Custom scope'}
                      </span>
                    </span>
                  </label>
                )
              })}
            </div>
          </div>

          {mintError ? (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{mintError}</span>
            </div>
          ) : null}
        </div>
      </Modal>

      {/* One-time secret. The modal is not dismissible by a stray click. */}
      <Modal
        open={Boolean(minted)}
        onClose={() => {
          setMinted(null)
          setMintOpen(false)
          resetMint()
        }}
        title="Copy your API key now"
        description="This is the only time the secret is shown. The server stores only a hash."
        footer={
          <Button
            variant="primary"
            onClick={() => {
              setMinted(null)
              setMintOpen(false)
              resetMint()
            }}
          >
            I've stored it
          </Button>
        }
      >
        {minted ? <OneTimeSecret value={minted.token} prefix={minted.key_prefix} warning={minted.warning} /> : null}
      </Modal>

      {/* Revoke confirmation. */}
      <Modal
        open={Boolean(revoking)}
        onClose={() => setRevoking(null)}
        size="sm"
        title={`Revoke "${revoking?.name ?? ''}"?`}
        description="Any system using this key stops authenticating immediately. This cannot be undone."
        footer={
          <>
            <Button onClick={() => setRevoking(null)}>Cancel</Button>
            <Button
              variant="danger"
              disabled={revoke.isPending}
              onClick={() => {
                if (revoking) revoke.mutate(revoking.id)
                setRevoking(null)
              }}
              icon={<Trash2 className="h-4 w-4" />}
            >
              Revoke key
            </Button>
          </>
        }
      >
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Rotation is revoke-then-recreate: the plaintext secret is unrecoverable, so a replacement
            key must be minted and redistributed.
          </span>
        </div>
      </Modal>
    </>
  )
}

/**
 * The one-time secret block, shared with the enrollment-token flow. Rendered
 * dark so it reads as "copy this somewhere safe" rather than ordinary page
 * content, with the prefix shown separately so a truncated paste is noticeable.
 */
export function OneTimeSecret({
  value,
  prefix,
  warning,
}: {
  value: string
  prefix?: string
  warning?: string
}) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
        <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>{warning ?? 'Store this secret now — it cannot be retrieved later.'}</span>
      </div>
      <div className="flex items-stretch gap-2">
        <code className="min-w-0 flex-1 break-all rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 font-mono text-xs leading-relaxed text-slate-100">
          {value}
        </code>
        <Button
          onClick={async () => {
            setCopied(await copyText(value))
            window.setTimeout(() => setCopied(false), 1600)
          }}
          icon={copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
        >
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      {prefix ? (
        <p className="text-[11px] text-slate-500">
          Identifier for logs and the UI: <span className="font-mono text-slate-700">{prefix}</span>
        </p>
      ) : null}
    </div>
  )
}
