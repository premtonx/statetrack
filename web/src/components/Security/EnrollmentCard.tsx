import { useState } from 'react'
import {
  Check,
  Copy,
  Loader2,
  Plus,
  Server,
  Terminal,
  Trash2,
  TriangleAlert,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import StatusPill from '../ui/StatusPill'
import Modal from '../ui/Modal'
import { Button, Field, IconButton, Select, TextInput } from '../ui/controls'
import { OneTimeSecret } from './APIKeysCard'
import { copyText } from '../../lib/clipboard'
import { useReadOnly } from '../../lib/authContext'
import {
  useCreateEnrollmentToken,
  useEnrollmentTokens,
  useRevokeEnrollmentToken,
} from '../../api/hooks'
import type { CreateEnrollmentTokenResponse, EnrollmentToken } from '../../types'
import { formatDateTime, timeUntil } from '../../lib/utils'

const EXPIRY_OPTIONS = [0, 7, 30, 90, 180]
const MAX_USES_OPTIONS = [0, 1, 5, 10, 25, 100]

function expiryLabel(days: number): string {
  return days === 0 ? '30 days (default)' : `${days} days`
}

function usesLabel(n: number): string {
  return n === 0 ? 'Unlimited (default 25)' : `${n} agents`
}

/**
 * Agent enrollment tokens.
 *
 * A token is a bearer secret that lets a host join the fleet, so the card is
 * built around three guard rails the server also enforces: a finite use cap, an
 * expiry, and one-time display. The ready-to-paste bootstrap commands come from
 * the server rather than being assembled here, so shell quoting is never a
 * frontend concern.
 */
export default function EnrollmentCard() {
  const readOnly = useReadOnly()
  const { data, isLoading, isError } = useEnrollmentTokens()
  const create = useCreateEnrollmentToken()
  const revoke = useRevokeEnrollmentToken()

  const [mintOpen, setMintOpen] = useState(false)
  const [name, setName] = useState('')
  const [maxUses, setMaxUses] = useState(0)
  const [days, setDays] = useState(0)
  const [mintError, setMintError] = useState<string | null>(null)
  const [minted, setMinted] = useState<CreateEnrollmentTokenResponse | null>(null)
  const [revoking, setRevoking] = useState<EnrollmentToken | null>(null)

  const tokens = data?.enrollment_tokens ?? []

  const resetMint = () => {
    setName('')
    setMaxUses(0)
    setDays(0)
    setMintError(null)
    setMinted(null)
  }

  const submitMint = () => {
    setMintError(null)
    create.mutate(
      { name: name.trim(), max_uses: maxUses, expires_in_days: days },
      {
        onSuccess: (res) => setMinted(res),
        onError: (err: unknown) =>
          setMintError(err instanceof Error ? err.message : 'Could not create the token'),
      },
    )
  }

  const columns: DataTableColumn<EnrollmentToken>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (t) => (
        <div className="min-w-0">
          <p className="truncate text-xs font-medium text-slate-800">{t.name}</p>
          <p className="mt-0.5 font-mono text-[11px] text-slate-400">{t.token_prefix}…</p>
        </div>
      ),
    },
    {
      key: 'uses',
      header: 'Uses',
      cell: (t) => (
        <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-600">
          {t.uses_count}
          <span className="text-slate-400"> / {t.max_uses ?? '∞'}</span>
        </span>
      ),
    },
    {
      key: 'expires',
      header: 'Expires',
      cell: (t) => {
        if (!t.expires_at) {
          return <span className="text-[11px] text-amber-700">never</span>
        }
        const left = timeUntil(t.expires_at)
        return (
          <span className="whitespace-nowrap text-[11px] text-slate-500" title={formatDateTime(t.expires_at)}>
            {left === 'expired' ? 'expired' : `${left} left`}
          </span>
        )
      },
    },
    {
      key: 'created',
      header: 'Created',
      cell: (t) => (
        <span className="whitespace-nowrap font-mono text-[11px] text-slate-500">
          {formatDateTime(t.created_at)}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (t) =>
        t.active ? (
          <StatusPill tone="green" dot>
            Active
          </StatusPill>
        ) : t.revoked_at ? (
          <StatusPill tone="slate" dot>
            Revoked
          </StatusPill>
        ) : (
          <StatusPill tone="amber" dot>
            Exhausted
          </StatusPill>
        ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (t) => (
        <IconButton
          label={`Revoke ${t.name}`}
          disabled={readOnly || !t.active || revoke.isPending}
          onClick={() => setRevoking(t)}
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
            title="Agent Enrollment Tokens"
            subtitle="Bootstrap secrets an installer presents to join the fleet"
            icon={<Server className="h-4 w-4" />}
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
            New enrollment token
          </Button>
        </div>

        {isError ? (
          <div className="flex items-start gap-2 border-b border-red-200 bg-red-50 px-4 py-2 text-xs text-red-800">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>Could not load enrollment tokens.</span>
          </div>
        ) : null}

        <DataTable
          columns={columns}
          rows={tokens}
          rowKey={(t) => t.id}
          loading={isLoading}
          empty="No enrollment tokens yet. Create one to onboard a new environment."
        />
      </Card>

      <Modal
        open={mintOpen && !minted}
        onClose={() => setMintOpen(false)}
        title="New enrollment token"
        description="Capped and time-boxed by default — an unbounded token is a fleet-takeover primitive."
        footer={
          <>
            <Button onClick={() => setMintOpen(false)}>Cancel</Button>
            <Button
              variant="primary"
              disabled={!name.trim() || create.isPending}
              onClick={submitMint}
              icon={create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Server className="h-4 w-4" />}
            >
              {create.isPending ? 'Creating…' : 'Create token'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name" hint="Which rollout is this for?" htmlFor="enroll-name">
            <TextInput
              id="enroll-name"
              value={name}
              autoFocus
              onChange={(e) => setName(e.target.value)}
              placeholder="Production Fleet Rollout"
            />
          </Field>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Maximum uses" hint="How many agents may enroll with it." htmlFor="enroll-uses">
              <Select id="enroll-uses" value={String(maxUses)} onChange={(e) => setMaxUses(Number(e.target.value))}>
                {MAX_USES_OPTIONS.map((n) => (
                  <option key={n} value={n}>
                    {usesLabel(n)}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Expiry" hint="Rotate before it lapses." htmlFor="enroll-expiry">
              <Select id="enroll-expiry" value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
                {EXPIRY_OPTIONS.map((d) => (
                  <option key={d} value={d}>
                    {expiryLabel(d)}
                  </option>
                ))}
              </Select>
            </Field>
          </div>

          {mintError ? (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{mintError}</span>
            </div>
          ) : null}
        </div>
      </Modal>

      {/* One-time token plus the ready-to-paste install commands. */}
      <Modal
        open={Boolean(minted)}
        onClose={() => {
          setMinted(null)
          setMintOpen(false)
          resetMint()
        }}
        size="lg"
        title="Enrollment token created"
        description="Copy the token or paste one of the one-line installers on the target host."
        footer={
          <Button
            variant="primary"
            onClick={() => {
              setMinted(null)
              setMintOpen(false)
              resetMint()
            }}
          >
            Done
          </Button>
        }
      >
        {minted ? (
          <div className="space-y-4">
            <OneTimeSecret
              value={minted.token}
              prefix={minted.token_prefix}
              warning={minted.warning}
            />
            <div className="space-y-2">
              <p className="text-xs font-medium text-slate-700">Install on the target host</p>
              <CommandBlock
                label="Linux / macOS"
                command={minted.enrollment_token.linux_command}
              />
              <CommandBlock
                label="Windows (PowerShell)"
                command={minted.enrollment_token.windows_command}
              />
              <p className="text-[11px] text-slate-400">
                The token is embedded in the command, so treat the shell history on that host as
                sensitive until the agent has enrolled.
              </p>
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={Boolean(revoking)}
        onClose={() => setRevoking(null)}
        size="sm"
        title={`Revoke "${revoking?.name ?? ''}"?`}
        description="Hosts that have not yet enrolled with this token will be refused. Already-enrolled agents are unaffected."
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
              Revoke token
            </Button>
          </>
        }
      >
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>If a token may have leaked, revoke it and issue a fresh one.</span>
        </div>
      </Modal>
    </>
  )
}

/** One labelled, copyable shell command. */
function CommandBlock({ label, command }: { label: string; command: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="overflow-hidden rounded-lg border border-slate-700 bg-slate-900">
      <div className="flex items-center justify-between gap-2 border-b border-slate-700/60 px-3 py-1.5">
        <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide text-slate-400">
          <Terminal className="h-3 w-3" /> {label}
        </span>
        <button
          onClick={async () => {
            setCopied(await copyText(command))
            window.setTimeout(() => setCopied(false), 1600)
          }}
          className="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-slate-300 transition-colors hover:bg-slate-700/60 hover:text-white"
        >
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-auto px-3 py-2.5 font-mono text-[11px] leading-relaxed text-slate-200">
        {command}
      </pre>
    </div>
  )
}
