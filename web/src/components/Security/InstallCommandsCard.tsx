import { useState } from 'react'
import { Check, Copy, Download, Terminal, TriangleAlert } from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import { copyText } from '../../lib/clipboard'

/**
 * The install commands an operator needs before there is anything else to do.
 *
 * This card is deliberately first on the Agents tab and is populated from the
 * deployment's own origin, so the command a new user copies already points at
 * the server they are looking at. The commands are the published release
 * installers: they verify the release checksum before anything is installed.
 */

const REPO = 'premtonx/statetrack'
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/main/deploy`
const RELEASE_BASE = `https://github.com/${REPO}/releases/latest/download`
const RELEASE_PAGE = `https://github.com/${REPO}/releases/latest`

const LINUX_AGENT_FILE = 'statetrack-agent-linux-amd64.tar.gz'
const WINDOWS_AGENT_FILE = 'statetrack-agent-windows-amd64.zip'

const LINUX_AGENT_URL = `${RELEASE_BASE}/${LINUX_AGENT_FILE}`
const WINDOWS_AGENT_URL = `${RELEASE_BASE}/${WINDOWS_AGENT_FILE}`

export interface InstallCommandsCardProps {
  /** Overrides the inferred gRPC endpoint (defaults to the console's host:50051). */
  serverAddress?: string
}

/** The gRPC endpoint an agent on the same network should dial. */
export function inferServerAddress(): string {
  if (typeof window === 'undefined') return 'localhost:50051'
  const host = window.location.hostname || 'localhost'
  return `${host}:50051`
}

export default function InstallCommandsCard({ serverAddress }: InstallCommandsCardProps) {
  const address = serverAddress || inferServerAddress()

  const linux = `curl -fsSL ${RAW_BASE}/install.sh | sudo bash -s -- --server ${address} --token <enrollment-token>`

  const windows = `& ([scriptblock]::Create((irm ${RAW_BASE}/install.ps1))) -Server ${address} -Token <enrollment-token>`

  return (
    <Card flush>
      <div className="border-b border-slate-200 px-4 py-3">
        <CardHeader
          title="Connect your first host"
          subtitle="One command per platform. It installs the agent, verifies the release checksum and registers the service."
          icon={<Terminal className="h-4 w-4" />}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 p-4 xl:grid-cols-2">
        <InstallBlock label="Linux (systemd)" command={linux} />
        <InstallBlock label="Windows (Service)" command={windows} />
      </div>

      <StandaloneDownloads />

      <div className="flex items-start gap-2 border-t border-slate-200 bg-slate-50/60 px-4 py-2.5 text-[11px] text-slate-500">
        <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
        <span>
          Create an enrollment token below to get the real command with a scoped token embedded.
          Manual package downloads and the full parameter reference are in{' '}
          <a
            href={RELEASE_PAGE}
            target="_blank"
            rel="noreferrer"
            className="font-medium text-blue-700 hover:underline"
          >
            the latest release
          </a>{' '}
          and the agent deployment guide.
        </span>
      </div>
    </Card>
  )
}

function InstallBlock({ label, command }: { label: string; command: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <div className="overflow-hidden rounded-lg border border-slate-700 bg-slate-900">
      <div className="flex items-center justify-between gap-2 border-b border-slate-700/60 px-3 py-1.5">
        <span className="font-mono text-[10px] uppercase tracking-wide text-slate-400">{label}</span>
        <div className="flex shrink-0 items-center gap-1">
          <button
            onClick={async () => {
              setCopied(await copyText(command))
              window.setTimeout(() => setCopied(false), 1600)
            }}
            className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-slate-300 transition-colors hover:bg-slate-700/60 hover:text-white"
          >
            {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>
      <pre className="overflow-auto px-3 py-2.5 font-mono text-[11px] leading-relaxed text-slate-200">
        {command}
      </pre>
    </div>
  )
}

/**
 * Escape hatch for operators who cannot pipe a remote script into a shell —
 * locked-down build agents, air-gapped networks, or a policy that forbids
 * `curl | bash`. They download the archive, verify it against the release
 * checksums and run the same binary the installer would have fetched.
 */
function StandaloneDownloads() {
  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-slate-200 bg-white px-4 py-3">
      <span className="mr-1 text-[11px] font-medium uppercase tracking-wide text-slate-400">
        Or download standalone binary
      </span>
      <a
        href={LINUX_AGENT_URL}
        className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 shadow-xs transition-colors hover:border-slate-300 hover:bg-slate-50"
      >
        <Download className="h-3.5 w-3.5 text-slate-400" />
        Download Linux Agent (.tar.gz)
      </a>
      <a
        href={WINDOWS_AGENT_URL}
        className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 shadow-xs transition-colors hover:border-slate-300 hover:bg-slate-50"
      >
        <Download className="h-3.5 w-3.5 text-slate-400" />
        Download Windows Agent (.zip)
      </a>
      <a
        href={`${RELEASE_BASE}/SHA256SUMS.txt`}
        className="ml-auto text-[11px] font-medium text-blue-700 hover:underline"
      >
        SHA256SUMS.txt
      </a>
    </div>
  )
}

/** Direct download links for the release archives, for air-gapped rollout. */
export const RELEASE_DOWNLOADS = [
  { label: 'Linux amd64', file: LINUX_AGENT_FILE },
  { label: 'Linux arm64', file: 'statetrack-agent-linux-arm64.tar.gz' },
  { label: 'Windows amd64', file: WINDOWS_AGENT_FILE },
] as const

export function ReleaseDownloads() {
  return (
    <ul className="space-y-1.5">
      {RELEASE_DOWNLOADS.map((d) => (
        <li key={d.file}>
          <a
            href={`${RELEASE_BASE}/${d.file}`}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 hover:underline"
          >
            <Download className="h-3.5 w-3.5" />
            {d.label} — {d.file}
          </a>
        </li>
      ))}
    </ul>
  )
}
