/**
 * Shared chrome for the Integrations hub: the copy/download pair every card
 * needs, and the small labelled code block that shows an asset or a config
 * snippet.
 */
import { useEffect, useState } from 'react'
import { Check, Copy, Download, Loader2, TriangleAlert } from 'lucide-react'
import { Button } from '../ui/controls'
import { cn } from '../../lib/utils'
import { copyText } from '../../lib/clipboard'
import {
  assetUrl,
  downloadText,
  useIntegrationAsset,
  type IntegrationAsset,
} from '../../lib/integrationAssets'

/** Copy + download buttons for one provisioned asset. */
export function AssetActions({
  asset,
  size = 'md',
  className,
}: {
  asset: IntegrationAsset
  size?: 'sm' | 'md'
  className?: string
}) {
  const { data, isError, isLoading } = useIntegrationAsset(asset)
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')

  useEffect(() => {
    if (state === 'idle') return
    const t = window.setTimeout(() => setState('idle'), 1800)
    return () => window.clearTimeout(t)
  }, [state])

  const handleCopy = async () => {
    if (data === undefined) return
    setState((await copyText(data)) ? 'copied' : 'failed')
  }

  const handleDownload = () => {
    if (data === undefined) return
    downloadText(asset.filename, data, mimeFor(asset.language))
  }

  return (
    <div className={cn('flex flex-wrap items-center gap-2', className)}>
      <Button
        size={size}
        disabled={isLoading || isError || data === undefined}
        icon={
          isLoading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : state === 'copied' ? (
            <Check className="h-3.5 w-3.5" />
          ) : state === 'failed' ? (
            <TriangleAlert className="h-3.5 w-3.5" />
          ) : (
            <Copy className="h-3.5 w-3.5" />
          )
        }
        onClick={handleCopy}
        title={
          isError
            ? `Could not load ${asset.filename}`
            : state === 'failed'
              ? 'The browser blocked clipboard access — use Download instead'
              : `Copy ${asset.filename}`
        }
      >
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy blocked' : `Copy ${asset.filename}`}
      </Button>
      <Button
        size={size}
        disabled={isLoading || isError || data === undefined}
        icon={<Download className="h-3.5 w-3.5" />}
        onClick={handleDownload}
      >
        Download
      </Button>
    </div>
  )
}

/** An anchor that downloads an asset directly, for doc-style links. */
export function AssetDownloadLink({ asset }: { asset: IntegrationAsset }) {
  return (
    <a
      href={assetUrl(asset)}
      download={asset.filename}
      className="text-xs font-medium text-blue-700 hover:text-blue-800 hover:underline"
    >
      {asset.filename}
    </a>
  )
}

/**
 * Read-only code block with a copy button. Used for scrape configs and CLI
 * commands, where a mis-transcribed character is the whole failure mode.
 */
export function CodeBlock({
  code,
  label,
  language,
  copyable = true,
  className,
  maxHeight = 'max-h-80',
}: {
  code: string
  label?: string
  language?: string
  copyable?: boolean
  className?: string
  maxHeight?: string
}) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return
    const t = window.setTimeout(() => setCopied(false), 1600)
    return () => window.clearTimeout(t)
  }, [copied])

  return (
    <div className={cn('overflow-hidden rounded-lg border border-slate-200 bg-slate-900', className)}>
      {label ? (
        <div className="flex items-center justify-between gap-2 border-b border-slate-700/60 px-3 py-1.5">
          <span className="truncate font-mono text-[10px] uppercase tracking-wide text-slate-400">
            {label}
            {language ? <span className="ml-2 normal-case text-slate-500">{language}</span> : null}
          </span>
          {copyable ? (
            <button
              onClick={async () => setCopied(await copyText(code))}
              className="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-slate-300 transition-colors hover:bg-slate-700/60 hover:text-white"
            >
              {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          ) : null}
        </div>
      ) : null}
      <pre
        className={cn(
          'overflow-auto px-3 py-2.5 font-mono text-[11px] leading-relaxed text-slate-200',
          maxHeight,
        )}
      >
        {code}
      </pre>
    </div>
  )
}

/** Loader placeholder sized like the block it replaces, to avoid layout shift. */
export function BlockSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="h-3 animate-pulse rounded bg-slate-200"
          style={{ width: `${90 - i * 9}%` }}
        />
      ))}
    </div>
  )
}

function mimeFor(language: IntegrationAsset['language']): string {
  switch (language) {
    case 'json':
      return 'application/json'
    case 'yaml':
      return 'text/yaml'
    default:
      return 'text/x-python'
  }
}
