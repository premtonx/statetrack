import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  Check,
  Copy,
  Cpu,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Terminal,
  Wrench,
} from 'lucide-react'
import { useEventAnalysis } from '../../api/hooks'
import { useReadOnly } from '../../lib/authContext'
import { copyText } from '../../lib/clipboard'
import { cn } from '../../lib/utils'
import type { Analysis, BlastRadius } from '../../types'
import StatusPill, { type PillTone } from '../ui/StatusPill'
import { Button } from '../ui/controls'

/**
 * Blast-radius presentation. A closed set on the server, so the tone is a
 * lookup rather than a heuristic: Low is calm, High is the one that should make
 * an operator pause before dismissing the panel.
 */
const BLAST_TONE: Record<string, PillTone> = {
  Low: 'green',
  Medium: 'amber',
  High: 'red',
}

/**
 * The "✦ Analyze & Rollback" pane inside the Inspector drawer.
 *
 * This is the entire visible footprint of the AI engine in the console, and it
 * lives here — behind an explicit click, inside a drawer the operator already
 * opened for a specific change — rather than as a dashboard widget. Two
 * properties matter: nothing runs until asked (a model call has a cost and a
 * latency), and the engine that answered is always named, so a reader can tell a
 * model's judgement from the deterministic heuristics, especially when a
 * configured model failed and the fallback filled in.
 */
export default function AnalyzePanel({ eventId }: { eventId: string }) {
  const readOnly = useReadOnly()
  const { analysis, isAnalyzing, error, run } = useEventAnalysis(eventId)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-blue-600">
            <Sparkles className="h-4 w-4" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-slate-900">Analyze &amp; Rollback</h3>
            <p className="text-xs text-slate-500">
              Assess the operational risk of this change and get the exact command to undo it.
            </p>
          </div>
        </div>
        <Button
          variant="primary"
          size="sm"
          icon={
            isAnalyzing ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Sparkles className="h-3.5 w-3.5" />
            )
          }
          disabled={isAnalyzing}
          onClick={run}
        >
          {isAnalyzing ? 'Analyzing…' : analysis ? 'Re-analyze' : '✦ Analyze & Rollback'}
        </Button>
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
        <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600" />
        <span>
          The analyzer reasons over the already-scrubbed diff — secret-looking values are replaced
          with <span className="font-mono text-slate-600">[REDACTED:sha256:…]</span> stubs at the
          host, so no credential ever leaves this deployment.
        </span>
      </div>

      {error ? (
        <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      {isAnalyzing && !analysis ? <AnalysisSkeleton /> : null}

      {analysis ? <AnalysisResult analysis={analysis} readOnly={readOnly} /> : null}
    </div>
  )
}

function AnalysisResult({ analysis, readOnly }: { analysis: Analysis; readOnly: boolean }) {
  const tone = BLAST_TONE[analysis.blast_radius] ?? 'slate'
  const engineTone: PillTone = analysis.fallback ? 'amber' : analysis.provider === 'deterministic' ? 'slate' : 'purple'

  return (
    <div className="space-y-4">
      {/* Engine + verdict strip */}
      <div className="flex flex-wrap items-center gap-2">
        <StatusPill tone={engineTone} dot>
          <Cpu className="h-3 w-3" />
          {analysis.provider_label}
        </StatusPill>
        {analysis.model ? (
          <StatusPill tone="slate" mono>
            {analysis.model}
          </StatusPill>
        ) : null}
        <StatusPill tone={tone} dot>
          Blast radius: {analysis.blast_radius}
        </StatusPill>
        {analysis.scrubbed ? <StatusPill tone="green">Scrubbed diff</StatusPill> : null}
        {analysis.latency_ms > 0 ? (
          <span className="font-mono text-[11px] tabular-nums text-slate-400">
            {analysis.latency_ms} ms
          </span>
        ) : null}
      </div>

      {analysis.fallback ? (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] leading-relaxed text-amber-800">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            The configured engine did not answer, so the built-in offline heuristics produced this
            assessment.
            {analysis.fallback_reason ? (
              <>
                {' '}
                <span className="font-mono">{analysis.fallback_reason}</span>
              </>
            ) : null}
          </span>
        </div>
      ) : null}

      {/* Risk summary */}
      <div className="rounded-lg border border-slate-200">
        <div className="flex items-center gap-2 border-b border-slate-200 bg-slate-50/70 px-3 py-2">
          <AlertTriangle className="h-3.5 w-3.5 text-slate-400" />
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Operational risk &amp; blast radius
          </h3>
        </div>
        <p className="px-3 py-3 text-sm leading-relaxed text-slate-700">{analysis.risk_summary}</p>
        {analysis.affected_services && analysis.affected_services.length > 0 ? (
          <div className="flex flex-wrap items-center gap-1.5 border-t border-slate-100 px-3 py-2">
            <span className="text-[11px] font-medium text-slate-500">Affected:</span>
            {analysis.affected_services.map((s) => (
              <StatusPill key={s} tone="slate">
                {s}
              </StatusPill>
            ))}
          </div>
        ) : null}
      </div>

      {/* Rollback command */}
      <CommandBox
        label="Safe rollback command"
        icon={<Wrench className="h-3.5 w-3.5" />}
        command={analysis.rollback_command}
        emptyText="No safe generic command exists for this change — revert it by hand using the actor tree and the diff above."
        note={analysis.rollback_notes}
        readOnly={readOnly}
      />

      {/* Verification command */}
      <CommandBox
        label="Verification command"
        icon={<Terminal className="h-3.5 w-3.5" />}
        command={analysis.verification_command}
        emptyText="No verification command was derived for this change."
        readOnly={readOnly}
      />
    </div>
  )
}

/**
 * One monospace command with a 1-click copy button.
 *
 * The copy affordance is the whole point: a rollback command that has to be
 * selected by hand from a rendered box is a rollback command that will one day
 * be mistyped at 3am. `copyText` reports failure (a plain-HTTP LAN address has
 * no Clipboard API), so the button says so rather than silently doing nothing.
 */
function CommandBox({
  label,
  icon,
  command,
  emptyText,
  note,
  readOnly,
}: {
  label: string
  icon: React.ReactNode
  command?: string
  emptyText: string
  note?: string
  readOnly?: boolean
}) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')

  useEffect(() => {
    if (state === 'idle') return
    const t = window.setTimeout(() => setState('idle'), 1800)
    return () => window.clearTimeout(t)
  }, [state])

  return (
    <div className="overflow-hidden rounded-lg border border-slate-200">
      <div className="flex items-center justify-between gap-2 border-b border-slate-200 bg-slate-50/70 px-3 py-1.5">
        <span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
          <span className="text-slate-400">{icon}</span>
          {label}
        </span>
        {command ? (
          <button
            onClick={async () => setState((await copyText(command)) ? 'copied' : 'failed')}
            title={readOnly ? 'Copy is always available; rollback itself is a human action' : 'Copy command'}
            className="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-slate-500 transition-colors hover:bg-slate-200/60 hover:text-slate-800"
          >
            {state === 'copied' ? (
              <Check className="h-3 w-3 text-emerald-600" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
            {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy blocked' : 'Copy'}
          </button>
        ) : null}
      </div>
      {command ? (
        <pre className="overflow-auto bg-slate-900 px-3 py-2.5 font-mono text-[11px] leading-relaxed text-slate-100">
          {command}
        </pre>
      ) : (
        <p className="px-3 py-2.5 text-xs italic text-slate-400">{emptyText}</p>
      )}
      {note ? (
        <p className="border-t border-slate-100 bg-slate-50/60 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
          {note}
        </p>
      ) : null}
    </div>
  )
}

function AnalysisSkeleton() {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="h-5 w-40 animate-pulse rounded-full bg-slate-200" />
        <div className="h-5 w-32 animate-pulse rounded-full bg-slate-200" />
      </div>
      <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
        {[90, 78, 64].map((w, i) => (
          <div key={i} className="h-3 animate-pulse rounded bg-slate-200" style={{ width: `${w}%` }} />
        ))}
      </div>
      <div className={cn('h-16 animate-pulse rounded-lg bg-slate-200')} />
      <div className={cn('h-16 animate-pulse rounded-lg bg-slate-200')} />
    </div>
  )
}

export type { BlastRadius }
