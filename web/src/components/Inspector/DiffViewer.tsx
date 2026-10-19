import { useEffect, useMemo, useRef } from 'react'
import { DiffEditor, type DiffOnMount } from '@monaco-editor/react'
import { ShieldAlert } from 'lucide-react'
import { monaco } from '../../lib/monaco'
import { detectLanguage, hasRedacted, unifiedToSides } from '../../lib/diff'

interface DiffViewerProps {
  diff: string
  pathOrKey: string
  targetType?: string
  /** Stable key for the underlying models (normally the event id). */
  modelKey: string
  /** Editor height; the drawer passes a taller value for side-by-side review. */
  height?: number | string
  sideBySide?: boolean
}

const REDACTED_RE = /\[REDACTED:[a-z0-9]+:[0-9a-f]+(?:\.\.\.)?\]/i

/**
 * Side-by-side Monaco diff viewer with redaction highlighting.
 *
 * Models are addressed by explicit URI and kept alive across unmounts
 * (`keepCurrent*Model`), then disposed from a deferred cleanup. This avoids
 * Monaco's "TextModel got disposed before DiffEditorWidget model got reset"
 * race, which fires when the editor auto-disposes its models during React's
 * commit phase (and is amplified by StrictMode's double-invoked effects).
 */
export default function DiffViewer({
  diff,
  pathOrKey,
  targetType,
  modelKey,
  height = 520,
  sideBySide = true,
}: DiffViewerProps) {
  const language = useMemo(() => detectLanguage(pathOrKey, targetType), [pathOrKey, targetType])
  const sides = useMemo(() => unifiedToSides(diff), [diff])
  const redacted = useMemo(() => hasRedacted(diff), [diff])

  const originalPath = `inmemory://statetrack/${modelKey}/before`
  const modifiedPath = `inmemory://statetrack/${modelKey}/after`

  // Counts live editors so a StrictMode remount (cleanup → effect) never
  // disposes models that the remounted editor is about to reuse.
  const epoch = useRef(0)
  useEffect(() => {
    const mine = ++epoch.current
    return () => {
      window.setTimeout(() => {
        if (epoch.current !== mine) return
        for (const uri of [originalPath, modifiedPath]) {
          monaco.editor.getModel(monaco.Uri.parse(uri))?.dispose()
        }
      }, 0)
    }
  }, [originalPath, modifiedPath])

  const handleMount: DiffOnMount = (editor) => {
    if (!redacted) return
    const modified = editor.getModifiedEditor()
    const model = modified.getModel()
    if (!model) return
    const decorations: monaco.editor.IModelDeltaDecoration[] = []
    for (let i = 1; i <= model.getLineCount(); i++) {
      if (REDACTED_RE.test(model.getLineContent(i))) {
        decorations.push({
          range: new monaco.Range(i, 1, i, 1),
          options: { isWholeLine: true, className: 'monaco-redacted-line' },
        })
      }
    }
    modified.deltaDecorations([], decorations)
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-200">
      <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-3 py-1.5">
        <div className="flex items-center gap-2 font-mono text-[11px] text-slate-500">
          <span className="text-red-600">−</span> before
          <span className="text-emerald-600">+</span> after
          <span className="ml-2 rounded border border-slate-200 bg-white px-1 py-0.5 uppercase">
            {language}
          </span>
        </div>
        {redacted ? (
          <span className="flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-700">
            <ShieldAlert className="h-3.5 w-3.5" />
            Secrets redacted
          </span>
        ) : null}
      </div>
      <DiffEditor
        height={height}
        language={language}
        original={sides.before}
        modified={sides.after}
        originalModelPath={originalPath}
        modifiedModelPath={modifiedPath}
        keepCurrentOriginalModel
        keepCurrentModifiedModel
        onMount={handleMount}
        loading={<div className="p-4 text-xs text-slate-400">Loading diff editor…</div>}
        options={{
          readOnly: true,
          renderSideBySide: sideBySide,
          minimap: { enabled: false },
          fontSize: 12,
          fontFamily: 'var(--font-mono)',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          renderOverviewRuler: false,
          lineNumbers: 'on',
          folding: true,
          wordWrap: 'on',
        }}
      />
    </div>
  )
}
