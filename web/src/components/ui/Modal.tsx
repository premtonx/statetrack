import { useEffect, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { cn } from '../../lib/utils'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: ReactNode
  /** Optional supporting sentence under the title. */
  description?: ReactNode
  children: ReactNode
  /** Right-aligned footer actions. */
  footer?: ReactNode
  /** Panel width; defaults to a comfortable form width. */
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

const SIZES: Record<'sm' | 'md' | 'lg', string> = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
}

/**
 * Centred modal dialog for the console's create/enroll flows.
 *
 * Kept deliberately small: the console already has a slide-over (the inspector
 * and the recommendations drawer) for browsing, so this exists only for a short
 * form or a one-time secret that must be acknowledged before it disappears.
 *
 * Escape closes it, and a backdrop click does too — except that the two
 * one-time-secret dialogs opt out via `dismissible={false}` so a stray click
 * cannot discard the only copy of a minted credential.
 */
export default function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
  className,
}: ModalProps) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center overflow-y-auto p-4 sm:items-center" role="dialog" aria-modal="true">
      <div className="drawer-backdrop absolute inset-0 bg-slate-900/30" onClick={onClose} aria-hidden />
      <div
        className={cn(
          'panel-enter relative my-auto w-full overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl',
          SIZES[size],
          className,
        )}
      >
        <div className="flex items-start gap-3 border-b border-slate-200 px-5 py-4">
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-sm font-semibold text-slate-900">{title}</h2>
            {description ? (
              <p className="mt-0.5 text-xs text-slate-500">{description}</p>
            ) : null}
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="px-5 py-4">{children}</div>

        {footer ? (
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-200 bg-slate-50/70 px-5 py-3">
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  )
}
