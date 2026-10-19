import { ExternalLink, ShieldCheck, ShieldX, Ticket } from 'lucide-react'
import { cn } from '../../lib/utils'
import { complianceStyle, isComplianceViolation } from '../../lib/labels'

/**
 * Change-control badges for the timeline, inspector and reports.
 *
 * Two shapes exist because two questions get asked. `ChangeTicketBadge` answers
 * "which approved change is this?" and is only rendered when a ticket actually
 * matched. `ComplianceBadge` answers "was this allowed at all?" and is rendered
 * whenever enforcement is active — including when the answer is *no*, which is
 * the case an auditor is filtering for.
 *
 * They are deliberately separate components rather than one with a mode flag:
 * a caller that renders only the ticket badge on an unauthorised change would
 * be showing a green-ish chip for a compliance violation, which is the worst
 * possible failure mode for this feature.
 */

/** `🎫 CHG-1042 · Approved` — the matched change request. */
export function ChangeTicketBadge({
  ref: ticketRef,
  status,
  url,
  className,
  onClick,
}: {
  ref?: string
  status?: string
  url?: string
  className?: string
  onClick?: (e: React.MouseEvent) => void
}) {
  if (!ticketRef) return null

  const body = (
    <>
      <Ticket className="h-3 w-3 shrink-0" strokeWidth={2.4} />
      <span className="font-mono font-semibold">{ticketRef}</span>
      {status ? <span className="text-current/80">· {status}</span> : null}
      {url ? <ExternalLink className="h-2.5 w-2.5 shrink-0 opacity-70" /> : null}
    </>
  )

  // A ticket with a deep link becomes an anchor rather than a button, so
  // middle-click and "copy link address" behave the way an operator expects.
  if (url) {
    return (
      <a
        href={url}
        target="_blank"
        rel="noreferrer noopener"
        onClick={(e) => {
          e.stopPropagation()
          onClick?.(e)
        }}
        className={cn(
          'inline-flex max-w-full items-center gap-1.5 whitespace-nowrap rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[11px] font-medium text-blue-700 transition-colors hover:bg-blue-100',
          className,
        )}
        title={`Approved change request ${ticketRef}${status ? ` (${status})` : ''} — opens in the ITSM system`}
      >
        {body}
      </a>
    )
  }

  return (
    <span
      onClick={onClick}
      className={cn(
        'inline-flex max-w-full items-center gap-1.5 whitespace-nowrap rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[11px] font-medium text-blue-700',
        className,
      )}
      title={`Approved change request ${ticketRef}${status ? ` (${status})` : ''}`}
    >
      {body}
    </span>
  )
}

/** `⚠ Unapproved Change` / `✓ Change Approved` — the compliance verdict. */
export function ComplianceBadge({
  compliance,
  reason,
  className,
  showLabel = true,
}: {
  compliance?: string
  reason?: string
  className?: string
  /** When false, renders only the shield icon (for dense table cells). */
  showLabel?: boolean
}) {
  if (!compliance) return null
  const style = complianceStyle(compliance)
  const violating = isComplianceViolation(compliance)

  return (
    <span
      className={cn(
        'inline-flex max-w-full items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium',
        style.badge,
        className,
      )}
      title={reason || style.help}
    >
      {violating ? (
        <ShieldX className="h-3 w-3 shrink-0" strokeWidth={2.4} />
      ) : (
        <ShieldCheck className="h-3 w-3 shrink-0" strokeWidth={2.4} />
      )}
      {showLabel ? <span className="truncate">{style.label}</span> : null}
    </span>
  )
}

/**
 * The compact form used in timeline rows and table cells: the ticket if one
 * matched, otherwise the headline verdict — but never both, because a row's
 * badge slot has room for one and the ticket is the more specific fact.
 */
export function ChangeControlBadge({
  compliance,
  reason,
  ticketRef,
  ticketStatus,
  ticketUrl,
  className,
}: {
  compliance?: string
  reason?: string
  ticketRef?: string
  ticketStatus?: string
  ticketUrl?: string
  className?: string
}) {
  if (ticketRef) {
    return (
      <ChangeTicketBadge
        ref={ticketRef}
        status={ticketStatus}
        url={ticketUrl}
        className={className}
      />
    )
  }
  // A violation is always shown, even without a ticket: the absence of a ticket
  // *is* the finding.
  if (compliance && isComplianceViolation(compliance)) {
    return <ComplianceBadge compliance={compliance} reason={reason} className={className} />
  }
  return null
}
