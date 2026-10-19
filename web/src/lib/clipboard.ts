/**
 * Clipboard helper shared by every copy affordance in the console (integration
 * assets, one-time API keys, enrollment bootstrap commands).
 *
 * It lives on its own rather than inside the Integrations feature because the
 * Settings security surface needs the same behaviour, and a second
 * implementation of a fallback path like this is how the two drift.
 */

/**
 * Copies text to the clipboard, returning whether it worked.
 *
 * The Clipboard API needs a secure context, and `navigator.clipboard` is
 * genuinely absent on a plain-HTTP LAN address — a realistic way an operator
 * reaches this console. Falls back to a hidden textarea + execCommand so the
 * button is not silently dead there, and reports failure so the UI can say so
 * instead of falsely claiming success.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    /* fall through to the legacy path */
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '-1000px'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
