// Helpers for turning a unified diff (as returned by the backend) into the
// before/after sides Monaco's DiffEditor expects, plus language detection and
// redaction helpers.

export interface DiffSides {
  before: string
  after: string
}

/**
 * Reconstructs the before/after texts from a unified diff. Lines beginning
 * with `-` are removed, `+` added, and ` ` context. Handles the common
 * `--- ` / `+++ ` file headers and `@@ ... @@` hunk markers produced by the
 * server's Myers diff.
 */
export function unifiedToSides(unified: string): DiffSides {
  const before: string[] = []
  const after: string[] = []

  for (const raw of unified.split('\n')) {
    if (raw === '') {
      before.push('')
      after.push('')
      continue
    }
    if (raw.startsWith('+++') || raw.startsWith('---') || raw.startsWith('@@')) {
      continue
    }
    if (raw.startsWith('\\')) {
      // "\ No newline at end of file" marker — already handled by newline split.
      continue
    }
    const marker = raw[0]
    const line = raw.slice(1)
    switch (marker) {
      case ' ':
        before.push(line)
        after.push(line)
        break
      case '-':
        before.push(line)
        break
      case '+':
        after.push(line)
        break
      default:
        // Malformed or context line without a space marker.
        before.push(raw)
        after.push(raw)
    }
  }

  return { before: before.join('\n'), after: after.join('\n') }
}

/** Map a target path/key to a Monaco language for syntax highlighting. */
export function detectLanguage(pathOrKey: string, targetType?: string): string {
  const lower = (pathOrKey || '').toLowerCase()
  const base = lower.split(/[?#]/)[0]

  if (targetType === 'registry') return 'ini'
  if (base.endsWith('.json') || base.endsWith('.json5') || base.endsWith('.jsonc'))
    return 'json'
  if (base.endsWith('.yml') || base.endsWith('.yaml')) return 'yaml'
  if (base.endsWith('.xml') || base.endsWith('.config') || base.endsWith('.csproj'))
    return 'xml'
  if (base.endsWith('.ini') || base.endsWith('.conf') || base.endsWith('.cfg') || base.endsWith('.service'))
    return 'ini'
  if (base.endsWith('.sh') || base.endsWith('.bash') || base.endsWith('.zsh') || base.includes('shell'))
    return 'shell'
  if (base.endsWith('.js') || base.endsWith('.ts') || base.endsWith('.jsx') || base.endsWith('.tsx'))
    return 'javascript'
  if (base.endsWith('.py')) return 'python'
  if (base.endsWith('.toml')) return 'ini'
  // nginx, systemd units, env files and friends read well as ini.
  if (base.endsWith('nginx.conf') || base.includes('/nginx/') || base.endsWith('.env'))
    return 'ini'
  return 'plaintext'
}

const REDACTED_RE = /\[REDACTED:[a-z0-9]+:[0-9a-f]+(?:\.\.\.)?\]/i

/** True if the diff text contains any redacted secret marker. */
export function hasRedacted(diff: string): boolean {
  return REDACTED_RE.test(diff)
}

/** Split the redacted marker so React renders the `[` and `]` literally. */
export function redactedBadge(line: string): boolean {
  return REDACTED_RE.test(line)
}
