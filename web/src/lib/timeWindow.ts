/**
 * Stable time windows for API queries.
 *
 * Building a filter with `new Date(Date.now() - …)` inline in a component body
 * produces a **new string on every render**. React Query hashes query keys
 * structurally, so an inline timestamp turns every render into a cache miss:
 * the in-flight request is cancelled and restarted before it can settle,
 * `data` stays `undefined`, and pages silently fall back to their seeded
 * preview store (whose row IDs the API does not know).
 *
 * Always derive the window through these helpers, from inside a `useMemo`
 * whose dependencies are the filter values — never call `Date.now()` directly
 * in a render body. Flooring to a coarse bucket additionally keeps the key
 * byte-identical when a memo re-runs for an unrelated reason.
 */

/** Milliseconds in each of the range presets offered by the UI. */
export function rangeToSeconds(range: string): number {
  switch (range) {
    case '15m':
      return 15 * 60
    case '1h':
      return 3600
    case '7d':
      return 7 * 24 * 3600
    case '30d':
      return 30 * 24 * 3600
    default:
      return 24 * 3600
  }
}

/**
 * Bucket size per preset. The lower bound only ever moves *earlier* as the
 * bucket rolls over, so a window that already returned data is never narrowed
 * — a subsequent refetch simply covers slightly more history.
 */
const BUCKET_MS: Record<string, number> = {
  '15m': 60_000,
  '1h': 5 * 60_000,
  '24h': 15 * 60_000,
  '7d': 60 * 60_000,
  '30d': 6 * 60 * 60_000,
}

/**
 * RFC3339 lower bound for a range preset (e.g. `"24h"`). Stable for the
 * duration of one bucket. Returns `undefined` for an unknown preset so the
 * caller can omit the filter entirely.
 */
export function windowFrom(range: string, now: number = Date.now()): string | undefined {
  const bucket = BUCKET_MS[range]
  if (!bucket) return undefined
  const from = Math.floor(now / bucket) * bucket - rangeToSeconds(range) * 1000
  return new Date(from).toISOString()
}
