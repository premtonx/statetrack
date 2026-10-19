import { useMemo } from 'react'

/**
 * A minimal, dependency-free QR code encoder for TOTP enrollment.
 *
 * Why hand-rolled rather than a library: the console's rule is no bloated
 * external bundles, and this is the only place the console needs a QR code. The
 * payload is always a short ASCII `otpauth://` URI of well under 200 bytes, so
 * byte mode at version 9-ish with error-correction level M is always sufficient
 * — which means the encoder only has to implement the subset of the spec that
 * range actually uses, not the full matrix of 40 versions and four modes.
 *
 * The implementation follows ISO/IEC 18004 section 8: data encoding, Reed-Solomon
 * error correction over GF(256), block interleaving, module placement, and the
 * eight data masks with their penalty rules.
 */

/* -------------------------------------------------------------------------- */
/* Galois field arithmetic (GF(256), primitive polynomial 0x11d)              */
/* -------------------------------------------------------------------------- */

const GF_EXP = new Uint8Array(512)
const GF_LOG = new Uint8Array(256)

;(function initGaloisField() {
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
  // Duplicate the table so multiplication can index exp[a+b] without a modulo.
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]
})()

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0
  return GF_EXP[GF_LOG[a] + GF_LOG[b]]
}

/** Reed-Solomon generator polynomial of the given degree. */
function rsGenerator(degree: number): Uint8Array {
  let poly = new Uint8Array([1])
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1)
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j]
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i])
    }
    poly = next
  }
  return poly
}

/** Computes the Reed-Solomon error-correction codewords for one block. */
function rsEncode(data: Uint8Array, ecLen: number): Uint8Array {
  const gen = rsGenerator(ecLen)
  const res = new Uint8Array(ecLen)
  for (const byte of data) {
    const factor = byte ^ res[0]
    res.copyWithin(0, 1)
    res[ecLen - 1] = 0
    if (factor !== 0) {
      for (let i = 0; i < ecLen; i++) {
        res[i] ^= gfMul(gen[i + 1], factor)
      }
    }
  }
  return res
}

/* -------------------------------------------------------------------------- */
/* Capacity tables (error-correction level M)                                 */
/* -------------------------------------------------------------------------- */

/**
 * Version capacity at EC level M, per ISO/IEC 18004 Table 9.
 *
 * Only three authoritative numbers per version: the symbol's total codewords,
 * the total error-correction codewords, and the block count. The block *layout*
 * is derived in `blockLayout` rather than tabulated, because the group split is
 * a formula and a hand-copied table is one transposed digit away from a symbol
 * that scans as garbage — which is exactly the bug this replaced.
 *
 * Note `ecTotal` is the spec's "number of error correction codewords" column: a
 * total across all blocks, not a per-block value.
 */
const EC_LEVEL_M: Record<number, { total: number; ecTotal: number; blocks: number }> = {
  1: { total: 26, ecTotal: 10, blocks: 1 },
  2: { total: 44, ecTotal: 16, blocks: 1 },
  3: { total: 70, ecTotal: 26, blocks: 1 },
  4: { total: 100, ecTotal: 36, blocks: 2 },
  5: { total: 134, ecTotal: 48, blocks: 2 },
  6: { total: 172, ecTotal: 64, blocks: 4 },
  7: { total: 196, ecTotal: 72, blocks: 4 },
  8: { total: 242, ecTotal: 88, blocks: 4 },
  9: { total: 292, ecTotal: 110, blocks: 5 },
  10: { total: 346, ecTotal: 130, blocks: 5 },
  11: { total: 404, ecTotal: 150, blocks: 5 },
  12: { total: 466, ecTotal: 176, blocks: 8 },
  13: { total: 532, ecTotal: 198, blocks: 9 },
  14: { total: 581, ecTotal: 216, blocks: 9 },
  15: { total: 655, ecTotal: 240, blocks: 10 },
  16: { total: 733, ecTotal: 280, blocks: 10 },
}

/**
 * The block layout for a version, derived the way the spec defines it.
 *
 * The remainder of `total / blocks` tells how many blocks belong to group 2;
 * group 2 blocks carry one extra data codeword each. This holds for every
 * version and EC level, so there is no table to get wrong.
 */
function blockLayout(version: number): {
  g1Blocks: number
  g2Blocks: number
  g1DataLen: number
  g2DataLen: number
  ecPerBlock: number
} {
  const spec = EC_LEVEL_M[version]
  const dataTotal = spec.total - spec.ecTotal
  const g2Blocks = spec.total % spec.blocks
  const g1Blocks = spec.blocks - g2Blocks
  const g1TotalLen = Math.floor(spec.total / spec.blocks)
  const g1DataLen = Math.floor(dataTotal / spec.blocks)
  // Every block in a version carries the same number of EC codewords, which is
  // the difference between a group-1 block's total length and its data length.
  const ecPerBlock = g1TotalLen - g1DataLen
  const g2DataLen = g2Blocks > 0 ? g1DataLen + 1 : 0
  return { g1Blocks, g2Blocks, g1DataLen, g2DataLen, ecPerBlock }
}

/** Data codewords available at a version (total minus its error correction). */
function dataCapacity(version: number): number {
  const spec = EC_LEVEL_M[version]
  return spec.total - spec.ecTotal
}

/** Alignment-pattern centre coordinates, from the spec's Appendix E. */
const ALIGNMENT_CENTRES: Record<number, number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
  11: [6, 30, 54],
  12: [6, 32, 58],
  13: [6, 34, 62],
  14: [6, 26, 46, 66],
  15: [6, 26, 48, 70],
  16: [6, 26, 50, 74],
}

/* -------------------------------------------------------------------------- */
/* Bit buffer                                                                 */
/* -------------------------------------------------------------------------- */

class BitBuffer {
  readonly bits: number[] = []

  put(value: number, length: number) {
    for (let i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1)
    }
  }

  get length() {
    return this.bits.length
  }
}

/* -------------------------------------------------------------------------- */
/* Encoding pipeline                                                          */
/* -------------------------------------------------------------------------- */

/** Picks the smallest version whose data capacity fits the payload. */
function chooseVersion(byteLength: number): number {
  // 4 bits for the mode indicator, a character count (8 bits up to version 9,
  // 16 above), then the payload itself.
  for (let v = 1; v <= 16; v++) {
    const countBits = v < 10 ? 8 : 16
    const needed = Math.ceil((4 + countBits + byteLength * 8) / 8)
    if (needed <= dataCapacity(v)) return v
  }
  throw new Error('QR payload too large for the supported versions')
}

function encodeData(text: string, version: number): Uint8Array {
  const bytes = new TextEncoder().encode(text)
  const buf = new BitBuffer()

  buf.put(0b0100, 4) // byte mode
  buf.put(bytes.length, version < 10 ? 8 : 16)
  for (const b of bytes) buf.put(b, 8)

  const capacityBits = dataCapacity(version) * 8
  // Terminator: up to four zero bits, then pad to a byte boundary.
  buf.put(0, Math.min(4, capacityBits - buf.length))
  while (buf.length % 8 !== 0) buf.put(0, 1)

  // Pad codewords 0xEC / 0x11 alternate until the capacity is filled.
  let pad = 0
  while (buf.length < capacityBits) {
    buf.put(pad++ % 2 === 0 ? 0xec : 0x11, 8)
  }

  const out = new Uint8Array(buf.length / 8)
  for (let i = 0; i < buf.length; i += 8) {
    let byte = 0
    for (let j = 0; j < 8; j++) byte = (byte << 1) | buf.bits[i + j]
    out[i / 8] = byte
  }
  return out
}

/** Splits data into blocks, adding error correction, then interleaves. */
function buildCodewords(data: Uint8Array, version: number): Uint8Array {
  const spec = EC_LEVEL_M[version]
  const layout = blockLayout(version)

  const dataBlocks: Uint8Array[] = []
  const ecBlocks: Uint8Array[] = []
  let offset = 0
  for (let b = 0; b < spec.blocks; b++) {
    const len = b < layout.g1Blocks ? layout.g1DataLen : layout.g2DataLen
    const block = data.slice(offset, offset + len)
    offset += len
    dataBlocks.push(block)
    ecBlocks.push(rsEncode(block, layout.ecPerBlock))
  }

  const result = new Uint8Array(spec.total)
  let p = 0
  // Interleave data codewords column-wise across blocks. Group 2's extra
  // codeword is read after every group-1 block has contributed, which is why
  // the guard is on the block's own length rather than a fixed stride.
  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length))
  for (let i = 0; i < maxDataLen; i++) {
    for (const block of dataBlocks) {
      if (i < block.length) result[p++] = block[i]
    }
  }
  // Then interleave the error-correction codewords, all the same length.
  for (let i = 0; i < layout.ecPerBlock; i++) {
    for (const block of ecBlocks) {
      result[p++] = block[i]
    }
  }
  return result
}

/* -------------------------------------------------------------------------- */
/* Matrix construction                                                        */
/* -------------------------------------------------------------------------- */

const FUNCTION_RESERVED = 0x80
const DARK = 1
const LIGHT = 0

class Matrix {
  readonly size: number
  /** Module values (0/1) for data modules. */
  readonly modules: Uint8Array
  /** Non-zero where the module belongs to a function pattern (not maskable). */
  readonly reserved: Uint8Array

  constructor(size: number) {
    this.size = size
    this.modules = new Uint8Array(size * size)
    this.reserved = new Uint8Array(size * size)
  }

  get(x: number, y: number): number {
    return this.modules[y * this.size + x]
  }

  set(x: number, y: number, value: number) {
    this.modules[y * this.size + x] = value
  }

  reserve(x: number, y: number) {
    this.reserved[y * this.size + x] = FUNCTION_RESERVED
  }

  isReserved(x: number, y: number): boolean {
    return this.reserved[y * this.size + x] !== 0
  }
}

function placeFinderRings(m: Matrix, cx: number, cy: number) {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx
      const y = cy + dy
      if (x < 0 || y < 0 || x >= m.size || y >= m.size) continue
      const dist = Math.max(Math.abs(dx), Math.abs(dy))
      // Concentric rings: separator (4) and gap (2) are light; the outer ring
      // (3) and the 3x3 core (0..1) are dark.
      m.set(x, y, dist === 4 || dist === 2 ? LIGHT : DARK)
      m.reserve(x, y)
    }
  }
}

function placeAlignmentPattern(m: Matrix, cx: number, cy: number) {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      // 5x5: dark ring, light ring, dark centre.
      const dist = Math.max(Math.abs(dx), Math.abs(dy))
      m.set(cx + dx, cy + dy, dist === 1 ? LIGHT : DARK)
      m.reserve(cx + dx, cy + dy)
    }
  }
}

/**
 * The 18-bit version information block, present only on versions 7 and above.
 *
 * A 6-bit version number extended with 12 Golay error-correction bits, reduced
 * modulo the G18 generator polynomial. Without this block a version-7 symbol
 * scans as a lower version with misread data, which is exactly the failure this
 * (and the missing reservation for it) caused.
 */
function versionInfoBits(version: number): number {
  const G18 = 0b1111100100101
  const bchDigit = (n: number) => {
    let d = 0
    while (n !== 0) {
      d++
      n >>>= 1
    }
    return d
  }
  const g18Digit = bchDigit(G18)
  let d = version << 12
  while (bchDigit(d) - g18Digit >= 0) {
    d ^= G18 << (bchDigit(d) - g18Digit)
  }
  return (version << 12) | d
}

/**
 * Places and reserves the version information, in the two 3x6 blocks beside the
 * top-right and bottom-left finder patterns. No-op below version 7.
 */
function placeVersionInfo(m: Matrix, version: number) {
  if (version < 7) return
  const size = m.size
  const bits = versionInfoBits(version)
  for (let i = 0; i < 18; i++) {
    const row = Math.floor(i / 3)
    const col = (i % 3) + size - 11
    const value = (bits >>> i) & 1
    // Row-major block and its transposed counterpart.
    m.set(col, row, value)
    m.reserve(col, row)
    m.set(row, col, value)
    m.reserve(row, col)
  }
}

function placeFunctionPatterns(m: Matrix, version: number) {
  const size = m.size

  // Finder patterns in three corners.
  placeFinderRings(m, 3, 3)
  placeFinderRings(m, size - 4, 3)
  placeFinderRings(m, 3, size - 4)

  // Timing patterns along row/column 6: alternating starting dark at index 8.
  for (let i = 8; i < size - 8; i++) {
    const v = i % 2 === 0 ? DARK : LIGHT
    m.set(i, 6, v)
    m.reserve(i, 6)
    m.set(6, i, v)
    m.reserve(6, i)
  }

  // Alignment patterns, skipping the three corners occupied by finder patterns.
  // A centre is skipped when it falls inside an existing function area, which is
  // exactly what the reserved map already records.
  const centres = ALIGNMENT_CENTRES[version] ?? []
  for (const cy of centres) {
    for (const cx of centres) {
      if (cx <= 8 && cy <= 8) continue // top-left finder
      if (cx >= size - 9 && cy <= 8) continue // top-right finder
      if (cx <= 8 && cy >= size - 9) continue // bottom-left finder
      placeAlignmentPattern(m, cx, cy)
    }
  }

  // Dark module, always at (8, size-8).
  m.set(8, size - 8, DARK)
  m.reserve(8, size - 8)

  // Version information, for version 7 and above.
  placeVersionInfo(m, version)

  // Reserve the format-information modules before the data walk, and the
  // mirrors of the split format blocks. Derived from the same helper the writer
  // uses, so the two can never disagree about which modules are format bits.
  for (const [x, y] of formatModulePositions(size)) {
    m.reserve(x, y)
  }
}

/* -------------------------------------------------------------------------- */
/* Data placement                                                             */
/* -------------------------------------------------------------------------- */

function placeData(m: Matrix, codewords: Uint8Array) {
  let bitIndex = 0
  const totalBits = codewords.length * 8

  // Two-module-wide columns, right to left, alternating direction upward and
  // downward, skipping the vertical timing column (6).
  for (let x = m.size - 1; x > 0; x -= 2) {
    if (x === 6) x-- // skip the timing column
    const upward = ((m.size - 1 - x) / 2) % 2 === 0
    for (let i = 0; i < m.size; i++) {
      const y = upward ? m.size - 1 - i : i
      for (let dx = 0; dx < 2; dx++) {
        const cx = x - dx
        if (m.isReserved(cx, y)) continue
        let value = LIGHT
        if (bitIndex < totalBits) {
          const byte = codewords[bitIndex >> 3]
          value = (byte >>> (7 - (bitIndex & 7))) & 1
          bitIndex++
        }
        m.set(cx, y, value)
      }
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Masking                                                                    */
/* -------------------------------------------------------------------------- */

const MASKS: ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
]

/** Applies a mask in place to every non-reserved module. */
function applyMask(m: Matrix, maskIndex: number) {
  const fn = MASKS[maskIndex]
  for (let y = 0; y < m.size; y++) {
    for (let x = 0; x < m.size; x++) {
      if (m.isReserved(x, y)) continue
      if (fn(x, y)) m.set(x, y, m.get(x, y) ^ 1)
    }
  }
}

/** The four penalty rules from the spec, used to pick the least-noisy mask. */
function maskPenalty(m: Matrix): number {
  const size = m.size
  let penalty = 0

  // Rule 1: runs of five or more same-coloured modules in a row or column.
  for (let y = 0; y < size; y++) {
    let run = 1
    for (let x = 1; x < size; x++) {
      if (m.get(x, y) === m.get(x - 1, y)) {
        run++
      } else {
        if (run >= 5) penalty += run - 2
        run = 1
      }
    }
    if (run >= 5) penalty += run - 2
  }
  for (let x = 0; x < size; x++) {
    let run = 1
    for (let y = 1; y < size; y++) {
      if (m.get(x, y) === m.get(x, y - 1)) {
        run++
      } else {
        if (run >= 5) penalty += run - 2
        run = 1
      }
    }
    if (run >= 5) penalty += run - 2
  }

  // Rule 2: every 2x2 block of one colour.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const v = m.get(x, y)
      if (v === m.get(x + 1, y) && v === m.get(x, y + 1) && v === m.get(x + 1, y + 1)) {
        penalty += 3
      }
    }
  }

  // Rule 4: proportion of dark modules away from 50%.
  let dark = 0
  for (let i = 0; i < m.modules.length; i++) dark += m.modules[i]
  const ratio = (dark * 100) / m.modules.length
  penalty += Math.floor(Math.abs(ratio - 50) / 5) * 10

  return penalty
}

/** Rule 3 (finder-like patterns) is folded into the mask choice via this scan. */
function finderLikePenalty(m: Matrix): number {
  const size = m.size
  const pattern = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
  let penalty = 0
  const matches = (get: (i: number) => number, start: number) => {
    for (let i = 0; i < pattern.length; i++) {
      if (get(start + i) !== pattern[i]) return false
    }
    return true
  }
  for (let y = 0; y < size; y++) {
    for (let x = 0; x + pattern.length <= size; x++) {
      if (matches((i) => m.get(x + i, y), x)) penalty += 40
    }
  }
  for (let x = 0; x < size; x++) {
    for (let y = 0; y + pattern.length <= size; y++) {
      if (matches((i) => m.get(x, y + i), y)) penalty += 40
    }
  }
  return penalty
}

/* -------------------------------------------------------------------------- */
/* Format information                                                         */
/* -------------------------------------------------------------------------- */

/** BCH(15,5) format information: EC level M (0b00), mask index, then masked. */
function formatBits(maskIndex: number): number {
  // G15 and its mask, per ISO/IEC 18004 Annex C.
  const G15 = 0b10100110111
  const G15_MASK = 0b101010000010010
  const bchDigit = (n: number) => {
    let d = 0
    while (n !== 0) {
      d++
      n >>>= 1
    }
    return d
  }

  const data = (0b00 << 3) | maskIndex // 0b00 == EC level M
  let d = data << 10
  while (bchDigit(d) - bchDigit(G15) >= 0) {
    d ^= G15 << (bchDigit(d) - bchDigit(G15))
  }
  return ((data << 10) | d) ^ G15_MASK
}

/**
 * The 31 module positions the format information occupies: 15 bits in each of
 * two copies, plus the always-dark module.
 *
 * The two copies are an L-shaped strip beside the top-left finder (vertical, at
 * x=8, continuing below the bottom-left finder) and its mirror (horizontal, at
 * y=8, continuing under the top-right finder). They meet only visually; the
 * coordinates do not overlap, and the strips step over the timing patterns at
 * x=6 / y=6.
 *
 * Exposed as one list so reservation and writing cannot disagree — a single
 * mis-reserved module lets the data walker overwrite a format bit and the symbol
 * becomes unscannable while still looking like a valid QR code.
 */
function formatModulePositions(size: number): [number, number][] {
  const positions: [number, number][] = []
  for (let i = 0; i < 15; i++) {
    // Copy 1 (vertical then bottom-left).
    const y1 = i < 6 ? i : i < 8 ? i + 1 : size - 15 + i
    positions.push([8, y1])
    // Copy 2 (top-right then horizontal-left).
    const x2 = i < 8 ? size - 1 - i : i === 8 ? 7 : 14 - i
    positions.push([x2, 8])
  }
  positions.push([8, size - 8]) // the always-dark module
  return positions
}

function placeFormatInfo(m: Matrix, maskIndex: number) {
  const size = m.size
  const bits = formatBits(maskIndex)

  for (let i = 0; i < 15; i++) {
    const value = (bits >>> i) & 1
    // Copy 1: down column 8, then the bottom-left vertical strip.
    if (i < 6) {
      m.set(8, i, value)
    } else if (i < 8) {
      m.set(8, i + 1, value)
    } else {
      m.set(8, size - 15 + i, value)
    }
    // Copy 2: the bottom-left horizontal strip, then along row 8 to the left.
    if (i < 8) {
      m.set(size - 1 - i, 8, value)
    } else if (i === 8) {
      m.set(7, 8, value)
    } else {
      m.set(14 - i, 8, value)
    }
  }

  // The always-dark module.
  m.set(8, size - 8, DARK)
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Encodes `text` and returns a square boolean matrix (true = dark module).
 * Throws if the payload exceeds the supported capacity, which for an otpauth URI
 * cannot happen in practice.
 */
export function encodeQR(text: string): boolean[][] {
  const version = chooseVersion(new TextEncoder().encode(text).length)
  const data = encodeData(text, version)
  const codewords = buildCodewords(data, version)

  const size = version * 4 + 17

  // Try all eight masks and keep the one the penalty rules like best.
  let best: Matrix | null = null
  let bestPenalty = Infinity
  for (let mask = 0; mask < 8; mask++) {
    const m = new Matrix(size)
    placeFunctionPatterns(m, version)
    placeData(m, codewords)
    applyMask(m, mask)
    placeFormatInfo(m, mask)

    const penalty = maskPenalty(m) + finderLikePenalty(m)
    if (penalty < bestPenalty) {
      bestPenalty = penalty
      best = m
    }
  }

  const chosen = best as Matrix
  const matrix: boolean[][] = []
  for (let y = 0; y < size; y++) {
    const row: boolean[] = []
    for (let x = 0; x < size; x++) row.push(chosen.get(x, y) === DARK)
    matrix.push(row)
  }
  return matrix
}

/**
 * Renders a QR code for `value` as an SVG. Dependency-free and always crisp at
 * any size, which matters because a blurry enrollment QR is the difference
 * between 2FA working and a support ticket.
 */
export default function QRCode({ value, size = 176, className }: { value: string; size?: number; className?: string }) {
  const matrix = useMemo(() => {
    try {
      return encodeQR(value)
    } catch {
      return null
    }
  }, [value])

  if (!matrix) {
    // A QR that cannot be generated must not blank the enrollment dialog: the
    // manual entry key is rendered alongside it and is always sufficient.
    return (
      <div
        className={className}
        style={{ width: size, height: size }}
        role="img"
        aria-label="QR code unavailable — use the setup key"
      >
        <div className="flex h-full w-full items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 text-center text-[11px] text-slate-400">
          Use the setup key
        </div>
      </div>
    )
  }

  const count = matrix.length
  // A 4-module quiet zone is required by the spec for reliable scanning.
  const quiet = 4
  const dim = count + quiet * 2
  const paths: string[] = []
  for (let y = 0; y < count; y++) {
    for (let x = 0; x < count; x++) {
      if (matrix[y][x]) {
        paths.push(`M${x + quiet},${y + quiet}h1v1h-1z`)
      }
    }
  }

  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      shapeRendering="crispEdges"
      role="img"
      aria-label="Two-factor authentication QR code"
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <path d={paths.join('')} fill="#0f172a" />
    </svg>
  )
}
