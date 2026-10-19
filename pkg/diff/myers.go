// Package diff produces line-based unified diffs using Myers' O(ND)
// algorithm and provides the Zstd helpers used to ship them.
//
// The linear-space (middle snake) variant is used so memory stays
// proportional to the input size rather than to the edit distance squared,
// which matters under the agent's memory ceiling.
package diff

import "strings"

// OpKind is the kind of a single line edit.
type OpKind int8

const (
	Equal OpKind = iota
	Delete
	Insert
)

// Edit is one line of an edit script. A is the index of the line in the old
// text (valid for Equal and Delete), B the index in the new text (valid for
// Equal and Insert).
type Edit struct {
	Kind OpKind
	A, B int
}

// Lines computes a minimal edit script transforming a into b.
func Lines(a, b []string) []Edit {
	ia, ib, nids := intern(a, b)
	deleted := make([]bool, len(a))
	inserted := make([]bool, len(b))

	// Lines that occur on only one side can never be part of the LCS, so
	// they are marked up front and Myers only runs on the shared lines. This
	// keeps wholesale rewrites (the algorithm's worst case) cheap.
	inA, inB := make([]bool, nids), make([]bool, nids)
	for _, id := range ia {
		inA[id] = true
	}
	for _, id := range ib {
		inB[id] = true
	}
	fa, mapA := filterShared(ia, inB, deleted)
	fb, mapB := filterShared(ib, inA, inserted)

	d := newDiffer(fa, fb)
	d.compare(0, len(fa), 0, len(fb))
	for k, del := range d.deleted {
		if del {
			deleted[mapA[k]] = true
		}
	}
	for k, ins := range d.inserted {
		if ins {
			inserted[mapB[k]] = true
		}
	}
	return script(deleted, inserted)
}

// filterShared returns the ids present on the other side together with their
// original indexes, and marks the rest as changed.
func filterShared(ids []int, other []bool, changed []bool) (kept, index []int) {
	kept = make([]int, 0, len(ids))
	index = make([]int, 0, len(ids))
	for i, id := range ids {
		if other[id] {
			kept = append(kept, id)
			index = append(index, i)
		} else {
			changed[i] = true
		}
	}
	return kept, index
}

// SplitLines splits text into lines, keeping each line's terminator. A final
// line without a trailing newline is kept as-is.
func SplitLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func intern(a, b []string) (ia, ib []int, nids int) {
	ids := make(map[string]int, len(a))
	conv := func(lines []string) []int {
		out := make([]int, len(lines))
		for i, l := range lines {
			id, ok := ids[l]
			if !ok {
				id = len(ids)
				ids[l] = id
			}
			out[i] = id
		}
		return out
	}
	ia, ib = conv(a), conv(b)
	return ia, ib, len(ids)
}

type differ struct {
	a, b     []int
	deleted  []bool // deleted[i]: a[i] is not in the LCS
	inserted []bool // inserted[j]: b[j] is not in the LCS
	vf, vb   []int
	off      int
}

func newDiffer(a, b []int) *differ {
	maxD := (len(a)+len(b)+1)/2 + 1
	return &differ{
		a:        a,
		b:        b,
		deleted:  make([]bool, len(a)),
		inserted: make([]bool, len(b)),
		vf:       make([]int, 2*maxD+3),
		vb:       make([]int, 2*maxD+3),
		off:      maxD + 1,
	}
}

func (d *differ) compare(aLo, aHi, bLo, bHi int) {
	for aLo < aHi && bLo < bHi && d.a[aLo] == d.b[bLo] {
		aLo++
		bLo++
	}
	for aLo < aHi && bLo < bHi && d.a[aHi-1] == d.b[bHi-1] {
		aHi--
		bHi--
	}
	switch {
	case aLo == aHi:
		for j := bLo; j < bHi; j++ {
			d.inserted[j] = true
		}
		return
	case bLo == bHi:
		for i := aLo; i < aHi; i++ {
			d.deleted[i] = true
		}
		return
	}

	x, y, ok := d.split(aLo, aHi, bLo, bHi)
	if !ok || (x == aLo && y == bLo) || (x == aHi && y == bHi) {
		// Cannot happen for a correct middle snake, but never recurse
		// without progress: treat the whole range as replaced.
		for i := aLo; i < aHi; i++ {
			d.deleted[i] = true
		}
		for j := bLo; j < bHi; j++ {
			d.inserted[j] = true
		}
		return
	}
	d.compare(aLo, x, bLo, y)
	d.compare(x, aHi, y, bHi)
}

// split finds a point on an optimal edit path for a[aLo:aHi] -> b[bLo:bHi]
// by running the forward and reverse searches until they overlap. Callers
// guarantee both ranges are non-empty and have no common prefix or suffix,
// which makes the edit distance at least 2 and both halves strictly smaller.
func (d *differ) split(aLo, aHi, bLo, bHi int) (x, y int, ok bool) {
	n, m := aHi-aLo, bHi-bLo
	delta := n - m
	odd := delta&1 != 0
	off, vf, vb := d.off, d.vf, d.vb
	vf[off+1], vb[off+1] = 0, 0

	for D := 0; D <= (n+m+1)/2; D++ {
		// Forward search: vf[k] is the furthest x reached on diagonal k = x-y.
		for k := -D; k <= D; k += 2 {
			var x int
			if k == -D || (k != D && vf[off+k-1] < vf[off+k+1]) {
				x = vf[off+k+1]
			} else {
				x = vf[off+k-1] + 1
			}
			y := x - k
			for x < n && y >= 0 && y < m && d.a[aLo+x] == d.b[bLo+y] {
				x++
				y++
			}
			vf[off+k] = x
			if odd && k >= delta-(D-1) && k <= delta+(D-1) &&
				x <= n && y >= 0 && y <= m && x+vb[off+delta-k] >= n {
				return aLo + x, bLo + y, true
			}
		}
		// Reverse search in mirrored coordinates u = n-x, v = m-y, c = u-v.
		for c := -D; c <= D; c += 2 {
			var u int
			if c == -D || (c != D && vb[off+c-1] < vb[off+c+1]) {
				u = vb[off+c+1]
			} else {
				u = vb[off+c-1] + 1
			}
			v := u - c
			for u < n && v >= 0 && v < m && d.a[aHi-1-u] == d.b[bHi-1-v] {
				u++
				v++
			}
			vb[off+c] = u
			if k := delta - c; !odd && k >= -D && k <= D &&
				u <= n && v >= 0 && v <= m && u+vf[off+k] >= n {
				return aHi - u, bHi - v, true
			}
		}
	}
	return 0, 0, false
}

func script(deleted, inserted []bool) []Edit {
	edits := make([]Edit, 0, len(deleted)+len(inserted))
	i, j := 0, 0
	for i < len(deleted) || j < len(inserted) {
		switch {
		case i < len(deleted) && deleted[i]:
			edits = append(edits, Edit{Kind: Delete, A: i, B: j})
			i++
		case j < len(inserted) && inserted[j]:
			edits = append(edits, Edit{Kind: Insert, A: i, B: j})
			j++
		default:
			edits = append(edits, Edit{Kind: Equal, A: i, B: j})
			i++
			j++
		}
	}
	return edits
}
