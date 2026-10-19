package diff

import (
	"strconv"
	"strings"
)

// DefaultContext is the number of unchanged lines shown around each change.
const DefaultContext = 3

const noNewline = "\\ No newline at end of file\n"

// Unified returns a unified diff (diff -u / git compatible) between oldText
// and newText, labelled fromName and toName. It returns "" when the texts are
// identical. A negative context selects DefaultContext.
func Unified(fromName, toName, oldText, newText string, context int) string {
	if oldText == newText {
		return ""
	}
	if context < 0 {
		context = DefaultContext
	}
	a, b := SplitLines(oldText), SplitLines(newText)
	edits := Lines(a, b)

	var out strings.Builder
	out.WriteString("--- " + fromName + "\n")
	out.WriteString("+++ " + toName + "\n")

	for _, h := range hunks(edits, context) {
		writeHunk(&out, edits[h[0]:h[1]], a, b)
	}
	return out.String()
}

// hunks groups edits into [start, end) ranges of the edit script, each change
// surrounded by up to context equal lines and merged with its neighbour when
// the gap between them is at most 2*context.
func hunks(edits []Edit, context int) [][2]int {
	var hs [][2]int
	for i := 0; i < len(edits); {
		if edits[i].Kind == Equal {
			i++
			continue
		}
		start := max(0, i-context)
		j := i
		for {
			for j < len(edits) && edits[j].Kind != Equal {
				j++
			}
			k := j
			for k < len(edits) && edits[k].Kind == Equal {
				k++
			}
			if k < len(edits) && k-j <= 2*context {
				j = k
				continue
			}
			break
		}
		hs = append(hs, [2]int{start, min(len(edits), j+context)})
		i = j
	}
	return hs
}

func writeHunk(out *strings.Builder, edits []Edit, a, b []string) {
	var aCount, bCount int
	for _, e := range edits {
		if e.Kind != Insert {
			aCount++
		}
		if e.Kind != Delete {
			bCount++
		}
	}
	out.WriteString("@@ -" + hunkRange(edits[0].A, aCount) + " +" + hunkRange(edits[0].B, bCount) + " @@\n")
	for _, e := range edits {
		switch e.Kind {
		case Equal:
			writeLine(out, ' ', a[e.A])
		case Delete:
			writeLine(out, '-', a[e.A])
		case Insert:
			writeLine(out, '+', b[e.B])
		}
	}
}

// hunkRange formats a hunk range the way GNU diff does: the count is omitted
// when it is 1, and an empty range points at the line before it.
func hunkRange(start, count int) string {
	switch count {
	case 0:
		return strconv.Itoa(start) + ",0"
	case 1:
		return strconv.Itoa(start + 1)
	}
	return strconv.Itoa(start+1) + "," + strconv.Itoa(count)
}

func writeLine(out *strings.Builder, marker byte, line string) {
	out.WriteByte(marker)
	out.WriteString(line)
	if !strings.HasSuffix(line, "\n") {
		out.WriteString("\n" + noNewline)
	}
}
