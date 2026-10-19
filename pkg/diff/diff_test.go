package diff

import (
	"bytes"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func lcsLen(a, b []string) int {
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	return dp[0][0]
}

// checkScript verifies edits is a valid, minimal script from a to b.
func checkScript(t *testing.T, a, b []string, edits []Edit) {
	t.Helper()
	var gotB []string
	i, j, changes := 0, 0, 0
	for _, e := range edits {
		switch e.Kind {
		case Equal:
			if e.A != i || e.B != j || a[i] != b[j] {
				t.Fatalf("bad equal edit %+v at i=%d j=%d (a=%q b=%q)", e, i, j, a, b)
			}
			gotB = append(gotB, a[i])
			i++
			j++
		case Delete:
			if e.A != i {
				t.Fatalf("bad delete edit %+v at i=%d", e, i)
			}
			i++
			changes++
		case Insert:
			if e.B != j {
				t.Fatalf("bad insert edit %+v at j=%d", e, j)
			}
			gotB = append(gotB, b[j])
			j++
			changes++
		}
	}
	if i != len(a) || j != len(b) {
		t.Fatalf("script did not consume inputs: i=%d/%d j=%d/%d", i, len(a), j, len(b))
	}
	if strings.Join(gotB, "") != strings.Join(b, "") {
		t.Fatalf("script does not produce b")
	}
	if want := len(a) + len(b) - 2*lcsLen(a, b); changes != want {
		t.Fatalf("non-minimal script: %d changes, want %d\na=%q\nb=%q", changes, want, a, b)
	}
}

func randLines(r *rand.Rand, n, alphabet int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = string(rune('a'+r.Intn(alphabet))) + "\n"
	}
	return out
}

func TestLinesMinimalRandomized(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for iter := 0; iter < 20000; iter++ {
		alphabet := 1 + r.Intn(5)
		a := randLines(r, r.Intn(14), alphabet)
		b := randLines(r, r.Intn(14), alphabet)
		checkScript(t, a, b, Lines(a, b))
	}
}

func TestLinesMinimalLargerInputs(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for iter := 0; iter < 300; iter++ {
		a := randLines(r, r.Intn(200), 2+r.Intn(20))
		// b is a mutation of a so there are long common runs.
		b := append([]string(nil), a...)
		for k := r.Intn(15); k > 0; k-- {
			if len(b) > 0 && r.Intn(2) == 0 {
				p := r.Intn(len(b))
				b = append(b[:p], b[p+1:]...)
			} else {
				p := r.Intn(len(b) + 1)
				b = append(b[:p], append([]string{"new" + strconv.Itoa(k) + "\n"}, b[p:]...)...)
			}
		}
		checkScript(t, a, b, Lines(a, b))
	}
}

func TestLinesEdgeCases(t *testing.T) {
	cases := [][2][]string{
		{nil, nil},
		{nil, {"a\n"}},
		{{"a\n"}, nil},
		{{"a\n"}, {"a\n"}},
		{{"a\n"}, {"b\n"}},
		{{"a\n", "b\n", "c\n"}, {"c\n", "b\n", "a\n"}},
		{{"x\n", "x\n", "x\n"}, {"x\n"}},
	}
	for _, c := range cases {
		checkScript(t, c[0], c[1], Lines(c[0], c[1]))
	}
}

func TestUnifiedGolden(t *testing.T) {
	oldText := "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\n"
	newText := "line1\nline2\nline3\nLINE4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\n"
	want := `--- a/etc/app.conf
+++ b/etc/app.conf
@@ -1,7 +1,7 @@
 line1
 line2
 line3
-line4
+LINE4
 line5
 line6
 line7
@@ -10,3 +10,4 @@
 line10
 line11
 line12
+line13
`
	if got := Unified("a/etc/app.conf", "b/etc/app.conf", oldText, newText, DefaultContext); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestUnifiedMergesNearbyHunks(t *testing.T) {
	oldText := "1\n2\n3\n4\n5\n6\n7\n8\n"
	newText := "1\nX\n3\n4\n5\n6\nY\n8\n"
	got := Unified("a", "b", oldText, newText, 3)
	if n := strings.Count(got, "@@ -"); n != 1 {
		t.Fatalf("expected 1 merged hunk, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "@@ -1,8 +1,8 @@\n") {
		t.Fatalf("unexpected header:\n%s", got)
	}
}

func TestUnifiedIdentical(t *testing.T) {
	if got := Unified("a", "b", "same\n", "same\n", 3); got != "" {
		t.Fatalf("expected empty diff, got %q", got)
	}
}

func TestUnifiedCreateAndDelete(t *testing.T) {
	if got, want := Unified("/dev/null", "b/f", "", "x\ny\n", 3), "--- /dev/null\n+++ b/f\n@@ -0,0 +1,2 @@\n+x\n+y\n"; got != want {
		t.Fatalf("create:\n got %q\nwant %q", got, want)
	}
	if got, want := Unified("a/f", "/dev/null", "x\n", "", 3), "--- a/f\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"; got != want {
		t.Fatalf("delete:\n got %q\nwant %q", got, want)
	}
}

func TestUnifiedNoTrailingNewline(t *testing.T) {
	got := Unified("a", "b", "a\nb", "a\nb\n", 3)
	want := "--- a\n+++ b\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestUnifiedZeroContext(t *testing.T) {
	got := Unified("a", "b", "1\n2\n3\n", "1\nX\n3\n", 0)
	want := "--- a\n+++ b\n@@ -2 +2 @@\n-2\n+X\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// applyUnified is a minimal patch(1) used to check that generated diffs
// round-trip.
func applyUnified(t *testing.T, oldText, patch string) string {
	t.Helper()
	src := SplitLines(oldText)
	var out []string
	pos := 0
	var prev byte
	lines := strings.Split(patch, "\n")
	for i := 2; i < len(lines); i++ {
		l := lines[i]
		if l == `\ No newline at end of file` && prev == '-' {
			continue // applies to a removed line
		}
		if l != "" {
			prev = l[0]
		}
		switch {
		case strings.HasPrefix(l, "@@ -"):
			var start int
			fmt.Sscanf(l, "@@ -%d", &start)
			if strings.HasPrefix(l, fmt.Sprintf("@@ -%d,0 ", start)) {
				start++ // empty range points at the line before
			}
			for ; pos < start-1; pos++ {
				out = append(out, src[pos])
			}
		case l == `\ No newline at end of file`:
			out[len(out)-1] = strings.TrimSuffix(out[len(out)-1], "\n")
		case strings.HasPrefix(l, " "), strings.HasPrefix(l, "-"):
			if src[pos] != l[1:]+"\n" && src[pos] != l[1:] {
				t.Fatalf("context mismatch at old line %d: %q vs %q", pos+1, src[pos], l[1:])
			}
			if l[0] == ' ' {
				out = append(out, l[1:]+"\n")
			}
			pos++
		case strings.HasPrefix(l, "+"):
			out = append(out, l[1:]+"\n")
		}
	}
	out = append(out, src[pos:]...)
	return strings.Join(out, "")
}

func TestUnifiedRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for iter := 0; iter < 2000; iter++ {
		a := randLines(r, r.Intn(40), 4)
		b := randLines(r, r.Intn(40), 4)
		oldText, newText := strings.Join(a, ""), strings.Join(b, "")
		patch := Unified("a", "b", oldText, newText, r.Intn(4))
		if oldText == newText {
			continue
		}
		if got := applyUnified(t, oldText, patch); got != newText {
			t.Fatalf("round trip failed\nold=%q\nnew=%q\npatch:\n%s\ngot=%q", oldText, newText, patch, got)
		}
	}
}

func TestLinesLargeFullyDifferentInput(t *testing.T) {
	// Worst case for Myers (D = N+M); must stay fast and linear in memory.
	a := make([]string, 20000)
	b := make([]string, 20000)
	for i := range a {
		a[i] = "old" + strconv.Itoa(i) + "\n"
		b[i] = "new" + strconv.Itoa(i) + "\n"
	}
	edits := Lines(a, b)
	if len(edits) != 40000 {
		t.Fatalf("expected 40000 edits, got %d", len(edits))
	}
}

func TestLinesLargeReversedInput(t *testing.T) {
	// All lines are shared but the LCS is 1, so Myers itself does the work.
	const n = 3000
	a := make([]string, n)
	b := make([]string, n)
	for i := range a {
		a[i] = strconv.Itoa(i) + "\n"
		b[n-1-i] = a[i]
	}
	changes := 0
	for _, e := range Lines(a, b) {
		if e.Kind != Equal {
			changes++
		}
	}
	if changes != 2*n-2 {
		t.Fatalf("expected %d changes, got %d", 2*n-2, changes)
	}
}

func TestZstdRoundTrip(t *testing.T) {
	for _, in := range []string{"", "x", strings.Repeat("password = [REDACTED:sha256:0123abcd]\n", 5000)} {
		c, err := CompressString(in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := DecompressString(c)
		if err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Fatalf("round trip mismatch for %d-byte input", len(in))
		}
		if len(in) > 1000 && len(c) >= len(in)/10 {
			t.Errorf("poor compression: %d -> %d", len(in), len(c))
		}
	}
}

func TestZstdRejectsGarbage(t *testing.T) {
	if _, err := Decompress([]byte("definitely not zstd")); err == nil {
		t.Fatal("expected error for invalid input")
	}
}

func TestZstdRejectsOversizedOutput(t *testing.T) {
	c, err := Compress(bytes.Repeat([]byte{0}, MaxDecompressedSize+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decompress(c); err == nil {
		t.Fatal("expected decompression bomb to be rejected")
	}
}

func BenchmarkUnified(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&sb, "setting_%d = value_%d\n", i, i)
	}
	oldText := sb.String()
	newText := strings.Replace(oldText, "setting_1000 = value_1000", "setting_1000 = changed", 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Unified("a", "b", oldText, newText, DefaultContext)
	}
}
