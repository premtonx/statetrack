package spool

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

const (
	L1 = pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL
	L2 = pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED
	L3 = pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT
	L4 = pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC
)

func ev(id string, level pb.ImpactLevel, payload int) *pb.MutationEvent {
	return &pb.MutationEvent{EventId: id, Level: level, Summary: strings.Repeat("x", payload),
		Target: &pb.TargetResource{TargetType: "file", PathOrKey: "/etc/" + id}}
}

func open(t *testing.T, path string, opts Options) *Spool {
	t.Helper()
	s, err := Open(context.Background(), path, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func ids(evs []*pb.MutationEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.EventId
	}
	return out
}

func TestAppendReadAck(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "spool.db"), Options{})
	in := []*pb.MutationEvent{ev("a", L1, 10), ev("b", L3, 10), ev("c", L2, 10)}
	in[0].UnifiedDiffZstd = []byte{0x28, 0xb5, 0x2f, 0xfd}
	in[0].Metadata = map[string]string{"k": "v"}
	if err := s.Append(ctx, in...); err != nil {
		t.Fatal(err)
	}

	got, err := s.ReadBatch(ctx, 10, 0)
	if err != nil || strings.Join(ids(got), ",") != "a,b,c" {
		t.Fatalf("ReadBatch = %v, %v", ids(got), err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].MonotonicSeq <= got[i-1].MonotonicSeq {
			t.Fatal("MonotonicSeq not increasing")
		}
	}
	want := proto.Clone(in[0]).(*pb.MutationEvent)
	want.MonotonicSeq = got[0].MonotonicSeq
	if !proto.Equal(got[0], want) {
		t.Fatalf("round trip mismatch:\n got %v\nwant %v", got[0], want)
	}

	// At-least-once: unacked events are returned again.
	again, _ := s.ReadBatch(ctx, 10, 0)
	if len(again) != 3 {
		t.Fatalf("unacked events not redelivered: %v", ids(again))
	}
	if n, err := s.Ack(ctx, []string{"a", "c", "unknown"}); err != nil || n != 2 {
		t.Fatalf("Ack = %d, %v", n, err)
	}
	rest, _ := s.ReadBatch(ctx, 10, 0)
	if strings.Join(ids(rest), ",") != "b" {
		t.Fatalf("after ack: %v", ids(rest))
	}
	st, _ := s.Stats(ctx)
	if st.Events != 1 || st.MaxBytes != DefaultMaxBytes {
		t.Fatalf("stats %+v", st)
	}
}

func TestReadBatchLimits(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "spool.db"), Options{})
	for i := 0; i < 10; i++ {
		s.Append(ctx, ev(fmt.Sprintf("e%02d", i), L3, 100))
	}
	if got, _ := s.ReadBatch(ctx, 4, 0); len(got) != 4 || got[0].EventId != "e00" {
		t.Fatalf("maxEvents: %v", ids(got))
	}
	// Each payload is ~120 bytes: 300 bytes allows two.
	if got, _ := s.ReadBatch(ctx, 100, 300); len(got) != 2 {
		t.Fatalf("maxBytes: %v", ids(got))
	}
	// An event bigger than maxBytes is still delivered alone.
	if got, _ := s.ReadBatch(ctx, 100, 1); len(got) != 1 {
		t.Fatalf("oversized first event: %v", ids(got))
	}
}

func TestDuplicateIDsIgnored(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "spool.db"), Options{})
	s.Append(ctx, ev("a", L1, 10))
	before, _ := s.Stats(ctx)
	if err := s.Append(ctx, ev("a", L1, 10), ev("b", L1, 10)); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Stats(ctx)
	if after.Events != 2 || after.Bytes-before.Bytes != before.Bytes {
		t.Fatalf("dedupe accounting: before %+v after %+v", before, after)
	}
	if err := s.Append(ctx, &pb.MutationEvent{}); err == nil {
		t.Fatal("event without ID accepted")
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "spool.db")
	s, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Append(ctx, ev("a", L1, 50), ev("b", L3, 50))
	st1, _ := s.Stats(ctx)
	s.Close()

	s2 := open(t, path, Options{})
	st2, _ := s2.Stats(ctx)
	if st2.Events != 2 || st2.Bytes != st1.Bytes {
		t.Fatalf("after reopen %+v, before %+v", st2, st1)
	}
	got, _ := s2.ReadBatch(ctx, 10, 0)
	if strings.Join(ids(got), ",") != "a,b" {
		t.Fatalf("events lost: %v", ids(got))
	}
	// New events continue the sequence.
	s2.Append(ctx, ev("c", L1, 1))
	got, _ = s2.ReadBatch(ctx, 10, 0)
	if got[2].MonotonicSeq <= got[1].MonotonicSeq {
		t.Fatal("sequence restarted after reopen")
	}
}

func TestEvictsLevel3FirstThenByPriority(t *testing.T) {
	ctx := context.Background()
	one := int64(proto.Size(ev("x00", L1, 200))) + RowOverhead
	// Room for exactly 10 events.
	s := open(t, filepath.Join(t.TempDir(), "spool.db"), Options{MaxBytes: 10 * one})

	// Interleave levels: L1 x3, L2 x2, L3 x4, L4 x1 (10 events, full).
	levels := []pb.ImpactLevel{L3, L1, L3, L2, L4, L3, L1, L2, L3, L1}
	for i, lvl := range levels {
		if err := s.Append(ctx, ev(fmt.Sprintf("x%02d", i), lvl, 200)); err != nil {
			t.Fatal(err)
		}
	}
	// 5 more critical events evict the 4 L3 (oldest first) and then the L4.
	for i := 10; i < 15; i++ {
		if err := s.Append(ctx, ev(fmt.Sprintf("x%02d", i), L1, 200)); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.ReadBatch(ctx, 100, 0)
	want := "x01,x03,x06,x07,x09,x10,x11,x12,x13,x14"
	if strings.Join(ids(got), ",") != want {
		t.Fatalf("after eviction:\n got %s\nwant %s", strings.Join(ids(got), ","), want)
	}
	// Then L2, then the oldest L1.
	s.Append(ctx, ev("x15", L1, 200), ev("x16", L1, 200), ev("x17", L1, 200))
	got, _ = s.ReadBatch(ctx, 100, 0)
	want = "x06,x09,x10,x11,x12,x13,x14,x15,x16,x17"
	if strings.Join(ids(got), ",") != want {
		t.Fatalf("after second eviction:\n got %s\nwant %s", strings.Join(ids(got), ","), want)
	}
	st, _ := s.Stats(ctx)
	if st.Evicted[L3] != 4 || st.Evicted[L4] != 1 || st.Evicted[L2] != 2 || st.Evicted[L1] != 1 || st.Bytes > st.MaxBytes {
		t.Fatalf("stats %+v", st)
	}
}

func TestRejectsEventLargerThanSpool(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "spool.db"), Options{MaxBytes: 1024})
	if err := s.Append(context.Background(), ev("big", L1, 2048)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestCeilingInvariantUnderRandomLoad(t *testing.T) {
	ctx := context.Background()
	const max = 64 << 10
	s := open(t, filepath.Join(t.TempDir(), "spool.db"), Options{MaxBytes: max})
	r := rand.New(rand.NewSource(7))
	levels := []pb.ImpactLevel{L1, L2, L3, L4}
	n := 0
	for i := 0; i < 300; i++ {
		var batch []*pb.MutationEvent
		for j := r.Intn(8); j >= 0; j-- {
			batch = append(batch, ev(fmt.Sprintf("r%d", n), levels[r.Intn(4)], r.Intn(2000)))
			n++
		}
		if err := s.Append(ctx, batch...); err != nil {
			t.Fatal(err)
		}
		if r.Intn(5) == 0 {
			got, _ := s.ReadBatch(ctx, r.Intn(20)+1, 0)
			s.Ack(ctx, ids(got))
		}
		st, _ := s.Stats(ctx)
		if st.Bytes > max {
			t.Fatalf("iteration %d: %d bytes exceeds ceiling %d", i, st.Bytes, max)
		}
	}
	// Accounting must match the database exactly.
	var actual int64
	s.db.QueryRow(`SELECT COALESCE(SUM(size),0) + COUNT(*)*? FROM events`, RowOverhead).Scan(&actual)
	if st, _ := s.Stats(ctx); st.Bytes != actual {
		t.Fatalf("accounted %d bytes, database has %d", st.Bytes, actual)
	}
}

func TestOnDiskSizeStaysBounded(t *testing.T) {
	ctx := context.Background()
	const max = 1 << 20
	path := filepath.Join(t.TempDir(), "spool.db")
	s := open(t, path, Options{MaxBytes: max})
	// Write 10x the ceiling.
	for i := 0; i < 200; i++ {
		var batch []*pb.MutationEvent
		for j := 0; j < 50; j++ {
			batch = append(batch, ev(fmt.Sprintf("d%d-%d", i, j), L3, 1000))
		}
		if err := s.Append(ctx, batch...); err != nil {
			t.Fatal(err)
		}
	}
	// Freed pages are reused, so the file never grows past the ceiling plus
	// the fixed schema pages, even before compaction.
	if err := s.Compact(ctx); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > max+s.schemaBytes {
		t.Fatalf("spool.db is %d bytes for a %d byte ceiling (+%d schema)", fi.Size(), max, s.schemaBytes)
	}
	if st, _ := s.Stats(ctx); st.Evicted[L3] == 0 || st.Events == 0 {
		t.Fatalf("expected a full spool with evictions: %+v", st)
	}
	t.Logf("spool.db %d KiB after writing %d KiB (ceiling %d KiB)", fi.Size()>>10, (200*50*1100)>>10, max>>10)
}

func TestConcurrentProducersAndFlusher(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "spool.db"), Options{})
	const producers, perProducer = 4, 250
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				if err := s.Append(ctx, ev(fmt.Sprintf("p%d-%d", p, i), L1, 50)); err != nil {
					t.Error(err)
					return
				}
			}
		}(p)
	}
	seen := make(map[string]bool)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for finished := false; ; {
		select {
		case <-done:
			finished = true
		default:
		}
		batch, err := s.ReadBatch(ctx, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range batch {
			seen[e.EventId] = true
		}
		if _, err := s.Ack(ctx, ids(batch)); err != nil {
			t.Fatal(err)
		}
		if finished && len(batch) == 0 {
			break
		}
	}
	if len(seen) != producers*perProducer {
		t.Fatalf("delivered %d distinct events, want %d", len(seen), producers*perProducer)
	}
	if st, _ := s.Stats(ctx); st.Events != 0 || st.Bytes != 0 {
		t.Fatalf("spool not drained: %+v", st)
	}
}
