package transport

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/statetrack/statetrack/agent/internal/spool"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// fakeSender records batches and returns scripted responses.
type fakeSender struct {
	mu       sync.Mutex
	requests []*pb.IngestBatchRequest
	resp     *pb.IngestBatchResponse
	err      error
	calls    int
}

func (f *fakeSender) IngestBatch(_ context.Context, req *pb.IngestBatchRequest, _ ...grpc.CallOption) (*pb.IngestBatchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.requests = append(f.requests, req)
	if f.err != nil {
		return nil, f.err
	}
	if f.resp == nil {
		f.resp = &pb.IngestBatchResponse{}
	}
	return f.resp, nil
}

func (f *fakeSender) last() *pb.IngestBatchRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return nil
	}
	return f.requests[len(f.requests)-1]
}

func newTestSpool(t *testing.T) *spool.Spool {
	t.Helper()
	s, err := spool.Open(context.Background(), filepath.Join(t.TempDir(), "spool.db"),
		spool.Options{MaxBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func events(ids ...string) []*pb.MutationEvent {
	out := make([]*pb.MutationEvent, len(ids))
	for i, id := range ids {
		out[i] = &pb.MutationEvent{
			EventId: id,
			Level:   pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Target:  &pb.TargetResource{TargetType: "file", PathOrKey: "/etc/x"},
		}
	}
	return out
}

func TestSendBatchAndAck(t *testing.T) {
	s := newTestSpool(t)
	if err := s.Append(context.Background(), events("a", "b", "c")...); err != nil {
		t.Fatal(err)
	}
	fake := &fakeSender{resp: &pb.IngestBatchResponse{
		AckEventIds:         []string{"a", "b", "c"},
		ServerTimeMs:        1234,
		ForensicModeUntilMs: 0,
	}}
	f := &Flusher{opts: Options{
		Spool: s, HostID: "host-1", Hostname: "web-01",
		OSFamily: "linux", OSVersion: "1.0", AgentVersion: "v1",
	}, sender: fake}

	if err := f.send(context.Background(), events("a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	req := fake.last()
	if req == nil {
		t.Fatal("no request sent")
	}
	if req.HostId != "host-1" || req.Hostname != "web-01" || req.OsFamily != "linux" ||
		req.OsVersion != "1.0" || req.AgentVersion != "v1" {
		t.Fatalf("host metadata = %+v", req)
	}
	if len(req.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(req.Events))
	}
	if req.AgentSentMs == 0 {
		t.Fatal("agent_sent_ms not set")
	}
	// All acked: spool is empty.
	left, err := s.ReadBatch(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("spool still has %d events after ack", len(left))
	}
}

func TestSendEmptyAckTreatsBatchDelivered(t *testing.T) {
	s := newTestSpool(t)
	if err := s.Append(context.Background(), events("a")...); err != nil {
		t.Fatal(err)
	}
	f := &Flusher{opts: Options{Spool: s}, sender: &fakeSender{resp: &pb.IngestBatchResponse{}}}
	if err := f.send(context.Background(), events("a")); err != nil {
		t.Fatal(err)
	}
	left, _ := s.ReadBatch(context.Background(), 10, 0)
	if len(left) != 0 {
		t.Fatalf("spool still has %d events", len(left))
	}
}

func TestSendErrorLeavesEventsSpooled(t *testing.T) {
	s := newTestSpool(t)
	if err := s.Append(context.Background(), events("a")...); err != nil {
		t.Fatal(err)
	}
	f := &Flusher{opts: Options{Spool: s}, sender: &fakeSender{err: errors.New("down")}}
	if err := f.send(context.Background(), events("a")); err == nil {
		t.Fatal("expected error")
	}
	left, _ := s.ReadBatch(context.Background(), 10, 0)
	if len(left) != 1 {
		t.Fatalf("spool should retain the event, got %d", len(left))
	}
}

func TestForensicActivation(t *testing.T) {
	s := newTestSpool(t)
	if err := s.Append(context.Background(), events("a")...); err != nil {
		t.Fatal(err)
	}
	var got time.Time
	f := &Flusher{
		opts: Options{Spool: s, OnForensic: func(u time.Time) { got = u }},
		sender: &fakeSender{resp: &pb.IngestBatchResponse{
			AckEventIds:         []string{"a"},
			ForensicModeUntilMs: 1_700_000_000_000,
		}},
	}
	if err := f.send(context.Background(), events("a")); err != nil {
		t.Fatal(err)
	}
	if want := time.UnixMilli(1_700_000_000_000); !got.Equal(want) {
		t.Fatalf("forensic until = %v, want %v", got, want)
	}
}

func TestRunDrainsSpool(t *testing.T) {
	s := newTestSpool(t)
	if err := s.Append(context.Background(), events("a", "b")...); err != nil {
		t.Fatal(err)
	}
	fake := &fakeSender{resp: &pb.IngestBatchResponse{AckEventIds: []string{"a", "b"}}}
	f := &Flusher{opts: Options{Spool: s, PollInterval: 5 * time.Millisecond}, sender: fake}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go f.Run(ctx)
	// Wait until the spool drains.
	deadline := time.Now().Add(2 * time.Second)
	for {
		left, _ := s.ReadBatch(context.Background(), 10, 0)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spool did not drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDisabledTransport(t *testing.T) {
	f, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if f.sender != nil {
		t.Fatal("expected nil sender when no address configured")
	}
	// Run should return immediately on context cancel, not block forever.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	f.Run(ctx)
}

func TestLoadTLSErrors(t *testing.T) {
	if _, err := loadTLS(Options{CAFile: "/does/not/exist.pem"}); err == nil {
		t.Fatal("expected error for missing CA")
	}
	if _, err := loadTLS(Options{CertFile: "cert.pem"}); err == nil {
		t.Fatal("expected error for cert without key")
	}
}
