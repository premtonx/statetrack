// Package transport delivers spooled events to the StateTrack central
// server over gRPC. It performs clock sync, activates remote forensic mode,
// and retries with exponential backoff while the server is unreachable so
// the durable spool keeps the events safe.
//
// Delivery is at-least-once: events stay spooled until the server
// acknowledges them.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/statetrack/statetrack/agent/internal/spool"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

const (
	// DefaultBatchSize is the number of events per IngestBatch (spec: ~100).
	DefaultBatchSize = 100
	// DefaultMaxBatchBytes bounds a batch's serialized payload.
	DefaultMaxBatchBytes = 2 << 20
	// DefaultPollInterval is how often the flusher checks the spool when empty.
	DefaultPollInterval = 500 * time.Millisecond
	// DefaultDialTimeout bounds establishing the gRPC connection.
	DefaultDialTimeout = 5 * time.Second
	// DefaultRetryBase is the initial backoff after a failed send.
	DefaultRetryBase = 1 * time.Second
	// DefaultRetryMax caps the exponential backoff.
	DefaultRetryMax = 30 * time.Second
	// DefaultHeartbeatInterval paces idle heartbeats (no spooled events),
	// which carry discovery results and fetch policy rules.
	DefaultHeartbeatInterval = 15 * time.Second
)

// Sender sends one batch of events. pb.IngestionServiceClient satisfies it.
type Sender interface {
	IngestBatch(ctx context.Context, req *pb.IngestBatchRequest, opts ...grpc.CallOption) (*pb.IngestBatchResponse, error)
}

// Options configures a Flusher.
type Options struct {
	Spool        *spool.Spool
	HostID       string
	Hostname     string
	OSFamily     string
	OSVersion    string
	AgentVersion string

	// Address is the server target (host:port). Empty disables delivery
	// (the agent runs spool-only); New returns a no-op Flusher.
	Address string
	// CAFile/CertFile/KeyFile enable mTLS when set.
	CAFile, CertFile, KeyFile string

	BatchSize     int
	MaxBatchBytes int
	PollInterval  time.Duration
	DialTimeout   time.Duration
	RetryBase     time.Duration
	RetryMax      time.Duration

	// HeartbeatInterval is how often an empty batch is sent while the spool is
	// idle, carrying auto-discovered workloads and fetching policy rules
	// (default DefaultHeartbeatInterval).
	HeartbeatInterval time.Duration

	Logger *slog.Logger
	// OnForensic is invoked when the server activates Level 4 collection.
	OnForensic func(until time.Time)
	// Workloads, when set, supplies the auto-discovered workloads attached to
	// every batch (including idle heartbeats).
	Workloads func() []*pb.DiscoveredWorkload
	// OnPolicyRules is invoked with the host's active policy rules on every
	// acknowledgement.
	OnPolicyRules func([]*pb.PolicyRule)

	// Dialer overrides the default gRPC dialing (tests). It must return a
	// Sender and an optional closer.
	Dialer func(ctx context.Context, o Options) (Sender, io.Closer, error)
}

// Flusher drains a spool to the server.
type Flusher struct {
	opts   Options
	sender Sender
	close  io.Closer
	// lastHeartbeat is the time of the last successful send (events or
	// heartbeat), used to pace idle heartbeats.
	lastHeartbeat time.Time
}

// New builds a Flusher. It dials the server eagerly so connection errors
// surface at startup; a nil error means delivery can proceed.
func New(opts Options) (*Flusher, error) {
	opts = withDefaults(opts)
	f := &Flusher{opts: opts}
	if opts.Address == "" {
		return f, nil
	}
	if opts.Dialer != nil {
		s, c, err := opts.Dialer(context.Background(), opts)
		if err != nil {
			return nil, err
		}
		f.sender, f.close = s, c
		return f, nil
	}
	s, c, err := dialGRPC(context.Background(), opts)
	if err != nil {
		return nil, err
	}
	f.sender, f.close = s, c
	return f, nil
}

func withDefaults(o Options) Options {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.MaxBatchBytes <= 0 {
		o.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.RetryBase <= 0 {
		o.RetryBase = DefaultRetryBase
	}
	if o.RetryMax <= 0 {
		o.RetryMax = DefaultRetryMax
	}
	if o.HeartbeatInterval <= 0 {
		o.HeartbeatInterval = DefaultHeartbeatInterval
	}
	return o
}

// Close releases the connection.
func (f *Flusher) Close() error {
	if f.close != nil {
		return f.close.Close()
	}
	return nil
}

func (f *Flusher) logger() *slog.Logger {
	if f.opts.Logger != nil {
		return f.opts.Logger
	}
	return slog.Default()
}

// Run drains the spool until ctx is cancelled.
func (f *Flusher) Run(ctx context.Context) {
	if f.sender == nil {
		f.logger().Debug("transport disabled: no server address")
		<-ctx.Done()
		return
	}
	backoff := f.opts.RetryBase
	f.lastHeartbeat = time.Now()
	for {
		if ctx.Err() != nil {
			return
		}
		events, err := f.opts.Spool.ReadBatch(ctx, f.opts.BatchSize, f.opts.MaxBatchBytes)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			f.logger().Warn("spool read failed", "err", err)
			if !sleep(ctx, backoff) {
				return
			}
			continue
		}
		if len(events) == 0 {
			// Idle: send a heartbeat (empty batch + discovered workloads) at
			// the heartbeat interval so the server learns about new workloads
			// and can push policy rules without waiting for a mutation.
			if time.Since(f.lastHeartbeat) >= f.opts.HeartbeatInterval {
				if err := f.send(ctx, nil); err != nil {
					f.logger().Warn("heartbeat failed; will retry", "err", err)
					if !sleep(ctx, backoff) {
						return
					}
					backoff = min(backoff*2, f.opts.RetryMax)
					continue
				}
				backoff = f.opts.RetryBase
				f.lastHeartbeat = time.Now()
			}
			if !sleep(ctx, f.opts.PollInterval) {
				return
			}
			continue
		}
		if err := f.send(ctx, events); err != nil {
			f.logger().Warn("ingest failed; will retry", "events", len(events), "err", err)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, f.opts.RetryMax)
			continue
		}
		backoff = f.opts.RetryBase
		f.lastHeartbeat = time.Now()
	}
}

// send delivers one batch (events may be nil for a heartbeat) and handles
// acks, forensic activation and policy-rule updates.
func (f *Flusher) send(ctx context.Context, events []*pb.MutationEvent) error {
	req := &pb.IngestBatchRequest{
		HostId:       f.opts.HostID,
		AgentSentMs:  time.Now().UnixMilli(),
		Events:       events,
		Hostname:     f.opts.Hostname,
		OsFamily:     f.opts.OSFamily,
		OsVersion:    f.opts.OSVersion,
		AgentVersion: f.opts.AgentVersion,
	}
	if f.opts.Workloads != nil {
		req.Workloads = f.opts.Workloads()
	}
	resp, err := f.sender.IngestBatch(ctx, req)
	if err != nil {
		return err
	}

	ids := resp.GetAckEventIds()
	if len(ids) == 0 && len(events) > 0 {
		// Server did not acknowledge explicitly; treat the whole batch as
		// delivered to avoid an infinite resend loop.
		ids = make([]string, 0, len(events))
		for _, ev := range events {
			ids = append(ids, ev.GetEventId())
		}
	}
	if len(ids) > 0 {
		if n, err := f.opts.Spool.Ack(ctx, ids); err != nil {
			f.logger().Warn("ack failed", "err", err)
		} else if n > 0 {
			f.logger().Debug("acked", "events", n)
		}
	}

	if resp.GetForensicModeUntilMs() > 0 && f.opts.OnForensic != nil {
		f.opts.OnForensic(time.UnixMilli(resp.GetForensicModeUntilMs()))
	}
	if f.opts.OnPolicyRules != nil {
		f.opts.OnPolicyRules(resp.GetPolicyRules())
	}
	return nil
}

// Flush attempts one drain cycle and returns when the spool is empty or a
// send fails. It is used for a final delivery on shutdown.
func (f *Flusher) Flush(ctx context.Context) error {
	if f.sender == nil {
		return nil
	}
	for {
		events, err := f.opts.Spool.ReadBatch(ctx, f.opts.BatchSize, f.opts.MaxBatchBytes)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		if err := f.send(ctx, events); err != nil {
			return err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func dialGRPC(ctx context.Context, o Options) (Sender, io.Closer, error) {
	var creds credentials.TransportCredentials
	if o.CAFile != "" || o.CertFile != "" {
		tlsCfg, err := loadTLS(o)
		if err != nil {
			return nil, nil, err
		}
		creds = credentials.NewTLS(tlsCfg)
	} else {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(o.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("transport: dial %s: %w", o.Address, err)
	}
	return pb.NewIngestionServiceClient(conn), conn, nil
}

// loadTLS builds a mutual-TLS configuration from CA/cert/key PEM files.
func loadTLS(o Options) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("transport: read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("transport: no certificates in ca file")
		}
		cfg.RootCAs = pool
	}
	if o.CertFile != "" || o.KeyFile != "" {
		if o.CertFile == "" || o.KeyFile == "" {
			return nil, errors.New("transport: cert_file and key_file must both be set")
		}
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("transport: load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
