// Package grpc implements the agent ingestion service (statetrack.v1).
package grpc

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/metrics"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// Server implements IngestionService.
type Server struct {
	pb.UnimplementedIngestionServiceServer

	Store *storage.Store
	// OrgID is the organization all ingested data belongs to.
	OrgID string
	// Now supplies the server clock (injectable for tests).
	Now func() time.Time

	// Publish broadcasts a normalized event to live subscribers (websocket).
	Publish func(storage.Notification)
	// Enqueue hands a notification to the annotation/webhook worker.
	Enqueue func(storage.Notification)

	// Metrics records ingest SLIs and fleet mutation counters. Optional.
	Metrics *metrics.Registry

	Logger *slog.Logger
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// IngestBatch ingests a batch of events, de-skewing their timestamps by the
// measured clock offset, and returns acknowledgements plus any forensic-mode
// activation requested for this host.
func (s *Server) IngestBatch(ctx context.Context, req *pb.IngestBatchRequest) (*pb.IngestBatchResponse, error) {
	if req.GetHostId() == "" {
		return nil, status.Error(codes.InvalidArgument, "host_id is required")
	}

	now := s.now()
	serverTimeMs := now.UnixMilli()
	clockOffset := serverTimeMs - req.GetAgentSentMs()

	host, err := s.Store.UpsertHost(ctx, storage.Host{
		ID:            req.GetHostId(),
		OrgID:         s.OrgID,
		Hostname:      req.GetHostname(),
		OSFamily:      req.GetOsFamily(),
		OSVersion:     req.GetOsVersion(),
		AgentVersion:  req.GetAgentVersion(),
		ClockOffsetMS: clockOffset,
	})
	if err != nil {
		s.logger().Error("ingest: upsert host", "err", err)
		return nil, status.Errorf(codes.Internal, "host upsert: %v", err)
	}

	ack, notifs, err := s.Store.InsertEvents(ctx, s.OrgID, host.ID, clockOffset, req.GetEvents())
	if err != nil {
		s.logger().Error("ingest: insert events", "host", host.Hostname, "err", err)
		return nil, status.Errorf(codes.Internal, "insert events: %v", err)
	}

	// Ingest SLIs. The timer wraps only the durable write, not the host upsert
	// or the downstream fan-out, so it tracks storage latency specifically.
	if s.Metrics != nil {
		s.Metrics.RecordBatchIngest(time.Since(now).Seconds(), len(req.GetEvents()))
		// Mutation counters are recorded for root events only, matching the
		// dashboard KPIs: one aggregated package transaction carries hundreds
		// of children, and counting those would report one upgrade as hundreds
		// of mutations. Storm throttles get their own counter so an operator
		// can alert on circuit-breaker activity without parsing summaries.
		for _, n := range notifs {
			if n.ParentEventID != "" {
				continue
			}
			s.Metrics.RecordMutation(host.Hostname, int32(n.ImpactLevel), int32(n.Category), int32(n.Action))
			if n.Action == pb.Action_ACTION_THROTTLED {
				s.Metrics.RecordStormThrottle(host.Hostname, 1)
			}
		}
		// Drift inventory: a batch can add or delete tracked targets, so refresh
		// the host's gauge rather than trying to derive the delta from events.
		if count, err := s.Store.HostTargetCount(ctx, host.ID); err == nil {
			s.Metrics.SetDriftTargets(host.Hostname, count)
		}
	}

	// Auto-discovered workloads ride along with every batch (including the
	// idle heartbeats the agent sends) and are upserted as recommendations.
	if len(req.GetWorkloads()) > 0 {
		if err := s.Store.UpsertRecommendations(ctx, s.OrgID, host.ID, req.GetWorkloads()); err != nil {
			// Discovery is best-effort: never fail an event batch over it.
			s.logger().Warn("ingest: upsert recommendations", "host", host.Hostname, "err", err)
		}
	}

	for _, n := range notifs {
		if s.Publish != nil {
			s.Publish(n)
		}
		if s.Enqueue != nil {
			s.Enqueue(n)
		}
	}

	// The host's active policy rules are pushed on every ack so an accepted
	// recommendation takes effect on the next heartbeat/batch.
	rules, err := s.Store.PolicyRulesForHost(ctx, s.OrgID, host.ID)
	if err != nil {
		s.logger().Warn("ingest: load policy rules", "host", host.Hostname, "err", err)
	}

	resp := &pb.IngestBatchResponse{
		AckEventIds:  ack,
		ServerTimeMs: serverTimeMs,
		PolicyRules:  rules,
	}
	if host.ForensicUntil != nil && host.ForensicUntil.After(now) {
		resp.ForensicModeUntilMs = host.ForensicUntil.UnixMilli()
	}
	return resp, nil
}
