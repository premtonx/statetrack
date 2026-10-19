// Command statetrack-demo-traffic drives a steady trickle of realistic changes
// through StateTrack's *real* ingest path (the gRPC IngestionService), so the
// Grafana dashboard's rate and increase panels actually move.
//
// # Why this exists
//
// `dev.ps1 seed` writes a realistic timeline straight into Postgres. That is
// enough for the console and for the annotation flags on the hero panel, but it
// is deliberately *not* enough for the metric panels: statetrack_mutations_total
// is a live counter the server increments while it ingests agent batches
// (server/internal/grpc). Seeding bypasses that path, so the exporter reads the
// seeded totals exactly once at startup and then holds them flat — and a flat
// counter makes every rate() and increase() panel read zero. Replaying the
// seeded events is not an option either: the server de-skews each batch into
// server time, so a replayed event would land under "now" as a duplicate row.
//
// This command therefore generates *new* changes and submits them the way an
// agent would. The counters climb, the red L1 bars on the hero panel grow, the
// "Critical changes" stat leaves zero, and the annotations the server pushes for
// live changes land on the same clock as the generated ones.
//
// # Safety
//
// Targets the local ingest endpoint by default and prints a banner naming the
// host it is about to write to. It only ever sends the demo fleet's hostnames
// (which `dev.ps1 seed` already created), never touches existing rows, and
// stops on Ctrl-C. Point -grpc somewhere else only on purpose.
//
// Usage:
//
//	go run ./server/cmd/statetrack-demo-traffic                 # until Ctrl-C
//	go run ./server/cmd/statetrack-demo-traffic -interval 1s    # faster
//	go run ./server/cmd/statetrack-demo-traffic -duration 2m    # bounded
//	go run ./server/cmd/statetrack-demo-traffic -dry-run        # print only
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

func main() { os.Exit(run()) }

type config struct {
	grpcAddr string
	interval time.Duration
	duration time.Duration
	l1Ratio  float64
	burst    int
	dryRun   bool
}

// demoHost is one member of the seeded fleet, with the change shapes that host
// realistically produces. Keeping the fleet in lockstep with statetrack-seed is
// what makes a generated change look like it belongs beside a seeded one.
type demoHost struct {
	hostname  string
	osFamily  string
	osVersion string
	templates []changeTemplate
}

// changeTemplate is one realistic change: the classification the classifier
// would assign, the resource it touches, and a summary/actor pair. The target is
// a pointer because a protobuf message embeds a mutex and must never be copied
// by value (which is exactly what a template literal would do).
type changeTemplate struct {
	level    pb.ImpactLevel
	category pb.Category
	action   pb.Action
	target   *pb.TargetResource
	summary  string
	actor    string
	process  string
	cmdline  string
}

func run() int {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	var cfg config
	flag.StringVar(&cfg.grpcAddr, "grpc", envOr("GRPC_ADDR", "localhost:50051"),
		"StateTrack gRPC ingest endpoint")
	flag.DurationVar(&cfg.interval, "interval", 2*time.Second,
		"delay between generated changes (each tick emits one batch)")
	flag.DurationVar(&cfg.duration, "duration", 0,
		"stop after this long; 0 runs until interrupted")
	flag.Float64Var(&cfg.l1Ratio, "l1-ratio", 0.45,
		"share of generated changes that are Level 1 (critical) — the red hero-panel bars")
	flag.IntVar(&cfg.burst, "burst", 1,
		"changes per tick (a value > 1 exercises the grouped/burst paths)")
	flag.BoolVar(&cfg.dryRun, "dry-run", false,
		"print the generated changes without sending them")
	flag.Parse()

	if cfg.l1Ratio < 0 {
		cfg.l1Ratio = 0
	} else if cfg.l1Ratio > 1 {
		cfg.l1Ratio = 1
	}
	if cfg.burst < 1 {
		cfg.burst = 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.duration)
		defer cancel()
	}

	printBanner(cfg)

	var client pb.IngestionServiceClient
	if !cfg.dryRun {
		conn, err := grpc.NewClient(cfg.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Error("dial ingest endpoint", "addr", cfg.grpcAddr, "err", err)
			return 1
		}
		defer conn.Close()
		client = pb.NewIngestionServiceClient(conn)
	}

	// Seeded from the clock rather than a constant: identical takes would make
	// for a lifeless recording.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	fleet := demoFleet()
	tick := time.NewTicker(cfg.interval)
	defer tick.Stop()

	var sent, l1 int
	for {
		select {
		case <-ctx.Done():
			log.Info("traffic generator stopped", "changes_sent", sent, "l1_sent", l1)
			return 0
		case <-tick.C:
			host := fleet[rng.Intn(len(fleet))]
			events := buildBatch(host, cfg, rng)
			if cfg.dryRun {
				for _, ev := range events {
					log.Info("would send", "host", host.hostname,
						"level", ev.GetLevel().String(), "summary", ev.GetSummary())
				}
				continue
			}
			resp, err := client.IngestBatch(ctx, &pb.IngestBatchRequest{
				HostId:       host.hostname,
				AgentSentMs:  time.Now().UnixMilli(),
				Hostname:     host.hostname,
				OsFamily:     host.osFamily,
				OsVersion:    host.osVersion,
				AgentVersion: "demo-traffic",
				Events:       events,
			})
			if err != nil {
				// One failed batch must not kill a recording; the next tick
				// retries with a fresh event.
				log.Warn("ingest failed", "host", host.hostname, "err", err)
				continue
			}
			sent += len(resp.GetAckEventIds())
			for _, ev := range events {
				if ev.GetLevel() == pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
					l1++
				}
			}
			log.Info("change ingested", "host", host.hostname,
				"acked", len(resp.GetAckEventIds()), "total", sent, "l1", l1)
		}
	}
}

// buildBatch renders one tick's worth of changes for a host.
func buildBatch(host demoHost, cfg config, rng *rand.Rand) []*pb.MutationEvent {
	out := make([]*pb.MutationEvent, 0, cfg.burst)
	for i := 0; i < cfg.burst; i++ {
		tpl := pickTemplate(host, cfg.l1Ratio, rng)
		out = append(out, renderEvent(tpl, rng))
	}
	return out
}

// pickTemplate chooses a change shape, honouring the requested Level 1 share so
// the operator can dial the red-bar density for a recording.
func pickTemplate(host demoHost, l1Ratio float64, rng *rand.Rand) changeTemplate {
	critical := make([]changeTemplate, 0, len(host.templates))
	routine := make([]changeTemplate, 0, len(host.templates))
	for _, t := range host.templates {
		if t.level == pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
			critical = append(critical, t)
		} else {
			routine = append(routine, t)
		}
	}
	if len(critical) == 0 {
		return routine[rng.Intn(len(routine))]
	}
	if len(routine) == 0 {
		return critical[rng.Intn(len(critical))]
	}
	if rng.Float64() < l1Ratio {
		return critical[rng.Intn(len(critical))]
	}
	return routine[rng.Intn(len(routine))]
}

// renderEvent turns a template into a wire event, varying the concrete path and
// the actor so a recording never shows the same row twice.
func renderEvent(tpl changeTemplate, rng *rand.Rand) *pb.MutationEvent {
	suffix := strings.TrimPrefix(uuid.NewString(), "-")[:8]
	pathOrKey := strings.NewReplacer(
		"{n}", fmt.Sprint(rng.Intn(9)+1),
		"{id}", suffix,
	).Replace(tpl.target.GetPathOrKey())

	// A fresh message per event: reusing the template's would share its embedded
	// mutex across goroutines and races once the batch is marshalled.
	target := &pb.TargetResource{
		TargetType: tpl.target.GetTargetType(),
		PathOrKey:  pathOrKey,
		HashAfter:  "sha256:" + suffix,
	}

	return &pb.MutationEvent{
		EventId:          uuid.NewString(),
		AgentTimestampMs: time.Now().UnixMilli(),
		Level:            tpl.level,
		Category:         tpl.category,
		Action:           tpl.action,
		Summary:          tpl.summary + " (" + suffix + ")",
		Actor: &pb.ActorContext{
			Username:    tpl.actor,
			Pid:         uint32(rng.Intn(30000) + 1000),
			ProcessName: tpl.process,
			Cmdline:     tpl.cmdline,
			RemoteIp:    fmt.Sprintf("10.42.%d.%d", rng.Intn(8), rng.Intn(200)+1),
		},
		Target: target,
		Metadata: map[string]string{
			"content":        "text",
			"classification": "demo traffic generator",
			"generated":      "true",
		},
	}
}

// demoFleet mirrors the hosts statetrack-seed creates, so generated changes land
// on the same hosts the console, the drift matrix and the annotations already
// describe.
func demoFleet() []demoHost {
	return []demoHost{
		{
			hostname: "prod-web-01", osFamily: "linux", osVersion: "Ubuntu 24.04",
			templates: []changeTemplate{
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, category: pb.Category_CATEGORY_CONFIG,
					action: pb.Action_ACTION_MODIFIED, actor: "alice", process: "vim", cmdline: "vim /etc/nginx/nginx.conf",
					target:  &pb.TargetResource{TargetType: "file", PathOrKey: "/etc/nginx/nginx.conf"},
					summary: "Modified /etc/nginx/nginx.conf (upstream pool tuning)",
				},
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, category: pb.Category_CATEGORY_SERVICE,
					action: pb.Action_ACTION_RESTARTED, actor: "root", process: "systemctl", cmdline: "systemctl restart nginx",
					target:  &pb.TargetResource{TargetType: "service", PathOrKey: "nginx.service"},
					summary: "Restarted nginx.service",
				},
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, category: pb.Category_CATEGORY_CONFIG,
					action: pb.Action_ACTION_MODIFIED, actor: "deploy-bot", process: "rsync", cmdline: "rsync -a release/ /var/www/html/",
					target:  &pb.TargetResource{TargetType: "file", PathOrKey: "/etc/nginx/conf.d/site-{n}.conf"},
					summary: "Modified /etc/nginx/conf.d/site-{n}.conf",
				},
			},
		},
		{
			hostname: "win-app-02", osFamily: "windows", osVersion: "Windows Server 2022",
			templates: []changeTemplate{
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, category: pb.Category_CATEGORY_REGISTRY,
					action: pb.Action_ACTION_MODIFIED, actor: `CORP\Administrator`, process: "powershell.exe",
					cmdline: `powershell.exe Set-ItemProperty -Path 'HKLM:\Software\Company\App'`,
					target:  &pb.TargetResource{TargetType: "registry", PathOrKey: `HKLM\Software\Company\App\LogLevel`},
					summary: `Modified HKLM\Software\Company\App\LogLevel`,
				},
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED, category: pb.Category_CATEGORY_SERVICE,
					action: pb.Action_ACTION_RESTARTED, actor: "SYSTEM", process: "services.exe",
					cmdline: "sc.exe start W3SVC",
					target:  &pb.TargetResource{TargetType: "service", PathOrKey: "W3SVC"},
					summary: "Restarted IIS W3SVC",
				},
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, category: pb.Category_CATEGORY_CONFIG,
					action: pb.Action_ACTION_MODIFIED, actor: `CORP\svc-deploy`, process: "robocopy.exe",
					cmdline: `robocopy C:\release C:\inetpub\wwwroot /MIR`,
					target:  &pb.TargetResource{TargetType: "file", PathOrKey: `C:\inetpub\wwwroot\web.config`},
					summary: `Modified C:\inetpub\wwwroot\web.config`,
				},
			},
		},
		{
			hostname: "prod-k8s-01", osFamily: "kubernetes", osVersion: "Kubernetes v1.31.2",
			templates: []changeTemplate{
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, category: pb.Category_CATEGORY_CONFIG,
					action: pb.Action_ACTION_MODIFIED, actor: "argocd-controller", process: "kubectl", cmdline: "Apply",
					target:  &pb.TargetResource{TargetType: "k8s_configmap", PathOrKey: "/k8s/prod-k8s-01/payments/configmaps/checkout-config"},
					summary: "Modified ConfigMap payments/checkout-config",
				},
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, category: pb.Category_CATEGORY_SERVICE,
					action: pb.Action_ACTION_RESTARTED, actor: "argocd-controller", process: "kubectl", cmdline: "Apply",
					target:  &pb.TargetResource{TargetType: "k8s_deployment", PathOrKey: "/k8s/prod-k8s-01/messaging/deployments/rabbitmq"},
					summary: "Rolled out Deployment messaging/rabbitmq",
				},
				{
					level: pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, category: pb.Category_CATEGORY_CONFIG,
					action: pb.Action_ACTION_MODIFIED, actor: "kubectl", process: "kubectl", cmdline: "Update",
					target:  &pb.TargetResource{TargetType: "k8s_ingress", PathOrKey: "/k8s/prod-k8s-01/staging/ingresses/checkout-preview"},
					summary: "Modified Ingress staging/checkout-preview",
				},
			},
		},
	}
}

func printBanner(cfg config) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 78))
	fmt.Println("  StateTrack demo traffic generator")
	fmt.Println(strings.Repeat("=", 78))
	if cfg.dryRun {
		fmt.Println("  Mode      : DRY RUN (nothing will be sent)")
	} else {
		fmt.Printf("  Ingest    : %s\n", cfg.grpcAddr)
	}
	fmt.Printf("  Interval  : %s   Burst: %d   L1 share: %.0f%%\n",
		cfg.interval, cfg.burst, cfg.l1Ratio*100)
	if cfg.duration > 0 {
		fmt.Printf("  Duration  : %s\n", cfg.duration)
	} else {
		fmt.Println("  Duration  : until Ctrl-C")
	}
	fmt.Println("  Fleet     : prod-web-01, win-app-02, prod-k8s-01 (created by dev.ps1 seed)")
	fmt.Println(strings.Repeat("-", 78))
	fmt.Println("  Each change flows through the real ingest API, so the exporter's")
	fmt.Println("  statetrack_mutations_total counter climbs and the Grafana rate/")
	fmt.Println("  increase panels — including the hero panel's red L1 bars — move.")
	fmt.Println(strings.Repeat("=", 78))
	fmt.Println()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
