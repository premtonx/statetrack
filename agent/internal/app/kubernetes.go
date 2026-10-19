package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/collectors/k8s"
	"github.com/statetrack/statetrack/agent/internal/config"
	"github.com/statetrack/statetrack/agent/internal/discovery"
)

// startKubernetes starts the in-cluster configuration watcher when it is
// enabled, returning the collector so the agent can fold the cluster's
// workload recommendations into the discovery heartbeat.
//
// It is a no-op on a host that is not a cluster node, which is the common case
// and must never be an error: a configuration file deployed to a whole fleet
// turns the watcher on everywhere, and only the pods have a cluster to watch.
func startKubernetes(ctx context.Context, wg *sync.WaitGroup, a *Agent) (*k8s.Collector, error) {
	kcfg := a.Config.Kubernetes
	if !kcfg.Enabled {
		return nil, nil
	}
	log := a.Logger

	// Secret payloads must use the same salted scrubber as file content, so a
	// credential gets one stable marker across the whole host.
	k8s.SetStubber(a.scrubber)

	client, err := k8sClient(kcfg)
	if err != nil {
		// Not running in a pod (or the mount is missing): report and continue.
		// Discovery and every other collector keep working.
		log.Info("kubernetes watcher disabled", "reason", err)
		return nil, nil
	}

	col, err := k8s.New(k8s.Options{
		Client:         client,
		Classifier:     a.Classifier,
		Handle:         a.Engine.HandleDoc,
		Seed:           a.Engine.SeedDoc,
		Namespaces:     kcfg.Namespaces,
		ResyncInterval: kcfg.ResyncInterval.D(),
		Logger:         log,
	})
	if err != nil {
		return nil, fmt.Errorf("kubernetes collector: %w", err)
	}

	// Seed on the first run so bringing the watcher up on an existing cluster
	// does not report the whole cluster as a change.
	seedCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := col.Seed(seedCtx); err != nil {
		log.Warn("kubernetes baseline incomplete; changes since agent start may be reported", "err", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := col.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("kubernetes collector stopped", "err", err)
		}
	}()
	log.Info("kubernetes watcher started", "cluster", col.Cluster(), "namespaces", kcfg.Namespaces)
	return col, nil
}

// k8sClient builds the API client from the config, defaulting to the in-cluster
// service account when no endpoint is configured.
func k8sClient(kcfg config.Kubernetes) (*k8s.Client, error) {
	if kcfg.Endpoint == "" {
		cfg, err := k8s.InClusterConfig()
		if err != nil {
			return nil, err
		}
		cfg.Cluster = kcfg.Cluster
		cfg.InsecureSkipVerify = kcfg.InsecureSkipVerify
		return k8s.NewClient(cfg)
	}
	cfg := k8s.Config{
		Endpoint:           kcfg.Endpoint,
		Cluster:            kcfg.Cluster,
		InsecureSkipVerify: kcfg.InsecureSkipVerify,
	}
	if kcfg.TokenFile != "" {
		b, err := os.ReadFile(kcfg.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("kubernetes token file: %w", err)
		}
		cfg.Token = strings.TrimSpace(string(b))
	}
	if kcfg.CADataFile != "" {
		b, err := os.ReadFile(kcfg.CADataFile)
		if err != nil {
			return nil, fmt.Errorf("kubernetes CA file: %w", err)
		}
		cfg.CAData = b
	}
	return k8s.NewClient(cfg)
}

// kubernetesWorkloads folds the cluster watcher's recommendations into the
// discovery workload set.
//
// The host scanner skips Kubernetes entries on purpose (their objects are not
// on the host), so without this the console would never be offered a cluster
// recommendation. Reporting both sets from one heartbeat is what makes a
// cluster and its nodes appear as one fleet.
func kubernetesWorkloads(col *k8s.Collector) []discovery.DiscoveredWorkload {
	if col == nil {
		return nil
	}
	return col.Recommendations()
}
