// Command synapse-cluster-agent is the Kubernetes cluster agent (#411, epic #405). It reads a live
// cluster through the read-only collector (internal/infrastructure/k8sinv), maps it to the fleet
// asset model, and emits the resulting inventory plus a coverage-honest summary. It runs with the
// read-only ClusterRole shipped in deploy/k8s/cluster-agent.yaml.
//
// It is a composition root only: it loads Kubernetes config (in-cluster first, then a kubeconfig),
// builds the collector, and calls the testable run() with it. Collection is read-only — the agent
// never mutates the cluster.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/k8sinv"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func main() {
	log.SetFlags(0)
	cluster := envOr("SYNAPSE_CLUSTER", "")
	namespaces := envOr("SYNAPSE_CLUSTER_NAMESPACES", "")
	kubeconfig := envOr("KUBECONFIG", "")
	var pageSize int64 = 500
	var maxPages int64 = 0 // 0 -> collector default
	timeout := 2 * time.Minute
	resync := envDuration("SYNAPSE_CLUSTER_RESYNC", 5*time.Minute)
	once := false

	flag.StringVar(&cluster, "cluster", cluster, "cluster identity keyed into every asset (required)")
	flag.StringVar(&namespaces, "namespaces", namespaces, "comma-separated namespace scope; empty = all")
	flag.StringVar(&kubeconfig, "kubeconfig", kubeconfig, "path to a kubeconfig (used when not running in-cluster)")
	flag.Int64Var(&pageSize, "page-size", pageSize, "List page size")
	flag.Int64Var(&maxPages, "max-pages", maxPages, "max pages per resource (0 = collector default)")
	flag.DurationVar(&timeout, "timeout", timeout, "per-collection deadline")
	flag.DurationVar(&resync, "resync", resync, "interval between collections (long-running mode)")
	flag.BoolVar(&once, "once", once, "collect once then exit")
	flag.Parse()

	if strings.TrimSpace(cluster) == "" {
		log.Fatal("synapse-cluster-agent: -cluster (or SYNAPSE_CLUSTER) is required — it keys every asset")
	}

	restCfg, err := loadRESTConfig(kubeconfig)
	if err != nil {
		log.Fatalf("synapse-cluster-agent: kube config: %v", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("synapse-cluster-agent: kube client: %v", err)
	}
	collector, err := k8sinv.New(client, k8sinv.Config{Namespaces: splitCSV(namespaces), PageSize: pageSize, MaxPages: maxPages})
	if err != nil {
		log.Fatalf("synapse-cluster-agent: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// One collection per resync interval (req 7), each bounded by its own deadline, until signalled.
	// -once collects a single time (fail-fast for CI / kind tests).
	for {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		err := run(cctx, collector, cluster, os.Stdout)
		cancel()
		if once {
			if err != nil {
				log.Fatalf("synapse-cluster-agent: %v", err)
			}
			return
		}
		if err != nil {
			log.Printf("synapse-cluster-agent: collection error (will retry in %s): %v", resync, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(resync):
		}
	}
}

// run collects the cluster inventory and writes it as JSON to out, logging a coverage-honest summary.
// It is separated from config loading so it can be tested with a fake SnapshotSource.
func run(ctx context.Context, src ports.SnapshotSource, cluster string, out io.Writer) error {
	snap, err := src.Snapshot(ctx, cluster)
	if err != nil {
		return fmt.Errorf("collect snapshot: %w", err)
	}
	// Map to surface coverage gaps. Nothing is scanned from the agent's vantage point, so every running
	// digest is reported as an unscanned gap here; the control plane re-maps against its scanned set.
	inv := dci.Map(snap, nil)
	log.Printf("cluster %q: %d namespace(s), %d asset(s), %d coverage gap(s)", cluster, len(snap.Namespaces), len(inv.Assets), len(inv.Gaps))
	for _, g := range inv.Gaps {
		log.Printf("  coverage gap [%s] %s: %s", g.Kind, g.Workload, g.Detail)
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	return nil
}

// loadRESTConfig prefers in-cluster config (the normal deployment) and falls back to a kubeconfig
// only when genuinely not running in a cluster — a malformed in-cluster token is a real error, not a
// silent fall-through to kubeconfig.
func loadRESTConfig(kubeconfig string) (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, rest.ErrNotInCluster) {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loading.ExplicitPath = kubeconfig
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
