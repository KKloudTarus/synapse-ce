// Command synapse-cluster-agent is the Kubernetes cluster agent (#411/#446, epic #405). It reads a
// live cluster through the read-only collector (internal/infrastructure/k8sinv), enrols with the
// control plane's fleet API, and posts the collected snapshot each resync so the control plane maps
// and persists it into the asset model. It runs with the read-only ClusterRole shipped in
// deploy/k8s/cluster-agent.yaml. The private key is generated locally; only a CSR is sent.
//
// It is a composition root only: it loads Kubernetes config (in-cluster first, then a kubeconfig),
// builds the collector + fleet client, and calls the testable run(). Collection is read-only — the
// agent never mutates the cluster.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/k8sinv"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	clusterAgentVersion = "0.1.0"
	clusterCapability   = "scan.cluster"
)

// snapshotSender posts a cluster snapshot to the control plane; *fleetclient.Client satisfies it and
// a test uses a fake.
type snapshotSender interface {
	SendClusterInventory(ctx context.Context, token string, snap any) error
}

type config struct {
	cluster    string
	namespaces string
	kubeconfig string
	baseURL    string
	enrolToken string
	stateDir   string
	pageSize   int64
	maxPages   int64
	timeout    time.Duration
	resync     time.Duration
	once       bool
}

func main() {
	log.SetFlags(0)
	cfg := parseConfig()

	if strings.TrimSpace(cfg.cluster) == "" {
		log.Fatal("synapse-cluster-agent: -cluster (or SYNAPSE_CLUSTER) is required — it keys every asset")
	}
	if cfg.baseURL == "" {
		log.Fatal("synapse-cluster-agent: -url (or SYNAPSE_FLEET_URL) is required")
	}
	if err := fleetclient.ValidateControlPlaneURL(cfg.baseURL); err != nil {
		log.Fatalf("synapse-cluster-agent: %v", err)
	}

	restCfg, err := loadRESTConfig(cfg.kubeconfig)
	if err != nil {
		log.Fatalf("synapse-cluster-agent: kube config: %v", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("synapse-cluster-agent: kube client: %v", err)
	}
	collector, err := k8sinv.New(client, k8sinv.Config{Namespaces: splitCSV(cfg.namespaces), PageSize: cfg.pageSize, MaxPages: cfg.maxPages})
	if err != nil {
		log.Fatalf("synapse-cluster-agent: %v", err)
	}

	fleet := fleetclient.New(cfg.baseURL, 60*time.Second)
	store := fleetclient.NewCredentialStore(cfg.stateDir)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cred, err := fleetclient.EnsureEnrolled(ctx, fleet, store, cfg.enrolToken, fleetclient.EnrolRequest{
		Name:         cfg.cluster,
		Platform:     "kubernetes",
		AgentVersion: clusterAgentVersion,
		Capabilities: []string{clusterCapability},
	})
	if err != nil {
		log.Fatalf("synapse-cluster-agent: enrol: %v", err)
	}

	// One collect+report per resync interval, each bounded by its own deadline, until signalled.
	for {
		cctx, cancel := context.WithTimeout(ctx, cfg.timeout)
		err := run(cctx, collector, fleet, cred.Token, cfg.cluster)
		cancel()
		if cfg.once {
			if err != nil {
				log.Fatalf("synapse-cluster-agent: %v", err)
			}
			return
		}
		if err != nil {
			log.Printf("synapse-cluster-agent: sync error (will retry in %s): %v", cfg.resync, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.resync):
		}
	}
}

// run collects the cluster inventory and reports it to the control plane. It logs a coverage-honest
// summary (the control plane re-maps against its scanned set). It is testable via the SnapshotSource
// and snapshotSender interfaces.
func run(ctx context.Context, src ports.SnapshotSource, snd snapshotSender, token, cluster string) error {
	snap, err := src.Snapshot(ctx, cluster)
	if err != nil {
		return fmt.Errorf("collect snapshot: %w", err)
	}
	inv := dci.Map(snap, nil)
	log.Printf("cluster %q: %d namespace(s), %d asset(s), %d coverage gap(s)", cluster, len(snap.Namespaces), len(inv.Assets), len(inv.Gaps))
	if err := snd.SendClusterInventory(ctx, token, snap); err != nil {
		return fmt.Errorf("report snapshot: %w", err)
	}
	return nil
}

func parseConfig() config {
	var cfg config
	var enrolTokenFile string
	cfg.pageSize = 500
	cfg.timeout = 2 * time.Minute
	cfg.resync = envDuration("SYNAPSE_CLUSTER_RESYNC", 5*time.Minute)

	flag.StringVar(&cfg.cluster, "cluster", envOr("SYNAPSE_CLUSTER", ""), "cluster identity keyed into every asset (required)")
	flag.StringVar(&cfg.namespaces, "namespaces", envOr("SYNAPSE_CLUSTER_NAMESPACES", ""), "comma-separated namespace scope; empty = all")
	flag.StringVar(&cfg.kubeconfig, "kubeconfig", envOr("KUBECONFIG", ""), "path to a kubeconfig (used when not running in-cluster)")
	flag.StringVar(&cfg.baseURL, "url", envOr("SYNAPSE_FLEET_URL", ""), "control plane fleet API base URL (https required, except a loopback host)")
	flag.StringVar(&cfg.enrolToken, "enrol-token", os.Getenv("SYNAPSE_FLEET_ENROL_TOKEN"), "one-time enrolment token, first run only (DISCOURAGED: visible in ps; prefer -enrol-token-file)")
	flag.StringVar(&enrolTokenFile, "enrol-token-file", os.Getenv("SYNAPSE_FLEET_ENROL_TOKEN_FILE"), "file to read the one-time enrolment token from (preferred over -enrol-token)")
	flag.StringVar(&cfg.stateDir, "state-dir", envOr("SYNAPSE_AGENT_STATE_DIR", "/var/lib/synapse-cluster-agent"), "directory for the agent credential")
	flag.Int64Var(&cfg.pageSize, "page-size", cfg.pageSize, "List page size")
	flag.Int64Var(&cfg.maxPages, "max-pages", 0, "max pages per resource (0 = collector default)")
	flag.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "per-collection deadline")
	flag.DurationVar(&cfg.resync, "resync", cfg.resync, "interval between collections")
	flag.BoolVar(&cfg.once, "once", false, "collect + report once then exit")
	flag.Parse()

	if cfg.enrolToken == "" {
		// An absent token file is NOT fatal: it is the normal state after enrolment, once the
		// one-time secret has been cleaned up. EnsureEnrolled decides from the stored credential.
		tok, err := fleetclient.ReadEnrolTokenFile(enrolTokenFile)
		if err != nil {
			log.Fatalf("synapse-cluster-agent: %v", err)
		}
		cfg.enrolToken = tok
	}
	return cfg
}

// loadRESTConfig prefers in-cluster config (the normal deployment) and falls back to a kubeconfig
// only when genuinely not running in a cluster — a malformed in-cluster token is a real error.
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
