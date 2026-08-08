// Command synapse-agent is the fleet VM agent (#410, epic #405). It enrols with the control plane's
// fleet API, then repeatedly heartbeats, claims host-inventory work orders, collects the host's
// facts and installed OS packages (reusing the engine's owned package cataloger), and reports the
// outcome. The private key is generated locally and never leaves the host; only a CSR is sent.
//
// Scope for this issue: host facts + OS package inventory + the fleet transport loop. Listener/
// service enumeration, local-config evaluation, source-tree scanning, and cgroup resource limits are
// deferred follow-ups, and Windows hosts are out of scope (documented in the collector).
//
// It is a composition root only: no business logic lives here beyond wiring and the run loop, and the
// loop is exercised by main_test.go against a fake API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/hostinv"
)

// agentVersion is reported to the control plane and gated by its version check.
const agentVersion = "0.1.0"

// hostInventoryCapability is the work-order capability this agent fulfils. It follows the platform's
// dotted capability namespace (cf. scan.source, detect.rules — workorder.WorkOrder.Capability).
const hostInventoryCapability = "scan.host"

// fleetAPI is the subset of the fleet client the run loop needs; a fake implements it in tests.
type fleetAPI interface {
	Enrol(ctx context.Context, enrolToken string, req fleetclient.EnrolRequest) (fleetclient.EnrolResponse, error)
	Heartbeat(ctx context.Context, token string, req fleetclient.EnrolRequest) error
	ClaimWork(ctx context.Context, token string, max int) ([]fleetclient.Order, error)
	Progress(ctx context.Context, token, orderID string) error
	SubmitResult(ctx context.Context, token, orderID, status, reason string) error
}

type config struct {
	baseURL    string
	enrolToken string
	stateDir   string
	root       string
	name       string
	poll       time.Duration
	maxOrders  int
	once       bool
}

func main() {
	log.SetFlags(0)
	cfg := parseConfig()
	if cfg.baseURL == "" {
		log.Fatal("synapse-agent: SYNAPSE_FLEET_URL (or -url) is required")
	}
	if err := fleetclient.ValidateControlPlaneURL(cfg.baseURL); err != nil {
		log.Fatalf("synapse-agent: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r := &runner{
		api:     fleetclient.New(cfg.baseURL, 30*time.Second),
		collect: hostinv.Collect,
		cfg:     cfg,
		store:   fleetclient.NewCredentialStore(cfg.stateDir),
	}
	if err := r.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("synapse-agent: %v", err)
	}
}

func parseConfig() config {
	var cfg config
	var enrolTokenFile string
	flag.StringVar(&cfg.baseURL, "url", os.Getenv("SYNAPSE_FLEET_URL"), "control plane fleet API base URL (https required, except a loopback host)")
	// The enrolment token is a one-time secret. Prefer the env var or -enrol-token-file; the -enrol-token
	// flag is DISCOURAGED because it is visible in the process listing (ps) and shell history.
	flag.StringVar(&cfg.enrolToken, "enrol-token", os.Getenv("SYNAPSE_FLEET_ENROL_TOKEN"), "one-time enrolment token, first run only (DISCOURAGED: visible in ps; prefer -enrol-token-file)")
	flag.StringVar(&enrolTokenFile, "enrol-token-file", os.Getenv("SYNAPSE_FLEET_ENROL_TOKEN_FILE"), "file to read the one-time enrolment token from (preferred over -enrol-token)")
	flag.StringVar(&cfg.stateDir, "state-dir", envOr("SYNAPSE_AGENT_STATE_DIR", defaultStateDir()), "directory for the agent credential + offline buffer")
	flag.StringVar(&cfg.root, "root", envOr("SYNAPSE_AGENT_ROOT", "/"), "host filesystem root to inventory")
	flag.StringVar(&cfg.name, "name", envOr("SYNAPSE_AGENT_NAME", hostname()), "agent display name")
	flag.DurationVar(&cfg.poll, "poll", 60*time.Second, "poll interval between claim cycles")
	flag.IntVar(&cfg.maxOrders, "max-orders", 8, "max work orders to claim per cycle")
	flag.BoolVar(&cfg.once, "once", false, "run a single cycle then exit")
	flag.Parse()
	if cfg.enrolToken == "" && enrolTokenFile != "" {
		b, err := os.ReadFile(enrolTokenFile)
		if err != nil {
			log.Fatalf("synapse-agent: read enrol token file: %v", err)
		}
		cfg.enrolToken = strings.TrimSpace(string(b))
	}
	return cfg
}

// runner holds the run-loop dependencies so the loop can be tested with a fake API + collector.
type runner struct {
	api     fleetAPI
	collect func(ctx context.Context, root string) (hostinventory.HostInventory, error)
	cfg     config
	store   *fleetclient.CredentialStore
}

func (r *runner) run(ctx context.Context) error {
	cred, err := r.ensureEnrolled(ctx)
	if err != nil {
		return err
	}
	for {
		if err := r.cycle(ctx, cred); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			log.Printf("cycle error (will retry): %v", err)
		}
		if r.cfg.once {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.cfg.poll):
		}
	}
}

// ensureEnrolled loads a persisted credential or, on first run, generates a key + CSR and enrols,
// using the shared fleetclient helper so credential persistence lives in one place.
func (r *runner) ensureEnrolled(ctx context.Context) (fleetclient.Credential, error) {
	return fleetclient.EnsureEnrolled(ctx, r.api, r.store, r.cfg.enrolToken, fleetclient.EnrolRequest{
		Name:         r.cfg.name,
		Platform:     runtime.GOOS,
		AgentVersion: agentVersion,
		Capabilities: []string{hostInventoryCapability},
	})
}

func (r *runner) cycle(ctx context.Context, cred fleetclient.Credential) error {
	if err := r.api.Heartbeat(ctx, cred.Token, fleetclient.EnrolRequest{
		Name: r.cfg.name, Platform: runtime.GOOS, AgentVersion: agentVersion,
	}); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	orders, err := r.api.ClaimWork(ctx, cred.Token, r.cfg.maxOrders)
	if err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	for _, o := range orders {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.handle(ctx, cred, o)
	}
	return nil
}

// handle runs one order to completion, reporting a terminal result either way.
func (r *runner) handle(ctx context.Context, cred fleetclient.Credential, o fleetclient.Order) {
	if o.Capability != "" && o.Capability != hostInventoryCapability {
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "unsupported capability: "+o.Capability)
		return
	}
	if err := r.api.Progress(ctx, cred.Token, o.ID); err != nil {
		log.Printf("order %s: progress: %v", o.ID, err)
	}
	inv, err := r.collect(ctx, r.cfg.root)
	if err != nil {
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "collect: "+err.Error())
		return
	}
	// The control-plane result endpoint records only the outcome; this on-disk buffer is the ONLY
	// place the actual inventory (including its machine-readable coverage) is preserved for the
	// forthcoming ingest surface. If buffering fails the inventory is lost, so the order is not a
	// success — fail it rather than report a green order with nothing behind it.
	if err := r.buffer(o.ID, inv); err != nil {
		log.Printf("order %s: buffer: %v", o.ID, err)
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "buffer inventory: "+err.Error())
		return
	}
	// Fail closed when the collected package data is untrustworthy (a package DB that exists but could
	// not be read): a consumer must never treat a poisoned inventory as a clean success. An inventory
	// that is merely incomplete for expected reasons (dimensions not yet collected) still succeeds, with
	// the incompleteness stated in the reason and preserved structurally in the buffered inventory.
	status := "succeeded"
	if inv.Degraded() {
		status = "failed"
	}
	if err := r.api.SubmitResult(ctx, cred.Token, o.ID, status, summary(inv)); err != nil {
		log.Printf("order %s: submit result: %v", o.ID, err)
	}
}

// summary is a coverage-honest, secret-free one-liner for the result reason.
func summary(inv hostinventory.HostInventory) string {
	s := fmt.Sprintf("%d packages, os=%s/%s", len(inv.Packages), inv.Facts.OS, inv.Facts.OSVersion)
	if inv.Degraded() {
		s += " (DEGRADED: a package database could not be read)"
	}
	if !inv.Complete {
		s += fmt.Sprintf(" (INCOMPLETE: %d coverage issue(s))", len(inv.Coverage))
	}
	return s
}

// --- state persistence ---------------------------------------------------

// buffer writes the collected inventory to the state dir as a local artifact and reports whether it
// succeeded. The control plane's result endpoint records only the order outcome; this on-disk buffer
// preserves the actual inventory for the forthcoming ingest surface and survives a transient
// reporting failure. It reuses fleetclient.WriteSecret (0600 + chmod) so on-disk-secret handling is
// not duplicated.
func (r *runner) buffer(orderID string, inv hostinventory.HostInventory) error {
	if err := os.MkdirAll(r.cfg.stateDir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	if err := fleetclient.WriteSecret(filepath.Join(r.cfg.stateDir, "inventory-"+safe(orderID)+".json"), b, 0o600); err != nil {
		return fmt.Errorf("write inventory: %w", err)
	}
	return nil
}

// --- helpers --------------------------------------------------------------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "synapse-agent")
	}
	return "/var/lib/synapse-agent"
}

func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "synapse-agent"
}

// safe strips path separators from an order id used in a filename.
func safe(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '/' || r == '\\' || r == '.' {
			out = append(out, '_')
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return "order"
	}
	return string(out)
}
