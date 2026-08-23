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
	"strconv"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/hostinv"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
)

// agentVersion is reported to the control plane and gated by its version-skew floor. It reflects the
// real build (a release tag via ldflags; "devel" for an untagged build) so the fleet floor can
// distinguish agent releases in the field, matching how the control plane reports its own version.
var agentVersion = buildinfo.App()

// hostInventoryCapability is the work-order capability this agent fulfils. It follows the platform's
// dotted capability namespace (cf. scan.source, detect.rules — workorder.WorkOrder.Capability).
const hostInventoryCapability = "scan.host"

// minControlPlaneVersion is the minimum control-plane version this agent requires (#412 version skew).
// If the heartbeat reports an older control plane, the agent refuses to claim work this cycle rather
// than risk acting against an incompatible transport contract.
const minControlPlaneVersion = "0.1.0"

// fleetAPI is the subset of the fleet client the run loop needs; a fake implements it in tests.
type fleetAPI interface {
	Enrol(ctx context.Context, enrolToken string, req fleetclient.EnrolRequest) (fleetclient.EnrolResponse, error)
	Heartbeat(ctx context.Context, token string, req fleetclient.EnrolRequest) (fleetclient.HeartbeatResponse, error)
	ClaimWork(ctx context.Context, token string, max int) ([]fleetclient.Order, error)
	Progress(ctx context.Context, token, orderID string) error
	SubmitResult(ctx context.Context, token, orderID, status, reason string) error
	SendHostInventory(ctx context.Context, token string, inv any) error
	RegisterDetectionKey(ctx context.Context, token string, key fleetagent.AgentSigningKey, proof string) error
	SendDetectionBatch(ctx context.Context, token string, batch fleetagent.AgentBatch, items []fleetagent.DetectionBatchItem) error
}

type config struct {
	baseURL               string
	enrolToken            string
	stateDir              string
	root                  string
	name                  string
	poll                  time.Duration
	maxOrders             int
	once                  bool
	detectClasses         string  // SYNAPSE_DETECT_CLASSES; empty = detection engine off
	detectCeiling         float64 // SYNAPSE_DETECT_CPU_CEIL_PCT; 0 = no load shedding
	spoolBytes            int64   // durable telemetry WAL quota
	metricsAddr           string  // optional private agent metrics listener
	detectionEngagement   string  // engagement receiving signed detection batches; empty = local-only
	detectionShipInterval time.Duration
	// inventorySweep turns the host inventory from on-demand (a scan.host work order) into a continuous
	// periodic stream (A8, #629). Enabled by default (ingest-on); the interval is clamped to a floor so a
	// misconfiguration cannot busy-loop the collector over the real filesystem.
	inventorySweepEnabled  bool
	inventorySweepInterval time.Duration
}

func main() {
	log.SetFlags(0)
	// The host floor is checked before the configuration, because it is the one refusal that no
	// configuration can make valid.
	if err := checkOSFloor(); err != nil {
		log.Fatalf("synapse-agent: %v", err)
	}
	cfg := parseConfig()
	if cfg.baseURL == "" {
		log.Fatal("synapse-agent: SYNAPSE_FLEET_URL (or -url) is required")
	}
	if err := fleetclient.ValidateControlPlaneURL(cfg.baseURL); err != nil {
		log.Fatalf("synapse-agent: %v", err)
	}
	r := &runner{
		api:     fleetclient.New(cfg.baseURL, 30*time.Second),
		collect: hostinv.Collect,
		cfg:     cfg,
		store:   fleetclient.NewCredentialStore(cfg.stateDir),
	}

	// On Windows the Service Control Manager starts the binary and expects a status handshake; a
	// process that just runs is killed as unresponsive. runAsService takes over when we were started
	// that way and reports false otherwise, so the same binary is still an ordinary command-line tool.
	if runAsService(r.run) {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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
	flag.StringVar(&cfg.detectClasses, "detect-classes", os.Getenv("SYNAPSE_DETECT_CLASSES"), "comma-separated eBPF detection classes to run (process,network,file,privilege); empty = detection engine off (#422, Linux+root only)")
	flag.Float64Var(&cfg.detectCeiling, "detect-ceiling", parseCeiling(os.Getenv("SYNAPSE_DETECT_CPU_CEIL_PCT")), "CPU ceiling percent for the detection engine; over it, classes are shed in a defined order (0 = no shedding)")
	flag.Int64Var(&cfg.spoolBytes, "telemetry-spool-bytes", parsePositiveBytes(os.Getenv("SYNAPSE_TELEMETRY_SPOOL_BYTES"), 512<<20), "maximum bytes retained by the priority telemetry WAL")
	flag.StringVar(&cfg.metricsAddr, "agent-metrics-addr", os.Getenv("SYNAPSE_AGENT_METRICS_ADDR"), "optional address for private agent Prometheus metrics (for example 127.0.0.1:9465)")
	flag.StringVar(&cfg.detectionEngagement, "detection-engagement", os.Getenv("SYNAPSE_DETECTION_ENGAGEMENT_ID"), "engagement id receiving signed detection batches; empty keeps detections local")
	flag.DurationVar(&cfg.detectionShipInterval, "detection-ship-interval", parsePositiveDuration(os.Getenv("SYNAPSE_DETECTION_SHIP_INTERVAL"), time.Second), "idle interval for the independent detection delivery loop")
	flag.BoolVar(&cfg.inventorySweepEnabled, "inventory-sweep", envEnabledDefaultTrue(os.Getenv("SYNAPSE_INVENTORY_SWEEP_ENABLED")), "ship host inventory continuously on a cadence (A8, #629); on by default")
	flag.DurationVar(&cfg.inventorySweepInterval, "inventory-sweep-interval", parsePositiveDuration(os.Getenv("SYNAPSE_INVENTORY_SWEEP_INTERVAL"), time.Hour), "cadence of the continuous host-inventory sweep (clamped to a floor)")
	flag.Parse()
	if cfg.enrolToken == "" {
		// An absent token file is NOT fatal: it is the normal state after enrolment, once the
		// one-time secret has been cleaned up. EnsureEnrolled decides from the stored credential.
		tok, err := fleetclient.ReadEnrolTokenFile(enrolTokenFile)
		if err != nil {
			log.Fatalf("synapse-agent: %v", err)
		}
		cfg.enrolToken = tok
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
	// Agent-side detection engine (#422): a continuous background observer, separate from the
	// per-work-order inventory cycle below. Best-effort — it never blocks or fails the inventory loop.
	// It is given the enrolled credential so its events carry the canonical AgentID, not the display
	// name (D1 fix, #606).
	r.startDetection(ctx, cred)
	// Continuous host-inventory sweep (#629, A8): a background stream, separate from the per-work-order
	// scan.host cycle below, so a control plane always has a fresh inventory to re-evaluate against new
	// advisories without a manual re-scan. Best-effort — it never blocks or fails the work-order loop.
	r.startInventorySweep(ctx, cred)
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
	hb, err := r.api.Heartbeat(ctx, cred.Token, fleetclient.EnrolRequest{
		Name: r.cfg.name, Platform: runtime.GOOS, AgentVersion: agentVersion,
	})
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	// Version skew (#412): if this agent is below the control plane's minimum, it will be refused work
	// server-side anyway — surface a clear update instruction. If the control plane is DEMONSTRABLY
	// older than this agent requires, refuse to claim this cycle. This check fails OPEN (availability):
	// an empty or unparseable control-plane version (e.g. an untagged "devel" build) is treated as
	// "unknown, proceed" — only a parseable CP version strictly below the floor skips the cycle. (This
	// is the opposite of the SERVER-side agent-version check, which fails closed for security.)
	if !fleetversion.MeetsFloor(agentVersion, hb.MinSupportedAgentVersion) {
		log.Printf("version skew: agent %s is below the control plane minimum %s — update this agent", agentVersion, hb.MinSupportedAgentVersion)
	}
	if cp, ok := fleetversion.Parse(hb.ControlPlaneVersion); ok {
		if floor, fok := fleetversion.Parse(minControlPlaneVersion); fok && cp.Less(floor) {
			log.Printf("version skew: control plane %s is older than this agent requires (%s) — skipping claim this cycle", hb.ControlPlaneVersion, minControlPlaneVersion)
			return nil
		}
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
	// Keep a durable local copy first (the buffer survives a transient reporting failure). If buffering
	// fails the inventory is lost, so the order is not a success.
	if err := r.buffer(o.ID, inv); err != nil {
		log.Printf("order %s: buffer: %v", o.ID, err)
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "buffer inventory: "+err.Error())
		return
	}
	// Report the inventory to the control plane, which persists the host into the asset model (#446).
	// The control plane records the coverage/degraded flags on the asset. If reporting fails the data
	// did not land, so the order is not a clean success — fail it (the local buffer preserves the data).
	if err := r.api.SendHostInventory(ctx, cred.Token, inv); err != nil {
		log.Printf("order %s: report inventory: %v", o.ID, err)
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "report inventory: "+err.Error())
		return
	}
	// Fail closed when the collected package data is untrustworthy (a package DB that exists but could
	// not be read): a consumer must never treat a poisoned inventory as a clean success. An inventory
	// that is merely incomplete for expected reasons (dimensions not yet collected) still succeeds, with
	// the incompleteness stated in the reason and preserved on the persisted asset.
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

func parsePositiveBytes(value string, def int64) int64 {
	if value == "" {
		return def
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		log.Printf("ignoring invalid telemetry spool byte count (want a positive integer)")
		return def
	}
	return parsed
}

func parsePositiveDuration(value string, def time.Duration) time.Duration {
	if value == "" {
		return def
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		log.Printf("ignoring invalid detection ship interval (want a positive duration)")
		return def
	}
	return parsed
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
