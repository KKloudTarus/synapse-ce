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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/agentspool"
	"github.com/KKloudTarus/synapse-ce/internal/composition/responseobserver"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
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

const responseProcessCapability = workorder.CapabilityResponseProcess
const responseHaltCapability = workorder.CapabilityResponseHalt
const responseObserveCapability = workorder.CapabilityResponseObserve

// minControlPlaneVersion is the minimum control-plane version this agent requires (#412 version skew).
// If the heartbeat reports an older control plane, the agent refuses to claim work this cycle rather
// than risk acting against an incompatible transport contract.
const minControlPlaneVersion = "0.1.0"

// fleetAPI is the subset of the fleet client the run loop needs; a fake implements it in tests.
type fleetAPI interface {
	Enrol(ctx context.Context, enrolToken string, req fleetclient.EnrolRequest) (fleetclient.EnrolResponse, error)
	ActivateCredential(cred fleetclient.Credential, keyPEM []byte) error
	Heartbeat(ctx context.Context, token string, req fleetclient.EnrolRequest) (fleetclient.HeartbeatResponse, error)
	ActivePrivacyPolicy(ctx context.Context, token string) (fleetclient.PrivacyPolicyResponse, error)
	ClaimWork(ctx context.Context, token string, max int) ([]fleetclient.Order, error)
	Progress(ctx context.Context, token, orderID, leaseID string) error
	SubmitResult(ctx context.Context, token, orderID, leaseID, status, reason string) error
	SubmitResponseResult(ctx context.Context, token, orderID string, request fleetclient.ResponseResultRequest) error
	SendHostInventory(ctx context.Context, token string, inv any) error
}

// hostInventoryResolvedAPI is optional so the long-standing run-loop test doubles
// remain source-compatible. The production fleet client implements it and returns
// the canonical asset identity reconciled by the authenticated control plane.
type hostInventoryResolvedAPI interface {
	SendHostInventoryResolved(ctx context.Context, token string, inv any) (fleetclient.HostInventoryResponse, error)
}

type responseCommandExecutor interface {
	Execute(context.Context, fleetagent.ResponseCommand, string, time.Time) (fleetagent.ResponseExecutionResult, error)
	ExecuteHaltCommand(context.Context, fleetagent.ResponseHaltCommand, string, time.Time) error
	Halt(context.Context, int64) error
	PendingResults(context.Context) ([]fleetagent.ResponseExecutionJournalEntry, error)
	AcknowledgeResult(context.Context, string, string) error
}

type responseObservationRunner interface {
	Observe(context.Context, fleetclient.Credential, fleetclient.Order) error
}

// producerController owns the source-observation lifetime. Durable telemetry
// shippers are process-owned separately so historical WAL continues shipping
// while a current privacy policy is unavailable or changes.
type producerController struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     <-chan struct{}
	digest   string
	disabled bool
}

func (c *producerController) reconcile(
	ctx context.Context,
	r *runner,
	transport *detectionTransport,
	assignment privacy.Assignment,
) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return false
	}
	if c.digest == assignment.Digest && c.cancel != nil {
		return true
	}
	if c.cancel != nil {
		c.cancel()
		<-c.done
		c.cancel = nil
		c.done = nil
		c.digest = ""
	}
	producerCtx, cancel := context.WithCancel(ctx)
	done, err := r.startDetectionProducer(producerCtx, transport, assignment)
	if err != nil {
		cancel()
		log.Printf("detection: start policy-bound producer: %v; source observation disabled", err)
		return false
	}
	c.cancel = cancel
	c.done = done
	c.digest = assignment.Digest
	return true
}

func (c *producerController) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disabled = true
	if c.cancel != nil {
		c.cancel()
		<-c.done
		c.cancel = nil
		c.done = nil
	}
}

func (r *runner) resolvePrivacyPolicy(
	ctx context.Context,
	cred fleetclient.Credential,
) (privacy.Assignment, error) {
	agentID := shared.ID(strings.TrimSpace(cred.AgentID))
	response, err := r.api.ActivePrivacyPolicy(ctx, cred.Token)
	if err == nil {
		assignment, conversionErr := response.AssignmentDomain()
		if conversionErr != nil {
			return privacy.Assignment{}, conversionErr
		}
		if persistErr := fleetclient.PersistPrivacyPolicy(
			r.cfg.stateDir,
			agentID,
			r.cfg.baseURL,
			assignment,
		); persistErr != nil {
			return privacy.Assignment{}, fmt.Errorf("persist active privacy policy: %w", persistErr)
		}
		return assignment, nil
	}
	if !privacyPolicyCacheFallbackAllowed(err) {
		return privacy.Assignment{}, fmt.Errorf("fetch active privacy policy: %w", err)
	}
	if assignment, ok := fleetclient.LoadPrivacyPolicy(
		r.cfg.stateDir,
		agentID,
		r.cfg.baseURL,
	); ok {
		return assignment, nil
	}
	return privacy.Assignment{}, fmt.Errorf("fetch active privacy policy: %w", err)
}

func privacyPolicyCacheFallbackAllowed(err error) bool {
	if fleetclient.IsNetworkError(err) {
		return true
	}
	status, _, ok := fleetclient.HTTPStatus(err)
	return ok && status >= http.StatusInternalServerError
}

type config struct {
	baseURL       string
	enrollmentURL string
	enrolToken    string
	stateDir      string
	root          string
	name          string
	poll          time.Duration
	maxOrders     int
	once          bool
	detectClasses string  // SYNAPSE_DETECT_CLASSES; empty = detection engine off
	detectCeiling float64 // SYNAPSE_DETECT_CPU_CEIL_PCT; 0 = no load shedding
	spoolBytes    int64   // durable telemetry WAL quota
	metricsAddr   string  // optional private agent metrics listener
	// inventorySweep turns host inventory from on-demand scan.host work into a continuous
	// periodic stream (A8, #629). It is default-on and cadence-clamped to avoid busy loops.
	inventorySweepEnabled  bool
	inventorySweepInterval time.Duration
	// processReportEnabled ships the host's running-process snapshot to the behavior baseline (#594 D)
	// on the inventory-sweep cadence. Read-only /proc metadata; on by default, operator-disableable.
	processReportEnabled    bool
	procRoot                string
	responseEnabled         bool
	responseTrustFile       string
	responseObserverEnabled bool
	responseObserverDelay   time.Duration
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
	if cfg.enrollmentURL == "" {
		cfg.enrollmentURL = cfg.baseURL
	}
	if err := fleetclient.ValidateControlPlaneURL(cfg.enrollmentURL); err != nil {
		log.Fatalf("synapse-agent: enrollment endpoint: %v", err)
	}
	responseRuntime, err := newEndpointResponseRuntime(cfg)
	if err != nil {
		log.Fatalf("synapse-agent: configure live response execution: %v", err)
	}
	defer func() {
		if err := responseRuntime.Close(); err != nil {
			log.Printf("synapse-agent: close response runtime: %v", err)
		}
	}()
	r := &runner{
		api:     fleetclient.NewWithEnrollmentURL(cfg.baseURL, cfg.enrollmentURL, 30*time.Second),
		collect: hostinv.Collect,
		cfg:     cfg,
		store:   fleetclient.NewCredentialStore(cfg.stateDir),
	}
	if cfg.responseObserverEnabled {
		observerAPI, ok := r.api.(responseobserver.API)
		if !ok {
			log.Fatalf("synapse-agent: response observer fleet transport is not configured")
		}
		responseRuntime, err := responseobserver.New(r.store, observerAPI, cfg.responseObserverDelay)
		if err != nil {
			log.Fatalf("synapse-agent: configure response observer: %v", err)
		}
		r.responseObserver = responseRuntime
	}
	if responseRuntime != nil {
		r.responseFactory = responseRuntime.executorFor
		r.responseProcesses = responseRuntime.registry
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
	flag.StringVar(&cfg.enrollmentURL, "enrol-url", os.Getenv("SYNAPSE_FLEET_ENROL_URL"), "one-time enrollment API base URL; defaults to -url (https required except loopback)")
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
	flag.BoolVar(&cfg.inventorySweepEnabled, "inventory-sweep", envEnabledDefaultTrue(os.Getenv("SYNAPSE_INVENTORY_SWEEP_ENABLED")), "ship host inventory continuously on a cadence (A8, #629); on by default")
	flag.DurationVar(&cfg.inventorySweepInterval, "inventory-sweep-interval", parsePositiveDuration(os.Getenv("SYNAPSE_INVENTORY_SWEEP_INTERVAL"), time.Hour), "cadence of the continuous host-inventory sweep (clamped to a floor)")
	flag.BoolVar(&cfg.processReportEnabled, "process-report", envEnabledDefaultTrue(os.Getenv("SYNAPSE_PROCESS_REPORT_ENABLED")), "report the host's running processes to the behavior baseline on the sweep cadence (read-only /proc; #594 D); on by default")
	flag.StringVar(&cfg.procRoot, "proc-root", envOr("SYNAPSE_AGENT_PROC_ROOT", "/proc"), "procfs root to enumerate running processes from")
	flag.BoolVar(&cfg.responseEnabled, "response-execution", envEnabled(os.Getenv("SYNAPSE_RESPONSE_EXECUTION_ENABLED")), "enable governed Linux process response (requires root, process detection, and a pinned command trust bundle)")
	flag.StringVar(&cfg.responseTrustFile, "response-command-trust-file", os.Getenv("SYNAPSE_RESPONSE_COMMAND_TRUST_FILE"), "path to the pinned control-plane response-command public-key bundle")
	flag.BoolVar(&cfg.responseObserverEnabled, "response-observer", envEnabled(os.Getenv("SYNAPSE_RESPONSE_OBSERVER_ENABLED")), "enable independent response post-condition observation (requires process detection and a server-assigned asset)")
	flag.DurationVar(&cfg.responseObserverDelay, "response-observer-delay", parsePositiveDuration(os.Getenv("SYNAPSE_RESPONSE_OBSERVER_DELAY"), 5*time.Second), "delay before emitting a verdict-free response readiness report")
	flag.Parse()
	if cfg.responseObserverEnabled {
		classes, err := parseDetectClasses(cfg.detectClasses)
		if err != nil {
			log.Fatalf("synapse-agent: response observer: %v", err)
		}
		hasProcess := false
		for _, class := range classes {
			if class == "process" {
				hasProcess = true
			}
		}
		if cfg.responseEnabled || !hasProcess {
			log.Fatal("synapse-agent: response observer must be a distinct non-executor agent with process detection enabled")
		}
	}
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
	api               fleetAPI
	collect           func(ctx context.Context, root string) (hostinventory.HostInventory, error)
	response          responseCommandExecutor
	responseFactory   func(shared.ID, shared.ID) (responseCommandExecutor, error)
	responseProcesses agentspool.ProcessLifecycleObserver
	responseObserver  responseObservationRunner
	cfg               config
	store             *fleetclient.CredentialStore
}

func (r *runner) run(ctx context.Context) error {
	cred, err := r.ensureEnrolled(ctx)
	if err != nil {
		return err
	}
	if err := r.configureResponse(cred); err != nil {
		return err
	}
	// A8 continuous host-inventory sweep is best-effort and independent from the
	// scan.host work-order loop. A3 still gates telemetry observation/signing on
	// the canonical server-provided AssetID below.
	// Every observer retains an independently enrolled primary host identity. Its secondary target is
	// applied only to a bounded response-observation telemetry session.
	r.startInventorySweep(ctx, cred)

	var transport *detectionTransport
	producer := &producerController{}
	defer func() {
		producer.stop()
		transport.stop()
	}()
	policyDigest := ""

	for {
		if err := r.configureResponse(cred); err != nil {
			return err
		}
		// A0.1 requires the canonical server-provided asset binding before telemetry
		// transport starts. The transport owns historical durable WAL independently of
		// whether current source observation is authorized by an active privacy policy.
		//
		// The binding is established by the inventory sweep, which runs in its own goroutine and
		// writes it to the credential store, so re-read it here rather than trusting the copy this
		// loop started with. Without the re-read the loop would hold an empty AssetID for the life
		// of the process and the transport would never start.
		if transport == nil && cred.AssetID == "" {
			if stored, ok := r.store.Load(); ok && stored.AssetID != "" {
				cred = stored
			}
		}
		if transport == nil && cred.AssetID != "" {
			transport, err = r.startDetectionTransport(ctx, cred)
			if err != nil {
				log.Printf("telemetry: %v; transport will retry after the next cycle", err)
			}
		}
		if transport != nil && len(transport.classes) > 0 {
			assignment, policyErr := r.resolvePrivacyPolicy(ctx, cred)
			if policyErr != nil {
				if policyDigest == "" {
					log.Printf("detection: active source-privacy policy unavailable; source observation disabled: %v", policyErr)
				} else {
					log.Printf("detection: refresh source-privacy policy: %v; retaining the last validated policy", policyErr)
				}
			} else if producer.reconcile(ctx, r, transport, assignment) {
				policyDigest = assignment.Digest
			}
		}

		if err := r.cycle(ctx, cred); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			log.Printf("cycle error (will retry): %v", err)
		}
		// handle may have learned and durably persisted the canonical AssetID. Reload
		// after every cycle so the transport starts exactly once with the server binding.
		if current, ok := r.store.Load(); ok && current.AgentID == cred.AgentID {
			cred = current
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
		Capabilities: r.capabilities(),
	})
}

func (r *runner) configureResponse(cred fleetclient.Credential) error {
	if r.response != nil || r.responseFactory == nil || strings.TrimSpace(cred.AssetID) == "" {
		return nil
	}
	executor, err := r.responseFactory(shared.ID(strings.TrimSpace(cred.AgentID)), shared.ID(strings.TrimSpace(cred.AssetID)))
	if err != nil {
		return fmt.Errorf("configure response executor: %w", err)
	}
	r.response = executor
	return nil
}

func (r *runner) capabilities() []string {
	capabilities := make([]string, 0, 3)
	if !r.cfg.responseObserverEnabled {
		capabilities = append(capabilities, hostInventoryCapability)
	}
	if r.cfg.responseObserverEnabled {
		capabilities = append(capabilities, responseObserveCapability)
	}
	if r.response != nil {
		capabilities = append(capabilities, responseProcessCapability, responseHaltCapability)
	}
	return capabilities
}

func (r *runner) cycle(ctx context.Context, cred fleetclient.Credential) error {
	hb, err := r.api.Heartbeat(ctx, cred.Token, fleetclient.EnrolRequest{
		Name: r.cfg.name, Platform: runtime.GOOS, AgentVersion: agentVersion,
		Capabilities: r.capabilities(),
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
	if hb.ResponseHalted && r.response != nil {
		if hb.ResponseHaltGeneration <= 0 {
			return fmt.Errorf("heartbeat returned an invalid response halt generation")
		}
		if err := r.response.Halt(ctx, hb.ResponseHaltGeneration); err != nil {
			return fmt.Errorf("apply control-plane response halt fence: %w", err)
		}
	}
	if r.cfg.responseObserverEnabled {
		if strings.TrimSpace(cred.AssetID) == "" {
			return fmt.Errorf("response observer has no established primary telemetry asset")
		}
		if strings.TrimSpace(hb.ResponseObserverAssetID) == "" {
			return fmt.Errorf("response observer has no active server-assigned asset")
		}
		if cred.ResponseObserverAssetID != hb.ResponseObserverAssetID {
			updated, err := r.store.PersistResponseObserverAssetBinding(cred, hb.ResponseObserverAssetID)
			if err != nil {
				return fmt.Errorf("persist response observer target assignment: %w", err)
			}
			cred = updated
		}
	}
	if err := r.flushResponseResults(ctx, cred); err != nil {
		return err
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
	if o.Capability == responseHaltCapability {
		r.handleResponseHalt(ctx, cred, o)
		return
	}
	if o.Capability == responseProcessCapability {
		r.handleResponse(ctx, cred, o)
		return
	}
	if o.Capability == responseObserveCapability {
		r.handleResponseObservation(ctx, cred, o)
		return
	}
	if o.Capability != "" && o.Capability != hostInventoryCapability {
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, "failed", "unsupported capability: "+o.Capability)
		return
	}
	if err := r.api.Progress(ctx, cred.Token, o.ID, o.LeaseID); err != nil {
		log.Printf("order %s: progress: %v", o.ID, err)
		return
	}
	inv, err := r.collect(ctx, r.cfg.root)
	if err != nil {
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, "failed", "collect: "+err.Error())
		return
	}
	// Keep a durable local copy first (the buffer survives a transient reporting failure). If buffering
	// fails the inventory is lost, so the order is not a success.
	if err := r.buffer(o.ID, inv); err != nil {
		log.Printf("order %s: buffer: %v", o.ID, err)
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, "failed", "buffer inventory: "+err.Error())
		return
	}
	// Production uses the resolved response path: the authenticated control plane
	// returns the canonical host AssetID and the agent persists that exact value.
	// Legacy fakes can keep the old void method without weakening production.
	if resolved, ok := r.api.(hostInventoryResolvedAPI); ok {
		resp, reportErr := resolved.SendHostInventoryResolved(ctx, cred.Token, inv)
		if reportErr != nil {
			log.Printf("order %s: report inventory: %v", o.ID, reportErr)
			_ = r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, "failed", "report inventory: "+reportErr.Error())
			return
		}
		if resp.AssetID == "" {
			_ = r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, "failed", "report inventory: control plane returned no canonical asset id")
			return
		}
		if _, err := r.store.PersistAssetBinding(cred, resp.AssetID); err != nil {
			log.Printf("order %s: persist canonical asset binding: %v", o.ID, err)
			_ = r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, "failed", "persist canonical asset binding: "+err.Error())
			return
		}
	} else if err := r.api.SendHostInventory(ctx, cred.Token, inv); err != nil {
		log.Printf("order %s: report inventory: %v", o.ID, err)
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, "failed", "report inventory: "+err.Error())
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
	if err := r.api.SubmitResult(ctx, cred.Token, o.ID, o.LeaseID, status, summary(inv)); err != nil {
		log.Printf("order %s: submit result: %v", o.ID, err)
	}
}

func (r *runner) handleResponseHalt(ctx context.Context, cred fleetclient.Credential, order fleetclient.Order) {
	if r.response == nil || order.ResponseHalt == nil || order.AssetID == "" || cred.AssetID == "" || order.AssetID != cred.AssetID ||
		order.ResponseHalt.CommandID.String() != order.ID || order.ResponseHalt.AttemptKey != order.IdempotencyKey ||
		order.ResponseHalt.AgentID.String() != cred.AgentID || order.ResponseHalt.AssetID.String() != cred.AssetID {
		_ = r.api.SubmitResult(ctx, cred.Token, order.ID, order.LeaseID, "failed", "response halt identity binding mismatch")
		return
	}
	if err := r.api.Progress(ctx, cred.Token, order.ID, order.LeaseID); err != nil {
		log.Printf("order %s: response halt progress: %v", order.ID, err)
		return
	}
	if err := r.response.ExecuteHaltCommand(ctx, *order.ResponseHalt, order.LeaseID, order.LeaseUntil); err != nil {
		_ = r.api.SubmitResult(ctx, cred.Token, order.ID, order.LeaseID, "failed", "response halt rejected")
		return
	}
	if err := r.api.SubmitResult(ctx, cred.Token, order.ID, order.LeaseID, "succeeded", "response halt fence persisted"); err != nil {
		log.Printf("order %s: submit response halt result: %v", order.ID, err)
	}
}

func (r *runner) handleResponse(ctx context.Context, cred fleetclient.Credential, order fleetclient.Order) {
	if r.response == nil || order.ResponseCommand == nil {
		_ = r.api.SubmitResult(ctx, cred.Token, order.ID, order.LeaseID, "failed", "response execution capability is not configured")
		return
	}
	if order.AssetID == "" || cred.AssetID == "" || order.AssetID != cred.AssetID ||
		order.ResponseCommand.CommandID.String() != order.ID || order.ResponseCommand.AttemptKey != order.IdempotencyKey ||
		order.ResponseCommand.AgentID.String() != cred.AgentID || order.ResponseCommand.AssetID.String() != cred.AssetID {
		_ = r.api.SubmitResult(ctx, cred.Token, order.ID, order.LeaseID, "failed", "response command identity binding mismatch")
		return
	}
	// Unlike inventory collection, a response command must not cross the side-effect boundary unless the
	// control plane has durably moved this exact addressed order to running.
	if err := r.api.Progress(ctx, cred.Token, order.ID, order.LeaseID); err != nil {
		log.Printf("order %s: response progress: %v", order.ID, err)
		return
	}
	result, err := r.response.Execute(ctx, *order.ResponseCommand, order.LeaseID, order.LeaseUntil)
	if err != nil {
		if result.State == fleetagent.ResponseExecutionOutcomeUnknown {
			if submitErr := r.submitResponseResult(ctx, cred, order.ID, result); submitErr != nil {
				log.Printf("order %s: submit ambiguous response result: %v", order.ID, submitErr)
			}
		}
		return
	}
	if result.State != fleetagent.ResponseExecutionApplied {
		_ = r.api.SubmitResult(ctx, cred.Token, order.ID, order.LeaseID, "failed", "response execution did not produce an applied outcome")
		return
	}
	if err := r.submitResponseResult(ctx, cred, order.ID, result); err != nil {
		log.Printf("order %s: submit response result: %v", order.ID, err)
	}
}

func (r *runner) flushResponseResults(ctx context.Context, cred fleetclient.Credential) error {
	if r.response == nil {
		return nil
	}
	entries, err := r.response.PendingResults(ctx)
	if err != nil {
		return fmt.Errorf("load response result outbox: %w", err)
	}
	for _, entry := range entries {
		if entry.Result == nil {
			return fmt.Errorf("response result outbox contains no terminal result for %s", entry.Command.AttemptKey)
		}
		if err := r.submitResponseResult(ctx, cred, entry.Command.CommandID.String(), *entry.Result); err != nil {
			return fmt.Errorf("submit response result outbox %s: %w", entry.Command.AttemptKey, err)
		}
	}
	return nil
}

func (r *runner) submitResponseResult(ctx context.Context, cred fleetclient.Credential, orderID string, result fleetagent.ResponseExecutionResult) error {
	status := string(workorder.StateFailed)
	reason := "response execution outcome requires reconciliation"
	if result.State == fleetagent.ResponseExecutionApplied {
		status = string(workorder.StateSucceeded)
		reason = "response command applied; awaiting independent verification"
	} else if result.State != fleetagent.ResponseExecutionOutcomeUnknown {
		return fmt.Errorf("response result is not terminal")
	}
	request := fleetclient.ResponseResultRequest{
		Status: status, Reason: reason, AttemptKey: result.AttemptKey,
		CommandDigest: result.CommandDigest, ExecutionState: result.State, ObservedRadius: result.ObservedRadius,
		AffectedCount: result.AffectedCount, AlreadyApplied: result.AlreadyApplied, CompletedAt: result.CompletedAt,
		LeaseID: result.LeaseID,
	}
	if err := r.api.SubmitResponseResult(ctx, cred.Token, orderID, request); err != nil {
		return err
	}
	return r.response.AcknowledgeResult(ctx, result.AttemptKey, result.CommandDigest)
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
