//go:build linux

package responsefleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/file"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responseactuator"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsejournal"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsekey"
	responseobserverinfra "github.com/KKloudTarus/synapse-ce/internal/infrastructure/responseobserver"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/signing"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/coveragewindow"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/endpointstate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseexecute"
	responseobserveruc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseobserver"
	responseverificationingest "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseverificationingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	responseuc "github.com/KKloudTarus/synapse-ce/internal/usecase/response"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

const nativeSagaTenantID shared.ID = "native-saga-tenant"

// TestNativeGovernedResponseSaga composes the control-plane and endpoint response seams without
// manufacturing a result: a real, non-root no-argument probe is pinned by Registry and stopped by Actuator.
//
// The observer's report and its target telemetry are independently purpose-signed and admitted through
// their production paths. Target telemetry is additionally bound to the live observer work order, so the
// observer's assignment does not relabel its general primary-host telemetry. The process-exit telemetry
// projects into the authoritative endpoint timeline and derives fixed-window process coverage before
// verification is attempted.
func TestNativeGovernedResponseSaga(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skipf("live Registry/Actuator response requires root; uid=%d", os.Geteuid())
	}

	ctx, cancel := context.WithTimeout(shared.WithTenant(context.Background(), nativeSagaTenantID), 20*time.Second)
	defer cancel()
	clock := idgen.SystemClock{}
	auditLog := file.NewAuditLog(filepath.Join(t.TempDir(), "response-audit.jsonl"))

	registry, err := responseactuator.NewRegistry()
	if err != nil {
		t.Skipf("live Registry/Actuator response is unavailable: %v", err)
	}
	defer func() { _ = registry.Close() }()

	assetID, observerHostID := shared.ID("native-asset"), shared.ID("native-observer-host")
	executorID, observerID := shared.ID("native-executor"), shared.ID("native-observer")
	probe, event, processID := nativeSagaProcess(t, assetID)
	defer probe.stop(t)
	childExited := make(chan error, 1)
	go func() { childExited <- probe.command.Wait() }()
	registry.ObserveProcess(assetID, "native-boot", event)

	engagements := memory.NewEngagementRepository()
	eng := nativeSagaEngagement(t, clock.Now(), processID)
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	guard, err := execution.NewGuard(engagements, clock, auditLog)
	if err != nil {
		t.Fatal(err)
	}
	approvalService, err := approval.NewService(memory.NewApprovalStore(), auditLog, clock, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	evidenceService, evidencePublicKey := nativeSagaEvidence(t, auditLog, clock)
	gate, err := safety.NewGate(guard, approvalService, evidenceService)
	if err != nil {
		t.Fatal(err)
	}

	workStore := memory.NewWorkOrderStore()
	workSigner, err := worksign.New([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	work, err := fleetwork.NewService(workStore, workSigner, auditLog, clock, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	work.SetExecutionAuthorizer(guard)

	agents := memory.NewFleetAgentStore()
	nativeSagaAddAgent(t, ctx, agents, executorID, assetID, []string{workorder.CapabilityResponseProcess}, clock.Now())
	nativeSagaAddAgent(t, ctx, agents, observerID, observerHostID, []string{workorder.CapabilityResponseObserve}, clock.Now())
	bindings := memory.NewTelemetryTransportStore()
	for agentID, boundAssetID := range map[shared.ID]shared.ID{executorID: assetID, observerID: observerHostID} {
		if err := bindings.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{
			TenantID: nativeSagaTenantID, AgentID: agentID, AssetID: boundAssetID, UpdatedAt: clock.Now(),
		}); err != nil {
			t.Fatalf("bind telemetry asset for %s: %v", agentID, err)
		}
	}

	commandSigner, commandResolver := nativeSagaCommandTrust(t, clock.Now())
	executor, err := New(work, agents, bindings, commandSigner, clock, Config{
		PollInterval: time.Millisecond, AgentStaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := responsejournal.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	actuator, err := responseactuator.New(registry)
	if err != nil {
		t.Fatal(err)
	}
	endpointExecutor, err := responseexecute.NewService(executorID, assetID, commandResolver, journal, actuator, clock)
	if err != nil {
		t.Fatal(err)
	}

	responseStore := memory.NewResponseStore()
	observations := memory.NewResponseVerificationStore()
	timeline := memory.NewEndpointTimelineStore()
	coverage := memory.NewCoverageWindowStore()
	observerKeys := memory.NewAgentSigningKeyStore()
	sensorStates := memory.NewSensorStateStore()
	privacyPolicies := memory.NewPrivacyPolicyStore()
	privacyAssignment, err := privacy.NewAssignment(nativeSagaTenantID, privacy.DefaultPolicy(), "operator-alice", clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := privacyPolicies.PutPrivacyPolicy(ctx, privacyAssignment); err != nil {
		t.Fatalf("store telemetry privacy policy: %v", err)
	}
	endpointTimeline, err := endpointstate.NewService(timeline)
	if err != nil {
		t.Fatal(err)
	}
	coverageService, err := coveragewindow.NewService(sensorStates, bindings, bindings, coverage, clock)
	if err != nil {
		t.Fatal(err)
	}
	coverageReconciler, err := coveragewindow.NewReconciler(coverageService, time.Millisecond, coveragewindow.DefaultMaxAffectedWindows)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := responseuc.NewTelemetryEffectVerifier("control-plane:response-verifier", observations, observations, timeline, coverage, evidenceService)
	if err != nil {
		t.Fatal(err)
	}
	observerBindings := memory.NewResponseObserverBindingStore()
	observerAssignment, err := responseobserveruc.NewService(observerBindings, agents, bindings, auditLog, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observerAssignment.Assign(ctx, responseobserveruc.AssignInput{
		TenantID: nativeSagaTenantID, AgentID: observerID, AssetID: assetID, Actor: "operator-alice",
		ExpiresAt: clock.Now().Add(time.Minute), ExpectedVersion: 0,
	}); err != nil {
		t.Fatalf("assign independent observer: %v", err)
	}
	observerAwareBindings, err := responseobserverinfra.NewBindingResolver(bindings, observerBindings, clock)
	if err != nil {
		t.Fatal(err)
	}
	telemetryService, err := telemetryingest.NewService(bindings, observerKeys, privacyPolicies, auditLog, clock)
	if err != nil {
		t.Fatal(err)
	}
	telemetryService.SetAssetBindingResolver(observerAwareBindings)

	telemetryService.SetSensorStateStore(sensorStates)
	telemetryService.SetCoverageReconciler(coverageReconciler)
	telemetryService.SetEndpointTimeline(endpointTimeline)
	dispatcher, err := NewObserverDispatcher(work, agents, observerBindings, clock, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	receiptBuilder, err := NewTargetEvidenceReceiptBuilder(bindings, timeline, coverage, observations, clock)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.SetTargetEvidenceReceiptBuilder(receiptBuilder)
	verifier.SetObservationDispatcher(dispatcher)
	responseService, err := responseuc.NewService(gate, executor, responseStore, auditLog, clock, verifier, evidenceService, evidencePublicKey, observations, observations, observerKeys)
	if err != nil {
		t.Fatal(err)
	}
	incidents := memory.NewIncidentEventStore()
	incidentService, err := incidentuc.NewService(incidents)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incidentService.Append(ctx, "native-incident", 0, []incident.IncidentEvent{{
		IncidentID: "native-incident", Kind: incident.EventCreated, At: clock.Now(), Actor: "correlator",
		AssetID: assetID, EngagementID: eng.ID, Title: "native test process", Severity: shared.SeverityHigh,
	}}); err != nil {
		t.Fatalf("create incident: %v", err)
	}
	coordinator, err := responseuc.NewIncidentCoordinator(responseService, incidentService, clock)
	if err != nil {
		t.Fatal(err)
	}

	action, err := rdom.NewAction("native-stop", rdom.KindStopProcess, processID)
	if err != nil {
		t.Fatal(err)
	}
	target := engagement.Target{Kind: engagement.TargetCloudAccount, Value: processID.String()}
	fingerprint := responsesaga.TargetFingerprint{
		Kind: responsesaga.FingerprintProcess, ProcessAssetID: assetID, ProcessEntityID: processID,
	}

	if _, err := coordinator.Apply(ctx, "native-incident", action, target, fingerprint, "operator-alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("unapproved response error=%v, want pending approval", err)
	}
	if _, err := approvalService.Decide(ctx, "operator-bob", action.ID, true, "confirmed test containment"); err != nil {
		t.Fatalf("human approval: %v", err)
	}

	// Re-enter through the response service after the human decision. The coordinator's first pending call
	// already durably recorded IncidentResponseRequested; its second call below adds ResponseVerified.
	endpointDone := make(chan error, 1)
	go nativeSagaRunEndpointWorker(ctx, work, endpointExecutor, executorID, func(ctx context.Context, command fleetagent.ResponseCommand) error {
		if err := nativeSagaExpectTermination(ctx, childExited); err != nil {
			return err
		}
		return nativeSagaIngestTargetProcess(ctx, telemetryService, observerKeys, timeline, coverage, executorID, assetID, privacyAssignment.Digest, command, event, "", clock)
	}, endpointDone)
	observerDone := make(chan error, 1)
	ingestService, err := responseverificationingest.NewService(observations, observations, responseStore, work, observerAwareBindings, observerKeys, auditLog, clock)
	if err != nil {
		t.Fatal(err)
	}
	go nativeSagaRunObserverWorker(ctx, work, ingestService, observerKeys, observerID, assetID, clock, observerDone)

	record, err := responseService.Apply(ctx, eng.ID, action, target, fingerprint, "operator-bob")
	if !errors.Is(err, responseuc.ErrVerificationPending) || record.State != responseuc.StateApplied || record.Verification != responseuc.VerificationPending {
		t.Fatalf("applied response = %+v, err=%v; want applied and verification pending", record, err)
	}
	if err := <-endpointDone; err != nil {
		t.Fatalf("endpoint worker: %v", err)
	}
	if err := <-observerDone; err != nil {
		t.Fatalf("observer worker: %v", err)
	}
	// The live agent would receive the canonical exit event through its durable telemetry path. The test
	// supplies that observed fact only after endpoint execution has completed; this preserves the Registry's
	// prerequisite that restart waits for the original pidfd-confirmed identity to exit.
	exitEvent := event
	exitEvent.Kind = "exit"
	registry.ObserveProcess(assetID, "native-boot", exitEvent)

	record, err = coordinator.Apply(ctx, "native-incident", action, target, fingerprint, "operator-alice")
	if err != nil {
		t.Fatalf("verify response saga: %v", err)
	}
	if record.State != responseuc.StateApplied || record.Verification != responseuc.VerificationSucceeded {
		t.Fatalf("terminal response=%+v, want applied/verified", record)
	}

	nativeSagaAssertTerminal(t, ctx, workStore, work, journal, endpointExecutor, observations, responseStore, evidenceService, incidentService, action.ID, executorID, observerID)

	// The restart is a separate governed action with a distinct human decision. The Registry receives only
	// the catalogued reversal argv and independently descriptor-pins the no-argument test helper.
	if _, err := responseService.Revert(ctx, action.ID, target, fingerprint, "operator-alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("unapproved reversal error=%v, want pending approval", err)
	}
	reversalID := shared.ID("revert:" + action.ID.String())
	if _, err := approvalService.Decide(ctx, "operator-carol", reversalID, true, "restore disposable process"); err != nil {
		t.Fatalf("human reversal approval: %v", err)
	}
	rollbackEndpointDone := make(chan error, 1)
	go nativeSagaRunEndpointWorker(ctx, work, endpointExecutor, executorID, func(ctx context.Context, command fleetagent.ResponseCommand) error {
		restarted, replacementProcessID, err := nativeSagaFindRestartedProbe(ctx, probe, event.PID, assetID)
		if err != nil {
			return err
		}
		return nativeSagaIngestTargetProcess(ctx, telemetryService, observerKeys, timeline, coverage, executorID, assetID, privacyAssignment.Digest, command, restarted, replacementProcessID, clock)
	}, rollbackEndpointDone)

	record, err = responseService.Revert(ctx, action.ID, target, fingerprint, "operator-alice")
	if !errors.Is(err, responseuc.ErrVerificationPending) || record.State != responseuc.StateApplied {
		select {
		case workerErr := <-rollbackEndpointDone:
			t.Fatalf("applied reversal=%+v, err=%v endpoint-worker=%v; want applied and verification pending", record, err, workerErr)
		default:
			t.Fatalf("applied reversal=%+v, err=%v endpoint-worker-still-running; want applied and verification pending", record, err)
		}
	}
	if err := <-rollbackEndpointDone; err != nil {
		t.Fatalf("rollback endpoint worker: %v", err)
	}
	rollbackObserverDone := make(chan error, 1)
	go nativeSagaRunObserverWorker(ctx, work, ingestService, observerKeys, observerID, assetID, clock, rollbackObserverDone)
	if err := <-rollbackObserverDone; err != nil {
		t.Fatalf("rollback observer worker: %v", err)
	}
	record, err = responseService.Revert(ctx, action.ID, target, fingerprint, "operator-alice")
	if err != nil {
		t.Fatalf("verify rollback saga: %v", err)
	}
	if record.State != responseuc.StateReverted || record.Verification != responseuc.VerificationSucceeded {
		t.Fatalf("terminal rollback=%+v, want reverted with verified original response", record)
	}
	nativeSagaAssertRolledBack(t, ctx, workStore, work, journal, endpointExecutor, observations, responseStore, evidenceService, incidentService, action.ID, executorID, observerID)
}

func nativeSagaEngagement(t *testing.T, now time.Time, processID shared.ID) *engagement.Engagement {
	t.Helper()
	eng, err := engagement.New("native-engagement", nativeSagaTenantID, "native response saga", "test client", now)
	if err != nil {
		t.Fatal(err)
	}
	from, until := now.Add(-time.Minute), now.Add(time.Minute)
	if err := eng.SetAuthorizationWindow(&from, &until, "UTC", now); err != nil {
		t.Fatal(err)
	}
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: processID.String()}}}
	return eng
}

func nativeSagaEvidence(t *testing.T, auditLog ports.AuditLogger, clock ports.Clock) (*evidence.Service, string) {
	t.Helper()
	service, err := evidence.NewService(memory.NewEvidenceStore(), nil, auditLog, clock, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.NewEd25519Signer(nil)
	if err != nil {
		t.Fatal(err)
	}
	service.SetSigner(signer.WithContext(evdom.AttestationContextEvidence))
	return service, signer.PublicKey()
}

func nativeSagaAddAgent(t *testing.T, ctx context.Context, agents *memory.FleetAgentStore, id, assetID shared.ID, capabilities []string, now time.Time) {
	t.Helper()
	entry, err := fleetagent.NewAgent(id, nativeSagaTenantID, assetID.String(), "linux", "native", "native", capabilities, "test-token-hash", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := agents.CreateAgent(ctx, entry); err != nil {
		t.Fatal(err)
	}
}

func nativeSagaCommandTrust(t *testing.T, now time.Time) (*responsekey.Signer, *responsekey.Resolver) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := responsekey.NewSigner(private, now.Add(-time.Minute), now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	key := signer.PublicKey()
	bundle, err := json.Marshal(struct {
		Version int `json:"version"`
		Keys    []struct {
			KeyID     string    `json:"key_id"`
			PublicKey string    `json:"public_key"`
			NotBefore time.Time `json:"not_before"`
			NotAfter  time.Time `json:"not_after"`
			RevokedAt time.Time `json:"revoked_at,omitempty"`
		} `json:"keys"`
	}{
		Version: 1,
		Keys: []struct {
			KeyID     string    `json:"key_id"`
			PublicKey string    `json:"public_key"`
			NotBefore time.Time `json:"not_before"`
			NotAfter  time.Time `json:"not_after"`
			RevokedAt time.Time `json:"revoked_at,omitempty"`
		}{{
			KeyID: key.KeyID, PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey), NotBefore: key.NotBefore, NotAfter: key.NotAfter,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := responsekey.New(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return signer, resolver
}

const nativeSagaProbeUIDGID = 65534

type nativeSagaProbe struct {
	command *exec.Cmd
	binary  string
	workDir string
	pidFile string
	ready   string
}

func nativeSagaProcess(t *testing.T, assetID shared.ID) (nativeSagaProbe, detection.ProcessEvent, shared.ID) {
	t.Helper()
	probe := nativeSagaRestartProbe(t)
	if err := probe.command.Start(); err != nil {
		t.Skipf("cannot start disposable non-root actuator target: %v", err)
	}
	if err := nativeSagaWaitForProbeReady(t, probe.ready); err != nil {
		_ = probe.command.Process.Kill()
		t.Fatal(err)
	}
	startNanos, err := nativeSagaProcessStartNanos(probe.command.Process.Pid)
	if err != nil {
		_ = probe.command.Process.Kill()
		t.Fatal(err)
	}
	event := detection.ProcessEvent{
		Kind: "exec", PID: probe.command.Process.Pid, PPID: os.Getpid(), StartTimeNanos: startNanos, Comm: "native-probe", Path: probe.binary,
	}
	return probe, event, telemetry.ProcessEntityID(assetID, "native-boot", event.PID, event.StartTimeNanos)
}

func nativeSagaWaitForProbeReady(t *testing.T, ready string) error {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	return fmt.Errorf("disposable probe did not publish readiness")
}

func nativeSagaRestartProbe(t *testing.T) nativeSagaProbe {
	t.Helper()
	// testing.T.TempDir is nested under a root-owned parent the unprivileged probe cannot traverse.
	// Create a private, non-root-owned directory directly under /tmp so Registry can descriptor-pin it.
	workDir, err := os.MkdirTemp("", "synapse-native-saga-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	if err := os.Chmod(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(workDir, nativeSagaProbeUIDGID, nativeSagaProbeUIDGID); err != nil {
		t.Fatal(err)
	}
	buildDir, err := os.MkdirTemp("", "synapse-native-saga-build-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(buildDir) })
	source := filepath.Join(buildDir, "probe.go")
	binary := filepath.Join(workDir, "probe")
	pidFile := filepath.Join(workDir, "pid")
	ready := filepath.Join(workDir, "ready")
	program := `package main
import (
 "os"
 "strconv"
 "time"
)
func main() {
 _ = os.WriteFile("pid", []byte(strconv.Itoa(os.Getpid())), 0600)
 _ = os.WriteFile("ready", []byte("ready"), 0600)
 for { time.Sleep(time.Second) }
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", binary, source)
	build.Env = append([]string{}, os.Environ()...)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native response restart probe: %v: %s", err, output)
	}
	if err := os.Chmod(binary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(binary, nativeSagaProbeUIDGID, nativeSagaProbeUIDGID); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary)
	command.Dir = workDir
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nativeSagaProbeUIDGID, Gid: nativeSagaProbeUIDGID}}
	return nativeSagaProbe{command: command, binary: binary, workDir: workDir, pidFile: pidFile, ready: ready}
}

func (p nativeSagaProbe) stop(t *testing.T) {
	t.Helper()
	if p.command != nil && p.command.Process != nil {
		_ = p.command.Process.Kill()
	}
	if data, err := os.ReadFile(p.pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 && pid != os.Getpid() {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	// Registry deliberately does not retain a child handle for a best-effort restart. The test owns this
	// uniquely named, non-root work directory, so remove every remaining probe using it before TempDir cleanup.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		workingDir, err := os.Readlink(filepath.Join("/proc", entry.Name(), "cwd"))
		if err == nil && workingDir == p.workDir {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func nativeSagaFindRestartedProbe(ctx context.Context, probe nativeSagaProbe, originalPID int, assetID shared.ID) (detection.ProcessEvent, shared.ID, error) {
	for {
		data, err := os.ReadFile(probe.pidFile)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if parseErr == nil && pid > 1 && pid != originalPID {
				if _, err := os.Stat(probe.ready); err == nil {
					startNanos, err := nativeSagaProcessStartNanos(pid)
					if err == nil {
						event := detection.ProcessEvent{
							Kind: "exec", PID: pid, PPID: os.Getpid(), StartTimeNanos: startNanos, Comm: "native-probe", Path: probe.binary,
						}
						return event, telemetry.ProcessEntityID(assetID, "native-boot", event.PID, event.StartTimeNanos), nil
					}
				}
			}
		}
		if !nativeSagaPause(ctx) {
			return detection.ProcessEvent{}, "", fmt.Errorf("observe restarted probe: %w", ctx.Err())
		}
	}
}

func nativeSagaProcessStartNanos(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, fmt.Errorf("read child process stat: %w", err)
	}
	boundary := strings.LastIndexByte(string(data), ')')
	if boundary < 0 {
		return 0, fmt.Errorf("child process stat has no command boundary")
	}
	fields := strings.Fields(string(data[boundary+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("child process stat is truncated")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse child process start tick: %w", err)
	}
	return ticks * 10_000_000, nil
}

func nativeSagaRunEndpointWorker(ctx context.Context, work *fleetwork.Service, service *responseexecute.Service, agentID shared.ID, observe func(context.Context, fleetagent.ResponseCommand) error, done chan<- error) {
	for {
		orders, err := work.Claim(ctx, "agent:"+agentID.String(), nativeSagaTenantID, agentID, 1)
		if err != nil {
			done <- err
			return
		}
		if len(orders) == 0 {
			if !nativeSagaPause(ctx) {
				done <- ctx.Err()
				return
			}
			continue
		}
		order := orders[0]
		if order.ResponseCommand == nil || order.ResponseCommand.Signature == "" {
			done <- fmt.Errorf("claimed order %s has no signed response command", order.ID)
			return
		}
		if err := work.Transition(ctx, "agent:"+agentID.String(), nativeSagaTenantID, order.ID, order.LeaseID, workorder.StateRunning, ""); err != nil {
			done <- err
			return
		}
		result, err := service.Execute(ctx, *order.ResponseCommand, order.LeaseID, order.LeaseUntil)
		if err != nil {
			done <- fmt.Errorf("execute %s response command: %w", order.ID, err)
			return
		}
		if observe != nil {
			if err := observe(ctx, *order.ResponseCommand); err != nil {
				done <- fmt.Errorf("ingest target process evidence: %w", err)
				return
			}
		}
		if err := work.CompleteResponse(ctx, "agent:"+agentID.String(), nativeSagaTenantID, order.ID, result, "registry actuator applied command"); err != nil {
			done <- err
			return
		}
		if err := service.AcknowledgeResult(ctx, result.AttemptKey, result.CommandDigest); err != nil {
			done <- err
			return
		}
		done <- nil
		return
	}
}

func nativeSagaRunObserverWorker(ctx context.Context, work *fleetwork.Service, ingest *responseverificationingest.Service, keys *memory.AgentSigningKeyStore, agentID, assetID shared.ID, clock ports.Clock, done chan<- error) {
	for {
		orders, err := work.Claim(ctx, "agent:"+agentID.String(), nativeSagaTenantID, agentID, 1)
		if err != nil {
			done <- err
			return
		}
		if len(orders) == 0 {
			if !nativeSagaPause(ctx) {
				done <- ctx.Err()
				return
			}
			continue
		}
		order := orders[0]
		if order.ResponseObserve == nil {
			done <- fmt.Errorf("claimed order %s has no response observation request", order.ID)
			return
		}
		if err := work.Transition(ctx, "agent:"+agentID.String(), nativeSagaTenantID, order.ID, order.LeaseID, workorder.StateRunning, ""); err != nil {
			done <- err
			return
		}
		if err := nativeSagaIngestObserverReport(ctx, ingest, keys, *order.ResponseObserve, agentID, assetID, clock); err != nil {
			done <- fmt.Errorf("ingest response observation: %w", err)
			return
		}
		if err := work.Transition(ctx, "agent:"+agentID.String(), nativeSagaTenantID, order.ID, order.LeaseID, workorder.StateSucceeded, "signed observation accepted"); err != nil {
			done <- err
			return
		}
		done <- nil
		return
	}
}

func nativeSagaIngestObserverReport(ctx context.Context, ingest *responseverificationingest.Service, keys *memory.AgentSigningKeyStore, request fleetagent.ResponseObservationRequest, agentID, assetID shared.ID, clock ports.Clock) error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	observedAt := clock.Now().UTC().Truncate(time.Microsecond)
	for !observedAt.After(request.AttemptedAt) {
		if !nativeSagaPause(ctx) {
			return ctx.Err()
		}
		observedAt = clock.Now().UTC().Truncate(time.Microsecond)
	}
	key, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeResponseResult, public, observedAt.Add(-time.Minute), observedAt.Add(time.Minute))
	if err != nil {
		return err
	}
	if err := keys.Register(ctx, key); err != nil {
		return err
	}
	replacementProcessEntityID := shared.ID("")
	if request.Reversal {
		replacementProcessEntityID = request.Target.ProcessEntityID + "-replacement"
	}
	report := fleetagent.ResponseVerificationReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: request.RequestID, AgentID: agentID, HostID: agentID,
		AgentSessionID: fleetagent.CanonicalSessionID(agentID), AssetID: assetID, EngagementID: request.EngagementID,
		ActionID: request.ActionID, ActionDigest: request.ActionDigest, AttemptKey: request.AttemptKey,
		ReceiptID: request.ReceiptID, ReceiptDigest: request.ReceiptDigest, VerificationChallenge: request.VerificationChallenge, Target: request.Target, Reversal: request.Reversal,
		ObservedAt: observedAt, ReplacementProcessEntityID: replacementProcessEntityID, KeyID: key.KeyID,
	}
	report.Signature = fleetagent.SignResponseVerification(private, report)
	_, err = ingest.Ingest(ctx, agentID, report)
	return err
}

func nativeSagaIngestTargetProcess(ctx context.Context, ingest *telemetryingest.Service, keys *memory.AgentSigningKeyStore, timeline *memory.EndpointTimelineStore, coverage *memory.CoverageWindowStore, agentID, assetID shared.ID, privacyDigest string, command fleetagent.ResponseCommand, event detection.ProcessEvent, replacementProcessID shared.ID, clock ports.Clock) error {
	observedAt := clock.Now().UTC().Truncate(time.Microsecond)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	key, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeTelemetryBatch, public, observedAt.Add(-time.Minute), observedAt.Add(time.Minute))
	if err != nil {
		return err
	}
	if err := keys.Register(ctx, key); err != nil {
		return err
	}
	activeAt := command.IssuedAt.UTC().Truncate(time.Microsecond).Add(-time.Microsecond)
	if activeAt.IsZero() {
		activeAt = observedAt.Add(-time.Minute)
	}
	statePayload := sha256.Sum256([]byte("native-saga-process-active:" + command.AttemptKey))
	state := fleetagent.SensorStateReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		ReportID:        shared.ID("native-sensor-state:" + command.AttemptKey),
		AgentID:         agentID,
		HostID:          agentID,
		AgentSessionID:  fleetagent.CanonicalSessionID(agentID),
		AssetID:         assetID,
		Kind:            "sensor_state",
		ObservedAt:      activeAt,
		SchemaVersion:   1,
		PayloadDigest:   hex.EncodeToString(statePayload[:]),
		States: []detection.ClassCoverage{{
			Class: detection.ClassProcess, HostID: agentID, AgentID: agentID, State: detection.StateActive, Since: activeAt,
		}},
		KeyID: key.KeyID,
	}
	state.Signature = fleetagent.SignSensorState(private, state)
	if _, err := ingest.IngestSensorState(ctx, agentID, state); err != nil {
		return fmt.Errorf("ingest signed active process state: %w", err)
	}

	sessionID := fleetagent.CanonicalSessionID(agentID)
	streamID, err := fleetagent.TelemetryDeliveryStreamID(agentID, sessionID, fleetagent.PriorityP3)
	if err != nil {
		return err
	}
	bootID := shared.ID("native-boot")
	exitAt := observedAt.UTC().Truncate(time.Microsecond)
	sequence, previousSequence := uint64(1), uint64(0)
	if command.Reversal {
		sequence, previousSequence = 2, 1
	}
	processKind, processID := "exit", command.Target.ProcessEntityID
	if command.Reversal {
		processKind, processID = "exec", replacementProcessID
	}
	process := &telemetry.ProcessObservation{
		Kind: processKind, PID: event.PID, PPID: event.PPID, StartTimeNanos: event.StartTimeNanos,
		EntityID: processID, Comm: event.Comm, Path: event.Path, UID: nativeSagaProbeUIDGID,
	}
	payloadEvent := telemetry.TelemetryEvent{Class: detection.ClassProcess, Process: process}
	eventID := telemetry.DeriveEventID(assetID, bootID, streamID, sequence, detection.ClassProcess, exitAt.UnixNano())
	envelope := telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       eventID, EventType: payloadEvent.EventType(), EventClass: detection.ClassProcess,
		AgentID: agentID, AgentSessionID: shared.ID(sessionID), AssetID: assetID, BootID: bootID, StreamID: streamID,
		SensorID: "native-observer", SensorVersion: "test", OccurredAt: exitAt, ObservedAt: exitAt,
		Sequence: sequence, RedactionPolicyDigest: privacyDigest, Event: payloadEvent,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal signed process-exit telemetry: %w", err)
	}
	ref := fleetagent.EventRef{ID: eventID, Digest: fleetagent.TelemetryEventDigest(payload, assetID)}
	manifest := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		SchemaVersion:   telemetry.SchemaVersion,
		BatchID:         shared.ID("native-process-batch:" + command.AttemptKey), AgentID: agentID, HostID: agentID,
		AssetID: assetID, StreamID: streamID,
		Position:         fleetagent.StreamPosition{Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: sequence, Session: sessionID, Boot: fleetagent.BootID(bootID)},
		PreviousSequence: previousSequence, EventTimeMin: exitAt, EventTimeMax: exitAt,
		ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "native-saga-p3", Events: []fleetagent.EventRef{ref},
		PayloadDigest: fleetagent.TelemetryPayloadDigest([]fleetagent.EventRef{ref}), KeyID: key.KeyID,
	}
	manifest.Signature = fleetagent.SignTelemetryManifest(private, manifest)
	result, err := ingest.Ingest(ctx, agentID, telemetryingest.IngestRequest{
		Manifest: manifest,
		Events:   []telemetryingest.EventPayload{{EventID: eventID, Class: detection.ClassProcess, Payload: payload, ObservedAt: exitAt}},
	})
	if err != nil {
		return fmt.Errorf("ingest signed process-exit telemetry: %w", err)
	}
	if !result.Accepted || result.GapOpen {
		return fmt.Errorf("signed process-exit telemetry admission=%+v, want accepted without gaps", result)
	}

	kind, entityID := endpoint.TimelineProcessExit, command.Target.ProcessEntityID
	if command.Reversal {
		kind, entityID = endpoint.TimelineProcessStart, replacementProcessID
	}
	timelineEntry := endpoint.TimelineEntry{
		OccurredAt: observedAt, TenantID: nativeSagaTenantID, AssetID: assetID,
		SourceAgentID: agentID, SourceAgentSessionID: shared.ID(sessionID), EntityKind: endpoint.EntityProcess,
		EntityID: entityID, Kind: kind, EventID: eventID,
	}
	timelineEntries := []endpoint.TimelineEntry{timelineEntry}
	if command.Reversal {
		timelineEntries = append([]endpoint.TimelineEntry{{
			OccurredAt: command.IssuedAt.UTC().Truncate(time.Microsecond).Add(time.Microsecond), TenantID: nativeSagaTenantID, AssetID: assetID,
			SourceAgentID: agentID, SourceAgentSessionID: shared.ID(sessionID), EntityKind: endpoint.EntityProcess,
			EntityID: command.Target.ProcessEntityID, Kind: endpoint.TimelineProcessExit, EventID: shared.ID("native-original-exit:" + command.AttemptKey),
		}}, timelineEntries...)
	}
	if err := timeline.AppendTimeline(ctx, timelineEntries); err != nil {
		return fmt.Errorf("append authoritative process timeline: %w", err)
	}
	window := sensorstate.CoverageWindow{
		AssetID: assetID, AgentID: agentID, HostID: assetID,
		Since: command.IssuedAt.UTC().Truncate(time.Microsecond).Add(-time.Second), Until: command.NotAfter.UTC().Truncate(time.Microsecond),
		InputDigest: strings.Repeat("a", 64), CreatedAt: observedAt.Add(time.Microsecond), BatchCount: 1,
		States: []detection.ClassCoverage{{
			Class: detection.ClassProcess, HostID: assetID, AgentID: agentID,
			State: detection.StateActive, Since: command.IssuedAt.UTC().Truncate(time.Microsecond),
		}},
	}
	window.Vector = sensorstate.BuildCoverageVector(window)
	window.Revision = sensorstate.RevisionFor(window)
	if _, err := coverage.AppendCoverageWindow(ctx, window); err != nil {
		return fmt.Errorf("append authoritative process coverage: %w", err)
	}
	storedTimeline, _ := timeline.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: assetID, SourceAgentID: agentID, SourceAgentSessionID: shared.ID(sessionID), From: command.IssuedAt, To: observedAt.Add(time.Second), Limit: 10})
	storedCoverage, _ := coverage.ListCoverageWindowsBounded(ctx, ports.CoverageWindowQuery{AgentID: agentID, AssetID: assetID, HostID: assetID, Since: command.IssuedAt, Until: observedAt.Add(time.Second)}, 10)
	if len(storedTimeline) == 0 || len(storedCoverage) == 0 {
		return fmt.Errorf("authoritative process evidence was not readable: timeline=%d coverage=%d", len(storedTimeline), len(storedCoverage))
	}
	return nil
}

func nativeSagaExpectTermination(ctx context.Context, exited <-chan error) error {
	select {
	case err := <-exited:
		if err != nil && !strings.Contains(err.Error(), "signal: terminated") {
			return fmt.Errorf("wait for registry-stopped child: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func nativeSagaPause(ctx context.Context) bool {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nativeSagaAssertRolledBack(t *testing.T, ctx context.Context, store *memory.WorkOrderStore, work *fleetwork.Service, journal *responsejournal.Store, endpointExecutor *responseexecute.Service, observations *memory.ResponseVerificationStore, responses *memory.ResponseStore, evidenceService *evidence.Service, incidents *incidentuc.Service, actionID, executorID, observerID shared.ID) {
	t.Helper()
	orders, err := store.ListByTenant(ctx, nativeSagaTenantID)
	if err != nil || len(orders) != 4 {
		t.Fatalf("rollback work orders=%d err=%v, want forward/reversal executor+observer", len(orders), err)
	}
	commands, forwardCommands, reversalCommands, observationsByAttempt := 0, 0, 0, 0
	for _, order := range orders {
		if !work.Verify(order) || order.State != workorder.StateSucceeded {
			t.Fatalf("rollback work order is not signed and successful: %+v", order)
		}
		if order.ResponseCommand != nil {
			commands++
			if order.AgentID != executorID {
				t.Fatalf("response command addressed to %s, want executor %s", order.AgentID, executorID)
			}
			if order.ResponseCommand.Reversal {
				reversalCommands++
			} else {
				forwardCommands++
			}
		}
		if order.ResponseObserve != nil {
			observationsByAttempt++
			if order.AgentID != observerID || order.ResponseObserve.ObserverAgentID == executorID {
				t.Fatalf("response observation is not independently addressed: %+v", order.ResponseObserve)
			}
		}
	}
	if commands != 2 || forwardCommands != 1 || reversalCommands != 1 || observationsByAttempt != 2 {
		t.Fatalf("response orders commands=%d forward=%d reversal=%d observations=%d, want one forward/reversal command and two observations", commands, forwardCommands, reversalCommands, observationsByAttempt)
	}
	entries, err := journal.ListResponseExecutions(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("acknowledged rollback endpoint journals remained: entries=%+v err=%v", entries, err)
	}
	pending, err := endpointExecutor.PendingResults(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("rollback endpoint outbox pending=%+v err=%v", pending, err)
	}
	rollbackKey := ""
	for _, order := range orders {
		if order.ResponseCommand != nil && order.ResponseCommand.Reversal {
			rollbackKey = order.ResponseCommand.AttemptKey
			break
		}
	}
	observation, found, err := observations.GetResponseVerification(ctx, rollbackKey)
	if err != nil || !found || !observation.Report.Reversal || observation.Report.ReplacementProcessEntityID.IsZero() || observation.Report.AgentID != observerID {
		t.Fatalf("accepted rollback observation=%+v found=%t err=%v", observation, found, err)
	}
	attempt, found, err := responses.GetAttempt(ctx, rollbackKey)
	if err != nil || !found || attempt.State != responsesaga.StateRolledBack || attempt.VerificationOutcome != responsesaga.VerificationSucceeded || attempt.VerificationEvidenceID.IsZero() {
		t.Fatalf("rolled-back response attempt=%+v found=%t err=%v", attempt, found, err)
	}
	verifiedEvidence, err := evidenceService.Verify(ctx, "native-engagement")
	if err != nil || !verifiedEvidence.Intact || verifiedEvidence.Attestation == nil {
		t.Fatalf("rollback evidence chain report=%+v err=%v", verifiedEvidence, err)
	}
	linked, err := incidents.Get(ctx, "native-incident")
	if err != nil || len(linked.Responses) != 1 || linked.Responses[0].ActionID != actionID || !linked.Responses[0].Verified {
		t.Fatalf("incident rollback linkage=%+v err=%v", linked, err)
	}
}

func nativeSagaAssertTerminal(t *testing.T, ctx context.Context, store *memory.WorkOrderStore, work *fleetwork.Service, journal *responsejournal.Store, endpointExecutor *responseexecute.Service, observations *memory.ResponseVerificationStore, responses *memory.ResponseStore, evidenceService *evidence.Service, incidents *incidentuc.Service, actionID, executorID, observerID shared.ID) {
	t.Helper()
	orders, err := store.ListByTenant(ctx, nativeSagaTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 2 {
		t.Fatalf("work orders=%d, want executor and observer orders", len(orders))
	}
	var endpointOrder, observerOrder *workorder.WorkOrder
	for _, order := range orders {
		if !work.Verify(order) || order.State != workorder.StateSucceeded {
			t.Fatalf("work order is not signed and successful: %+v", order)
		}
		switch {
		case order.ResponseCommand != nil:
			endpointOrder = order
		case order.ResponseObserve != nil:
			observerOrder = order
		}
	}
	if endpointOrder == nil || observerOrder == nil || endpointOrder.AgentID != executorID || observerOrder.AgentID != observerID || observerOrder.AgentID == endpointOrder.AgentID {
		t.Fatalf("executor/observer order bindings are invalid: endpoint=%+v observer=%+v", endpointOrder, observerOrder)
	}
	entries, err := journal.ListResponseExecutions(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("acknowledged endpoint journals remained: entries=%+v err=%v", entries, err)
	}
	pending, err := endpointExecutor.PendingResults(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("endpoint outbox pending=%+v err=%v", pending, err)
	}
	observation, found, err := observations.GetResponseVerification(ctx, endpointOrder.ResponseCommand.AttemptKey)
	if err != nil || !found || observation.Report.AgentID != observerID || observation.Report.Signature == "" {
		t.Fatalf("accepted purpose-signed observer report=%+v found=%t err=%v", observation, found, err)
	}
	attempt, found, err := responses.GetAttempt(ctx, endpointOrder.ResponseCommand.AttemptKey)
	if err != nil || !found || attempt.State != responsesaga.StateVerifiedSucceeded || attempt.VerificationEvidenceID.IsZero() {
		t.Fatalf("verified response attempt=%+v found=%t err=%v", attempt, found, err)
	}
	verifiedEvidence, err := evidenceService.Verify(ctx, "native-engagement")
	if err != nil || !verifiedEvidence.Intact || verifiedEvidence.Attestation == nil {
		t.Fatalf("verification evidence chain report=%+v err=%v", verifiedEvidence, err)
	}
	linked, err := incidents.Get(ctx, "native-incident")
	if err != nil || len(linked.Responses) != 1 || linked.Responses[0].ActionID != actionID || !linked.Responses[0].Verified {
		t.Fatalf("incident terminal response=%+v err=%v", linked, err)
	}
}
