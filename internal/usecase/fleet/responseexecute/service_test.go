package responseexecute

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type executeClock struct{ at time.Time }

func (c executeClock) Now() time.Time { return c.at }

type executeKeys struct {
	public    ed25519.PublicKey
	notAfter  time.Time
	revokedAt time.Time
}

func (k executeKeys) ResolveResponseCommandKey(context.Context, string) (fleetagent.ResponseCommandSigningKey, error) {
	notAfter := k.notAfter
	if notAfter.IsZero() {
		notAfter = time.Unix(1<<31, 0).UTC()
	}
	return fleetagent.ResponseCommandSigningKey{
		KeyID: evidence.KeyFingerprint(k.public), PublicKey: k.public,
		NotBefore: time.Unix(0, 0).UTC(), NotAfter: notAfter, RevokedAt: k.revokedAt,
	}, nil
}

type sequenceClock struct {
	times []time.Time
	n     int
}

func (c *sequenceClock) Now() time.Time {
	if c.n >= len(c.times) {
		return c.times[len(c.times)-1]
	}
	at := c.times[c.n]
	c.n++
	return at
}

type executeJournal struct {
	entry      fleetagent.ResponseExecutionJournalEntry
	found      bool
	saves      []fleetagent.ResponseExecutionState
	failSave   fleetagent.ResponseExecutionState
	failDelete bool
	afterSave  func(fleetagent.ResponseExecutionState)
	generation int64
	halted     bool
}

func (j *executeJournal) CurrentResponseHaltFence(context.Context) (int64, bool, error) {
	return j.generation, j.halted, nil
}

func (j *executeJournal) RaiseResponseHaltFence(_ context.Context, generation int64) error {
	if generation > j.generation {
		j.generation = generation
	}
	j.halted = true
	return nil
}

func (j *executeJournal) LoadResponseExecution(context.Context, string) (fleetagent.ResponseExecutionJournalEntry, bool, error) {
	return j.entry, j.found, nil
}

func (j *executeJournal) ListResponseExecutions(context.Context) ([]fleetagent.ResponseExecutionJournalEntry, error) {
	if !j.found {
		return nil, nil
	}
	return []fleetagent.ResponseExecutionJournalEntry{j.entry}, nil
}

func (j *executeJournal) SaveResponseExecution(_ context.Context, entry fleetagent.ResponseExecutionJournalEntry) error {
	if entry.State == j.failSave {
		return errors.New("journal unavailable")
	}
	j.entry, j.found = entry, true
	j.saves = append(j.saves, entry.State)
	if j.afterSave != nil {
		j.afterSave(entry.State)
	}
	return nil
}

func (j *executeJournal) DeleteResponseExecution(context.Context, string) error {
	if j.failDelete {
		return errors.New("journal unavailable")
	}
	j.entry, j.found = fleetagent.ResponseExecutionJournalEntry{}, false
	return nil
}

type executeActuator struct {
	journal *executeJournal
	calls   int
	err     error
	started chan struct{}
}

func (a *executeActuator) ExecuteResponse(ctx context.Context, _ fleetagent.ResponseCommand) (ActuatorOutcome, error) {
	a.calls++
	if !a.journal.found || a.journal.entry.State != fleetagent.ResponseExecutionExecuting {
		return ActuatorOutcome{}, errors.New("side effect started before executing journal was durable")
	}
	if a.started != nil {
		close(a.started)
		<-ctx.Done()
		return ActuatorOutcome{}, ctx.Err()
	}
	return ActuatorOutcome{ObservedRadius: offensivepolicy.RadiusStateChanging, AffectedCount: 1}, a.err
}

func executeCommand(t *testing.T) (fleetagent.ResponseCommand, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(4_000_000, 0).UTC()
	command := fleetagent.ResponseCommand{
		ProtocolVersion: fleetagent.ResponseCommandProtocolVersion, CommandID: "command-1", TenantID: "tenant-1",
		AgentID: "executor-1", AssetID: "asset-1", EngagementID: "eng-1", Action: action,
		ActionDigest: digest, AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("a", 64),
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetDomain, Value: "process-1"},
		Target:              responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		HaltGeneration:      0, IssuedAt: now.Add(-time.Second), NotAfter: now.Add(time.Minute), SigningKeyID: evidence.KeyFingerprint(public),
	}
	command.Signature = fleetagent.SignResponseCommand(private, command)
	return command, public, private, now
}

func TestExecuteHaltCommandVerifiesAndPersistsFence(t *testing.T) {
	_, public, private, now := executeCommand(t)
	journal := &executeJournal{}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, &executeActuator{journal: journal}, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	command := fleetagent.ResponseHaltCommand{
		ProtocolVersion: fleetagent.ResponseHaltCommandProtocolVersion, CommandID: "halt-1", TenantID: "tenant-1",
		AgentID: "executor-1", AssetID: "asset-1", Generation: 3, AttemptKey: "halt-attempt-1",
		IssuedAt: now.Add(-time.Second), NotAfter: now.Add(time.Minute), SigningKeyID: evidence.KeyFingerprint(public),
	}
	command.Signature = fleetagent.SignResponseHaltCommand(private, command)
	if err := service.ExecuteHaltCommand(context.Background(), command, "halt-lease", command.NotAfter); err != nil {
		t.Fatalf("execute halt: %v", err)
	}
	if journal.generation != 3 || !journal.halted {
		t.Fatalf("halt fence generation=%d halted=%t", journal.generation, journal.halted)
	}
	tampered := command
	tampered.Generation = 4
	if err := service.ExecuteHaltCommand(context.Background(), tampered, "halt-lease", command.NotAfter); !errors.Is(err, fleetagent.ErrBadResponseCommandSignature) {
		t.Fatalf("tampered halt command error=%v", err)
	}
}

func TestExecuteJournalsBeforeSideEffectAndDeduplicates(t *testing.T) {
	command, public, _, now := executeCommand(t)
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	second, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if first != second || actuator.calls != 1 {
		t.Fatalf("result retry=%+v first=%+v actuator calls=%d", second, first, actuator.calls)
	}
	want := []fleetagent.ResponseExecutionState{
		fleetagent.ResponseExecutionPrepared, fleetagent.ResponseExecutionExecuting, fleetagent.ResponseExecutionApplied,
	}
	if len(journal.saves) != len(want) {
		t.Fatalf("journal states=%v", journal.saves)
	}
	for i := range want {
		if journal.saves[i] != want[i] {
			t.Fatalf("journal states=%v want=%v", journal.saves, want)
		}
	}
	pending, err := service.PendingResults(context.Background())
	if err != nil || len(pending) != 1 || pending[0].CommandDigest != first.CommandDigest {
		t.Fatalf("pending results=%+v err=%v", pending, err)
	}
	if err := service.AcknowledgeResult(context.Background(), first.AttemptKey, first.CommandDigest); err != nil {
		t.Fatalf("acknowledge result: %v", err)
	}
	pending, err = service.PendingResults(context.Background())
	if err != nil || len(pending) != 0 || journal.found {
		t.Fatalf("acknowledged results remained in the local journal: %+v err=%v found=%t", pending, err, journal.found)
	}
}

func TestAcknowledgeResultRetriesDeletionAfterDurableAcknowledgement(t *testing.T) {
	command, public, _, now := executeCommand(t)
	journal := &executeJournal{}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, &executeActuator{journal: journal}, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	journal.failDelete = true
	if err := service.AcknowledgeResult(context.Background(), result.AttemptKey, result.CommandDigest); err == nil || !journal.found || !journal.entry.ResultAcknowledged {
		t.Fatalf("failed delete did not retain acknowledged retry state: entry=%+v found=%t err=%v", journal.entry, journal.found, err)
	}
	journal.failDelete = false
	if err := service.AcknowledgeResult(context.Background(), result.AttemptKey, result.CommandDigest); err != nil || journal.found {
		t.Fatalf("retry did not delete acknowledged result: found=%t err=%v", journal.found, err)
	}
}

func TestPendingResultsPrunesAcknowledgedJournalEntries(t *testing.T) {
	command, public, _, now := executeCommand(t)
	digest := fleetagent.ResponseCommandDigest(command)
	result := fleetagent.ResponseExecutionResult{
		AttemptKey: command.AttemptKey, CommandDigest: digest, LeaseID: "lease-1", State: fleetagent.ResponseExecutionApplied,
		ObservedRadius: offensivepolicy.RadiusStateChanging, AffectedCount: 1, CompletedAt: now,
	}
	journal := &executeJournal{found: true, entry: fleetagent.ResponseExecutionJournalEntry{
		Version: fleetagent.ResponseExecutionJournalVersion, Command: command, CommandDigest: digest,
		LeaseID: "lease-1", LeaseUntil: command.NotAfter, State: result.State, Result: &result, ResultAcknowledged: true,
	}}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, &executeActuator{journal: journal}, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.PendingResults(context.Background())
	if err != nil || len(pending) != 0 || journal.found {
		t.Fatalf("acknowledged startup journal remained: pending=%+v found=%t err=%v", pending, journal.found, err)
	}
}

func TestExecuteNeverRunsWithoutDurableClaim(t *testing.T) {
	command, public, _, now := executeCommand(t)
	journal := &executeJournal{failSave: fleetagent.ResponseExecutionExecuting}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter); err == nil {
		t.Fatal("execution must fail when the durable claim cannot be persisted")
	}
	if actuator.calls != 0 {
		t.Fatalf("actuator ran %d times without durable claim", actuator.calls)
	}
}

func TestExecuteRefreshesDeadlineAfterPreparedJournalWrite(t *testing.T) {
	command, public, _, now := executeCommand(t)
	clock := &executeClock{at: now}
	journal := &executeJournal{afterSave: func(state fleetagent.ResponseExecutionState) {
		if state == fleetagent.ResponseExecutionPrepared {
			clock.at = command.NotAfter
		}
	}}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("command expiring during prepared journal write must fail closed, got %v", err)
	}
	if actuator.calls != 0 || journal.entry.State != fleetagent.ResponseExecutionPrepared {
		t.Fatalf("expired command crossed execution claim: calls=%d state=%s", actuator.calls, journal.entry.State)
	}
}

func TestExecuteMarksCompletionAtDeadlineUnknown(t *testing.T) {
	command, public, _, now := executeCommand(t)
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal}
	clock := &sequenceClock{times: []time.Time{now, now, now, now, command.NotAfter}}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, clock)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
	if !errors.Is(err, shared.ErrForbidden) || !errors.Is(err, ErrExecutionOutcomeUnknown) {
		t.Fatalf("late completion result=%+v err=%v, want forbidden unknown outcome", result, err)
	}
	if actuator.calls != 1 || journal.entry.State != fleetagent.ResponseExecutionOutcomeUnknown {
		t.Fatalf("late completion calls=%d journal=%+v", actuator.calls, journal.entry)
	}
}

func TestExecuteRechecksSigningKeyAtSideEffectBoundary(t *testing.T) {
	command, public, _, now := executeCommand(t)
	revokedAt := now.Add(30 * time.Second)
	clock := &sequenceClock{times: []time.Time{now, now, now, revokedAt, revokedAt}}
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{
		public: public, notAfter: command.NotAfter.Add(time.Minute), revokedAt: revokedAt,
	}, journal, actuator, clock)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
	if !errors.Is(err, shared.ErrForbidden) || !errors.Is(err, ErrExecutionOutcomeUnknown) ||
		result.State != fleetagent.ResponseExecutionOutcomeUnknown {
		t.Fatalf("revoked boundary key result=%+v err=%v", result, err)
	}
	if actuator.calls != 0 {
		t.Fatalf("actuator ran %d times after key revocation", actuator.calls)
	}
}

func TestExecuteDoesNotReplayInterruptedExecution(t *testing.T) {
	command, public, _, now := executeCommand(t)
	digest := fleetagent.ResponseCommandDigest(command)
	journal := &executeJournal{found: true, entry: fleetagent.ResponseExecutionJournalEntry{
		Version: fleetagent.ResponseExecutionJournalVersion, Command: command, CommandDigest: digest,
		LeaseID: "lease-1", LeaseUntil: command.NotAfter, State: fleetagent.ResponseExecutionExecuting,
	}}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
	if !errors.Is(err, ErrExecutionOutcomeUnknown) || result.State != fleetagent.ResponseExecutionOutcomeUnknown {
		t.Fatalf("interrupted execution result=%+v err=%v", result, err)
	}
	if actuator.calls != 0 {
		t.Fatalf("interrupted execution was replayed %d times", actuator.calls)
	}
}

func TestExecuteReconcilesInterruptedExecutionUnderReclaimedLease(t *testing.T) {
	command, public, _, now := executeCommand(t)
	digest := fleetagent.ResponseCommandDigest(command)
	journal := &executeJournal{found: true, entry: fleetagent.ResponseExecutionJournalEntry{
		Version: fleetagent.ResponseExecutionJournalVersion, Command: command, CommandDigest: digest,
		LeaseID: "expired-lease", LeaseUntil: now.Add(-time.Second), State: fleetagent.ResponseExecutionExecuting,
	}}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), command, "reclaimed-lease", command.NotAfter)
	if !errors.Is(err, ErrExecutionOutcomeUnknown) || result.State != fleetagent.ResponseExecutionOutcomeUnknown || result.LeaseID != "reclaimed-lease" {
		t.Fatalf("reclaimed execution result=%+v err=%v", result, err)
	}
	if actuator.calls != 0 || journal.entry.LeaseID != "reclaimed-lease" {
		t.Fatalf("interrupted execution replayed or retained stale lease: calls=%d entry=%+v", actuator.calls, journal.entry)
	}
}

func TestExecuteResumesPreparedEntryWithCurrentLease(t *testing.T) {
	command, public, _, now := executeCommand(t)
	digest := fleetagent.ResponseCommandDigest(command)
	journal := &executeJournal{found: true, entry: fleetagent.ResponseExecutionJournalEntry{
		Version: fleetagent.ResponseExecutionJournalVersion, Command: command, CommandDigest: digest,
		LeaseID: "expired-lease", LeaseUntil: now.Add(-time.Second), State: fleetagent.ResponseExecutionPrepared,
	}}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), command, "reclaimed-lease", command.NotAfter)
	if err != nil || result.State != fleetagent.ResponseExecutionApplied || result.LeaseID != "reclaimed-lease" {
		t.Fatalf("prepared execution result=%+v err=%v", result, err)
	}
	if actuator.calls != 1 || journal.entry.LeaseID != "reclaimed-lease" || !journal.entry.LeaseUntil.Equal(command.NotAfter) {
		t.Fatalf("prepared execution did not bind current lease: calls=%d entry=%+v", actuator.calls, journal.entry)
	}
}

func TestExecuteRejectsWrongAgentBeforeJournaling(t *testing.T) {
	command, public, private, now := executeCommand(t)
	command.AgentID = "executor-2"
	command.Signature = fleetagent.SignResponseCommand(private, command)
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("wrong-agent command must fail, got %v", err)
	}
	if journal.found || actuator.calls != 0 {
		t.Fatal("wrong-agent command reached the journal or actuator")
	}
}

func TestExecuteHonorsDurableHaltFence(t *testing.T) {
	command, public, _, now := executeCommand(t)
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Halt(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("halted executor must reject command, got %v", err)
	}
	if actuator.calls != 0 || journal.entry.Command.AttemptKey != "" {
		t.Fatal("halted command reached execution journal or actuator")
	}
}

func TestHaltCancelsInFlightActuatorAndMarksOutcomeUnknown(t *testing.T) {
	command, public, _, now := executeCommand(t)
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal, started: make(chan struct{})}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	type execution struct {
		result fleetagent.ResponseExecutionResult
		err    error
	}
	done := make(chan execution, 1)
	go func() {
		result, executeErr := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
		done <- execution{result: result, err: executeErr}
	}()
	select {
	case <-actuator.started:
	case <-time.After(time.Second):
		t.Fatal("actuator did not start")
	}
	if err := service.Halt(context.Background(), 1); err != nil {
		t.Fatalf("halt: %v", err)
	}
	select {
	case got := <-done:
		if !errors.Is(got.err, ErrExecutionOutcomeUnknown) || got.result.State != fleetagent.ResponseExecutionOutcomeUnknown {
			t.Fatalf("result=%+v err=%v", got.result, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("halt did not cancel in-flight actuator")
	}
	if !journal.halted || journal.entry.State != fleetagent.ResponseExecutionOutcomeUnknown {
		t.Fatalf("halted=%t journal state=%s", journal.halted, journal.entry.State)
	}
}

func TestCommandExpiryCancelsInFlightActuatorAndMarksOutcomeUnknown(t *testing.T) {
	command, public, private, now := executeCommand(t)
	command.NotAfter = now.Add(20 * time.Millisecond)
	command.Signature = fleetagent.SignResponseCommand(private, command)
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal, started: make(chan struct{})}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(context.Background(), command, "lease-1", command.NotAfter)
	if !errors.Is(err, ErrExecutionOutcomeUnknown) || !errors.Is(err, context.DeadlineExceeded) || result.State != fleetagent.ResponseExecutionOutcomeUnknown {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestLeaseExpiryCancelsInFlightActuatorAndMarksOutcomeUnknown(t *testing.T) {
	command, public, _, now := executeCommand(t)
	journal := &executeJournal{}
	actuator := &executeActuator{journal: journal, started: make(chan struct{})}
	service, err := NewService("executor-1", "asset-1", executeKeys{public: public}, journal, actuator, executeClock{at: now})
	if err != nil {
		t.Fatal(err)
	}
	leaseUntil := now.Add(20 * time.Millisecond)
	result, err := service.Execute(context.Background(), command, "lease-1", leaseUntil)
	if !errors.Is(err, ErrExecutionOutcomeUnknown) || !errors.Is(err, context.DeadlineExceeded) || result.State != fleetagent.ResponseExecutionOutcomeUnknown {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !journal.entry.LeaseUntil.Equal(leaseUntil) {
		t.Fatalf("journal lease until=%s want=%s", journal.entry.LeaseUntil, leaseUntil)
	}
}
