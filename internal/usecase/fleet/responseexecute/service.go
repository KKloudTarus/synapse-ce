// Package responseexecute applies control-plane-signed response commands behind an endpoint-local journal.
package responseexecute

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var ErrExecutionOutcomeUnknown = errors.New("response execution outcome unknown")

// Actuator and its outcome remain aliases for compatibility; the endpoint side-effect port lives in ports.
type Actuator = ports.ResponseActuator
type ActuatorOutcome = ports.ResponseActuatorOutcome

type acknowledgedResponseExecutionDeleter interface {
	DeleteResponseExecution(context.Context, string) error
}

type Service struct {
	agentID  shared.ID
	assetID  shared.ID
	keys     ports.ResponseCommandKeyResolver
	journal  ports.ResponseExecutionJournal
	actuator Actuator
	clock    ports.Clock
	execMu   sync.Mutex
	stateMu  sync.Mutex
	active   context.CancelFunc
}

func NewService(agentID, assetID shared.ID, keys ports.ResponseCommandKeyResolver, journal ports.ResponseExecutionJournal, actuator Actuator, clock ports.Clock) (*Service, error) {
	if agentID.IsZero() || assetID.IsZero() || keys == nil || journal == nil || actuator == nil || clock == nil {
		return nil, fmt.Errorf("%w: response executor is missing an identity, trust resolver, journal, actuator, or clock", shared.ErrValidation)
	}
	return &Service{
		agentID: agentID, assetID: assetID, keys: keys,
		journal: journal, actuator: actuator, clock: clock,
	}, nil
}

func (s *Service) Execute(ctx context.Context, command fleetagent.ResponseCommand, leaseID string, leaseUntil time.Time) (fleetagent.ResponseExecutionResult, error) {
	s.execMu.Lock()
	defer s.execMu.Unlock()
	leaseID = strings.TrimSpace(leaseID)
	leaseUntil = leaseUntil.UTC()
	if leaseID == "" || leaseUntil.IsZero() {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: response execution requires a work-order lease", shared.ErrValidation)
	}

	key, err := s.keys.ResolveResponseCommandKey(ctx, command.SigningKeyID)
	if err != nil {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("resolve response command signing key: %w", err)
	}
	if err := key.UsableAt(command.IssuedAt); err != nil {
		return fleetagent.ResponseExecutionResult{}, err
	}
	if command.NotAfter.After(key.NotAfter) {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: response command outlives its signing key", shared.ErrForbidden)
	}
	if err := fleetagent.VerifyResponseCommand(key.PublicKey, command); err != nil {
		return fleetagent.ResponseExecutionResult{}, err
	}
	if command.AgentID != s.agentID || command.AssetID != s.assetID {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: response command is addressed to another executor", shared.ErrForbidden)
	}
	if leaseUntil.After(command.NotAfter) {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: work-order lease outlives its signed response command", shared.ErrForbidden)
	}
	digest := fleetagent.ResponseCommandDigest(command)
	entry, found, err := s.journal.LoadResponseExecution(ctx, command.AttemptKey)
	if err != nil {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("load response execution journal: %w", err)
	}
	if found {
		if entry.CommandDigest != digest {
			return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: response attempt key was reused for another command", shared.ErrConflict)
		}
		switch entry.State {
		case fleetagent.ResponseExecutionApplied:
			if entry.LeaseID != leaseID {
				return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: terminal response result belongs to another work-order lease", shared.ErrConflict)
			}
			return *entry.Result, nil
		case fleetagent.ResponseExecutionOutcomeUnknown:
			if entry.LeaseID != leaseID {
				return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: terminal response result belongs to another work-order lease", shared.ErrConflict)
			}
			return *entry.Result, ErrExecutionOutcomeUnknown
		case fleetagent.ResponseExecutionExecuting:
			return s.markUnknown(command, digest, leaseID, leaseUntil)
		case fleetagent.ResponseExecutionPrepared:
			// No side effect can begin until Executing is durable, so a prepared entry is safe to resume.
			entry.LeaseID = leaseID
			entry.LeaseUntil = leaseUntil
		default:
			return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: response execution journal has invalid state", shared.ErrValidation)
		}
	}
	now := s.clock.Now().UTC()
	if err := key.UsableAt(now); err != nil {
		return fleetagent.ResponseExecutionResult{}, err
	}
	if err := s.checkFence(ctx, command.HaltGeneration); err != nil {
		return fleetagent.ResponseExecutionResult{}, err
	}
	if !found {
		entry = fleetagent.ResponseExecutionJournalEntry{
			Version: fleetagent.ResponseExecutionJournalVersion, Command: command, CommandDigest: digest,
			LeaseID: leaseID, LeaseUntil: leaseUntil, State: fleetagent.ResponseExecutionPrepared,
		}
		if err := s.journal.SaveResponseExecution(ctx, entry); err != nil {
			return fleetagent.ResponseExecutionResult{}, fmt.Errorf("persist response command before execution: %w", err)
		}
	}

	now = s.clock.Now().UTC()
	if now.Before(command.IssuedAt) || !now.Before(command.NotAfter) || !now.Before(leaseUntil) {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("%w: response command is outside its authorization window", shared.ErrForbidden)
	}
	entry.State = fleetagent.ResponseExecutionExecuting
	if err := s.journal.SaveResponseExecution(ctx, entry); err != nil {
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("persist response execution claim before side effect: %w", err)
	}
	// Journal and trust-store I/O may consume the remaining authorization window. Refresh time after
	// the executing claim is durable and fail closed before crossing the actuator boundary.
	now = s.clock.Now().UTC()
	if err := key.UsableAt(now); err != nil {
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(err, journalErr)
	}
	if now.Before(command.IssuedAt) || !now.Before(command.NotAfter) || !now.Before(leaseUntil) {
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(fmt.Errorf("%w: response command expired before its side effect", shared.ErrForbidden), journalErr)
	}
	deadline := command.NotAfter
	if leaseUntil.Before(deadline) {
		deadline = leaseUntil
	}
	s.stateMu.Lock()
	if err := s.checkFence(ctx, command.HaltGeneration); err != nil {
		s.stateMu.Unlock()
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(err, journalErr)
	}
	now = s.clock.Now().UTC()
	if err := key.UsableAt(now); err != nil {
		s.stateMu.Unlock()
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(err, journalErr)
	}
	if now.Before(command.IssuedAt) || !now.Before(command.NotAfter) || !now.Before(leaseUntil) {
		s.stateMu.Unlock()
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(fmt.Errorf("%w: response command expired at the side-effect boundary", shared.ErrForbidden), journalErr)
	}
	execCtx, cancel := context.WithTimeout(ctx, deadline.Sub(now))
	s.active = cancel
	s.stateMu.Unlock()

	outcome, execErr := s.actuator.ExecuteResponse(execCtx, command)

	// Serialize the terminal journal commit with Halt. If halt won while the actuator was running, its
	// cancellation or advanced fence makes the side-effect outcome ambiguous even when the actuator
	// returned success.
	s.stateMu.Lock()
	s.active = nil
	executionErr := execCtx.Err()
	cancel()
	if execErr != nil || executionErr != nil || !outcome.ObservedRadius.Valid() || outcome.AffectedCount < 0 {
		s.stateMu.Unlock()
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(execErr, executionErr, journalErr)
	}
	if err := s.checkFence(context.WithoutCancel(ctx), command.HaltGeneration); err != nil {
		s.stateMu.Unlock()
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(err, journalErr)
	}
	completedAt := s.clock.Now().UTC()
	if !completedAt.Before(command.NotAfter) || !completedAt.Before(leaseUntil) {
		s.stateMu.Unlock()
		result, journalErr := s.markUnknown(command, digest, leaseID, leaseUntil)
		return result, errors.Join(fmt.Errorf("%w: response command completed outside its authorization window", shared.ErrForbidden), journalErr)
	}
	result := fleetagent.ResponseExecutionResult{
		AttemptKey: command.AttemptKey, CommandDigest: digest, LeaseID: leaseID, State: fleetagent.ResponseExecutionApplied,
		ObservedRadius: outcome.ObservedRadius, AffectedCount: outcome.AffectedCount,
		AlreadyApplied: outcome.AlreadyApplied, CompletedAt: completedAt,
	}
	entry.State = result.State
	entry.Result = &result
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.journal.SaveResponseExecution(persistCtx, entry); err != nil {
		s.stateMu.Unlock()
		return fleetagent.ResponseExecutionResult{}, fmt.Errorf("persist response execution outcome: %w", err)
	}
	s.stateMu.Unlock()
	return result, nil
}

// ExecuteHaltCommand verifies a separately signed, addressed halt command before durably raising the
// endpoint-local monotonic fence. It carries no production-changing action payload.
func (s *Service) ExecuteHaltCommand(ctx context.Context, command fleetagent.ResponseHaltCommand, leaseID string, leaseUntil time.Time) error {
	leaseID = strings.TrimSpace(leaseID)
	leaseUntil = leaseUntil.UTC()
	if leaseID == "" || leaseUntil.IsZero() {
		return fmt.Errorf("%w: response halt requires a work-order lease", shared.ErrValidation)
	}
	if err := command.Validate(); err != nil {
		return err
	}
	key, err := s.keys.ResolveResponseCommandKey(ctx, command.SigningKeyID)
	if err != nil {
		return fmt.Errorf("resolve response halt signing key: %w", err)
	}
	if err := key.UsableAt(command.IssuedAt); err != nil {
		return err
	}
	if command.NotAfter.After(key.NotAfter) || leaseUntil.After(command.NotAfter) {
		return fmt.Errorf("%w: response halt outlives its signing key or work-order authorization", shared.ErrForbidden)
	}
	if err := fleetagent.VerifyResponseHaltCommand(key.PublicKey, command); err != nil {
		return err
	}
	if command.AgentID != s.agentID || command.AssetID != s.assetID {
		return fmt.Errorf("%w: response halt is addressed to another executor", shared.ErrForbidden)
	}
	now := s.clock.Now().UTC()
	if now.Before(command.IssuedAt) || !now.Before(command.NotAfter) || !now.Before(leaseUntil) {
		return fmt.Errorf("%w: response halt is outside its authorization window", shared.ErrForbidden)
	}
	return s.Halt(ctx, command.Generation)
}

// Halt durably latches the local execution fence before returning. Clearing the latch requires a future
// separately governed resume protocol; an ordinary command cannot lower or clear it.
func (s *Service) Halt(ctx context.Context, generation int64) error {
	if generation <= 0 {
		return fmt.Errorf("%w: response halt generation must be positive", shared.ErrValidation)
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.active != nil {
		s.active()
	}
	return s.journal.RaiseResponseHaltFence(ctx, generation)
}

// PendingResults returns terminal local outcomes that the control plane has not acknowledged yet.
func (s *Service) PendingResults(ctx context.Context) ([]fleetagent.ResponseExecutionJournalEntry, error) {
	entries, err := s.journal.ListResponseExecutions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list response result outbox: %w", err)
	}
	pending := entries[:0]
	for _, entry := range entries {
		if entry.ResultAcknowledged {
			if deleter, ok := s.journal.(acknowledgedResponseExecutionDeleter); ok {
				if err := deleter.DeleteResponseExecution(ctx, entry.Command.AttemptKey); err != nil {
					return nil, fmt.Errorf("delete acknowledged response result: %w", err)
				}
			}
			continue
		}
		if entry.Result != nil &&
			(entry.State == fleetagent.ResponseExecutionApplied || entry.State == fleetagent.ResponseExecutionOutcomeUnknown) {
			pending = append(pending, entry)
		}
	}
	return pending, nil
}

// AcknowledgeResult durably closes one exact outbox item after the control plane accepts it.
func (s *Service) AcknowledgeResult(ctx context.Context, attemptKey, commandDigest string) error {
	s.execMu.Lock()
	defer s.execMu.Unlock()
	entry, found, err := s.journal.LoadResponseExecution(ctx, attemptKey)
	if err != nil {
		return fmt.Errorf("load response result for acknowledgement: %w", err)
	}
	if !found {
		return shared.ErrNotFound
	}
	if entry.CommandDigest != commandDigest || entry.Result == nil ||
		(entry.State != fleetagent.ResponseExecutionApplied && entry.State != fleetagent.ResponseExecutionOutcomeUnknown) {
		return fmt.Errorf("%w: response result acknowledgement is not bound to a terminal command", shared.ErrConflict)
	}
	deleter, canDelete := s.journal.(acknowledgedResponseExecutionDeleter)
	if entry.ResultAcknowledged {
		if canDelete {
			return deleter.DeleteResponseExecution(ctx, attemptKey)
		}
		return nil
	}
	entry.ResultAcknowledged = true
	if err := s.journal.SaveResponseExecution(ctx, entry); err != nil {
		return fmt.Errorf("persist response result acknowledgement: %w", err)
	}
	if canDelete {
		if err := deleter.DeleteResponseExecution(ctx, attemptKey); err != nil {
			return fmt.Errorf("delete acknowledged response result: %w", err)
		}
	}
	return nil
}

func (s *Service) checkFence(ctx context.Context, generation int64) error {
	current, halted, err := s.journal.CurrentResponseHaltFence(ctx)
	if err != nil {
		return fmt.Errorf("read response execution halt fence: %w", err)
	}
	if halted || generation != current {
		return fmt.Errorf("%w: response command generation %d is fenced by local generation %d", shared.ErrForbidden, generation, current)
	}
	return nil
}

func (s *Service) markUnknown(command fleetagent.ResponseCommand, digest, leaseID string, leaseUntil time.Time) (fleetagent.ResponseExecutionResult, error) {
	result := fleetagent.ResponseExecutionResult{
		AttemptKey: command.AttemptKey, CommandDigest: digest, LeaseID: leaseID, State: fleetagent.ResponseExecutionOutcomeUnknown,
		CompletedAt: s.clock.Now().UTC(),
	}
	entry := fleetagent.ResponseExecutionJournalEntry{
		Version: fleetagent.ResponseExecutionJournalVersion, Command: command, CommandDigest: digest,
		LeaseID: leaseID, LeaseUntil: leaseUntil, State: result.State, Result: &result,
	}
	persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.journal.SaveResponseExecution(persistCtx, entry); err != nil {
		return result, fmt.Errorf("persist ambiguous response execution outcome: %w", err)
	}
	return result, ErrExecutionOutcomeUnknown
}
