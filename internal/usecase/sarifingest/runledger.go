package sarifingest

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// parserVersion identifies the reader that produced a run's counters. It is stamped on every receipt so a
// stored outcome can be read back against the code that produced it. Bump it when a parsing change alters
// which results are accepted or refused, because a receipt written by an older reader no longer describes
// what the current one would do with the same bytes.
const parserVersion = "sarifingest/1.0.0"

// sourceIdentityPrefix namespaces this importer inside the receipt's idempotency key, so a future importer
// of the same document into the same engagement is a different run rather than a collision.
const sourceIdentityPrefix = "sarif"

// SetRunLedger wires durable import receipts into ingestion.
//
// Both collaborators are required together. The store alone would record outcomes that are not atomic with
// the rows they describe, which is the exact failure the receipt exists to rule out: a receipt saying
// "complete" while the findings it counted were rolled back is worse than no receipt, because an operator
// would stop looking.
//
// Leaving the ledger unset keeps the pre-ledger behaviour byte for byte, so a deployment or a test that has
// not wired it is unaffected.
func (s *Service) SetRunLedger(receipts ports.ImportReceiptStore, tx ports.TenantTransactionRunner) error {
	if receipts == nil || tx == nil {
		return fmt.Errorf("%w: the sarif run ledger needs both a receipt store and a tenant transaction runner", shared.ErrValidation)
	}
	s.receipts = receipts
	s.tx = tx
	return nil
}

// ingestRun persists one parsed document, under a durable receipt when the ledger is wired.
//
// Without the ledger this is the pre-ledger call, unchanged. With it:
//
//  1. The receipt is opened in its OWN transaction, before the work. It has to outlive a rollback of the
//     work, because a receipt that disappears with the rows it was tracking cannot tell anyone the run
//     was attempted.
//  2. The rows, their audit entry, their attribution effects and the receipt's finalization all run in
//     ONE transaction. Every adapter underneath joins the transaction bound to the context, so this is
//     atomic in PostgreSQL: a finalized receipt and the rows it counts commit together or neither does.
//  3. A failure leaves the receipt PENDING. Pending is the repair obligation: nothing durable was
//     written, and the next identical post picks the same receipt up and finishes it.
func (s *Service) ingestRun(ctx context.Context, tenantID shared.ID, req IngestRequest, parsedDoc parsed) (IngestResult, error) {
	if s.receipts == nil {
		return s.ingestDocument(ctx, tenantID, req, parsedDoc)
	}

	receipt, err := s.openReceipt(ctx, tenantID, req, parsedDoc)
	if err != nil {
		return IngestResult{}, err
	}

	var result IngestResult
	runErr := s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		var ingestErr error
		result, ingestErr = s.ingestDocument(txCtx, tenantID, req, parsedDoc)
		if ingestErr != nil {
			return ingestErr
		}
		if receipt.Outcome.Terminal() {
			// A replay of a finished run. The counters this run recorded are the ones that describe the
			// durable rows, so they are left exactly as they are: re-finalizing would either be a no-op
			// or would overwrite the real outcome with a replay's view of it, in which Accepted is 0.
			// The effects above still re-ran, which is how a replay repairs an effect that was lost.
			return nil
		}
		_, finalizeErr := s.receipts.Finalize(txCtx, tenantID, receipt.ID, runOutcome(result), runCounters(result), s.clock.Now().UTC())
		return finalizeErr
	})
	if runErr != nil {
		// The receipt stays pending on purpose. The caller sees the failure, and the next post of the same
		// document finds the pending receipt and completes it rather than opening a second run for work
		// that was already attempted.
		return IngestResult{}, runErr
	}

	result.RunID = receipt.ID
	result.Outcome = receipt.Outcome
	if !result.Outcome.Terminal() {
		result.Outcome = runOutcome(result)
	}
	return result, nil
}

// openReceipt returns the run this document belongs to, creating it on first sight. A re-post of the same
// bytes into the same engagement resolves to the SAME receipt, so one document is one run however many
// times it is sent.
func (s *Service) openReceipt(ctx context.Context, tenantID shared.ID, req IngestRequest, parsedDoc parsed) (importreceipt.Receipt, error) {
	now := s.clock.Now().UTC()
	receipt := importreceipt.Receipt{
		ID:             s.ids.NewID(),
		TenantID:       tenantID,
		EngagementID:   req.EngagementID,
		SourceIdentity: sourceIdentity(parsedDoc),
		Digest:         parsedDoc.digest,
		ParserVersion:  parserVersion,
		Outcome:        importreceipt.OutcomePending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	persisted, _, err := s.receipts.CreateOrGet(ctx, tenantID, receipt)
	if err != nil {
		return importreceipt.Receipt{}, fmt.Errorf("open sarif import receipt: %w", err)
	}
	return persisted, nil
}

// sourceIdentity names where the document came from. The tool is read from the document itself, already
// sanitized by the parser, so the identity of a given document is stable across posts. A document whose
// results were all refused names no tool, and falls back to the bare importer name.
func sourceIdentity(parsedDoc parsed) string {
	for _, c := range parsedDoc.results {
		if name := strings.TrimSpace(c.toolName); name != "" {
			return sourceIdentityPrefix + ":" + name
		}
	}
	return sourceIdentityPrefix
}

// runOutcome reads the terminal outcome off the result.
//
// Complete requires an empty refusal list, which is also what the domain enforces, so "complete" can never
// mean "complete except for the parts we dropped". A run that refused everything and stored nothing failed:
// reporting it as partial would imply something landed.
func runOutcome(result IngestResult) importreceipt.Outcome {
	if len(result.Refused) == 0 {
		return importreceipt.OutcomeComplete
	}
	if result.Accepted == 0 && result.Deduped == 0 {
		return importreceipt.OutcomeFailed
	}
	return importreceipt.OutcomePartial
}

// runCounters projects the result onto the receipt's durable counters.
func runCounters(result IngestResult) importreceipt.Counters {
	return importreceipt.Counters{
		Accepted:     result.Accepted,
		Deduplicated: result.Deduped,
		Refused:      len(result.Refused),
	}
}
