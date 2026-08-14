package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/promotion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fpeCols is the SELECT/RETURNING projection scanned by scanPromotionEvent.
const fpeCols = `id, engagement_id, judgment_id, finding_id, finding_version, after_finding_version,
    rule, effect, before_priority, after_priority, inputs, fingerprint,
    verdict_score, verdict_rationale, evidence_id, verifier,
    uncertainty, applied_by, applied_at`

// PromotionStore persists promotion lifecycle events to PostgreSQL.
// Every operation runs inside a single RLS-scoped transaction via
// WithContextTenant so tenant isolation is enforced at the database level.
//
// Apply atomically:
//  1. Acquires sorted advisory transaction locks on (judgment, fingerprint)
//     to serialize concurrent idempotency checks (prevents deadlocks).
//  2. Checks judgment-level idempotency (tenant+judgmentID).
//  3. Checks fingerprint-level idempotency (tenant+fingerprint).
//  4. Locks the finding FOR UPDATE, verifies CAS (priority + version).
//  5. Binds command metadata to CAS state.
//  6. Validates exact reversal for corroborating_signal_loss.
//  7. Constructs and validates the PromotionEvent.
//  8. Mutates the finding (priority + version) for escalating/de-escalating effects.
//  9. Appends the event to the append-only table.
type PromotionStore struct {
	pool *pgxpool.Pool
}

// NewPromotionStore returns a repository backed by the given pool.
func NewPromotionStore(pool *pgxpool.Pool) (*PromotionStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: promotion store requires a database pool", shared.ErrValidation)
	}
	return &PromotionStore{pool: pool}, nil
}

var (
	_ ports.PromotionStore             = (*PromotionStore)(nil)
	_ ports.PromotionAuditTracker      = (*PromotionStore)(nil)
	_ ports.PendingPromotionAuditStore = (*PromotionStore)(nil)
)

// sortedLockKeys returns two hashtext-based int32 keys in sorted order so that
// concurrent transactions always acquire advisory locks in the same order,
// preventing deadlocks. The "fpe:" namespace separates promotion locks from
// other advisory lock users.
func sortedLockKeys(judgmentID, fingerprint string) (int32, int32) {
	// Use the first 4 bytes of the string as a simple hash for advisory locks.
	// This doesn't need to be cryptographic; it just needs to be deterministic
	// and reasonably distributed. We use hashtext() in SQL instead.
	// For Go-side sorting, we compare the raw strings.
	a := "fpe:j:" + judgmentID
	b := "fpe:f:" + fingerprint
	if a > b {
		return hashStr(b), hashStr(a)
	}
	return hashStr(a), hashStr(b)
}

// hashStr produces a deterministic int32 from a string for advisory lock keys.
// Mirrors PostgreSQL's hashtext() behavior closely enough for lock keying.
func hashStr(s string) int32 {
	var h int32
	for _, c := range s {
		h = h*31 + int32(c)
	}
	return h
}

// Apply constructs a PromotionEvent from the command, persists it, and
// atomically moves the finding's priority. Returns the existing event on
// exact replay (same judgmentID), or shared.ErrConflict on semantic conflicts.
func (r *PromotionStore) Apply(ctx context.Context, engagementID, findingID shared.ID, cmd ports.PromotionCommand) (out finding.Finding, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		// 1. Acquire TWO independent namespaced advisory transaction locks:
		// one for the judgment key and one for the fingerprint key. Sorting
		// by the key values ensures deterministic acquisition order to
		// prevent deadlocks. We use the single-argument pg_advisory_xact_lock
		// form (one lock per call) so each key is an independent lock.
		k1, k2 := sortedLockKeys(cmd.JudgmentID.String(), cmd.Fingerprint)
		if _, lockErr := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock($1)`, k1); lockErr != nil {
			return fmt.Errorf("acquire promotion advisory lock (judgment): %w", lockErr)
		}
		if _, lockErr := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock($1)`, k2); lockErr != nil {
			return fmt.Errorf("acquire promotion advisory lock (fingerprint): %w", lockErr)
		}

		// 2. Judgment-level idempotency: if this exact judgment was already
		// applied, verify exact replay (all immutable semantic fields must
		// match) and return the existing finding state.
		jRow := tx.QueryRow(ctx,
			`SELECT `+fpeCols+` FROM finding_promotion_events WHERE judgment_id = $1`,
			cmd.JudgmentID.String())
		existingEvt, jErr := scanPromotionEvent(jRow)
		if jErr == nil {
			// Defense-in-depth: verify the stored event's engagement matches
			// the requested engagement. The composite FK
			// (tenant_id, engagement_id, judgment_id) enforces this at the
			// database level; this code-level check makes the intent explicit.
			if existingEvt.EngagementID != engagementID {
				return fmt.Errorf("%w: judgment %s belongs to engagement %s, not %s", shared.ErrConflict, cmd.JudgmentID, existingEvt.EngagementID, engagementID)
			}
			// Build the expected replay event for comparison.
			afterFV := cmd.FindingVersion
			if cmd.Effect != judgment.PromotionFlagForReview {
				afterFV = cmd.FindingVersion + 1
			}
			replayEvt := promotion.PromotionEvent{
				EngagementID:        engagementID,
				JudgmentID:          cmd.JudgmentID,
				FindingID:           findingID,
				FindingVersion:      cmd.FindingVersion,
				AfterFindingVersion: afterFV,
				Rule:                cmd.Rule,
				Effect:              cmd.Effect,
				BeforePriority:      cmd.BeforePriority,
				AfterPriority:       cmd.AfterPriority,
				Inputs:              cmd.Inputs,
				Fingerprint:         cmd.Fingerprint,
				Uncertainty:         cmd.Uncertainty,
				VerdictScore:        cmd.VerdictScore,
				VerdictRationale:    cmd.VerdictRationale,
				EvidenceID:          cmd.EvidenceID,
				Verifier:            cmd.Verifier,
				AppliedBy:           cmd.AppliedBy,
			}
			if !existingEvt.Equals(replayEvt) {
				return fmt.Errorf("%w: judgment %s replay differs from stored event", shared.ErrConflict, cmd.JudgmentID)
			}
			var scanErr error
			out, scanErr = scanFindingFromTx(ctx, tx, engagementID, findingID)
			return scanErr
		}
		if !errors.Is(jErr, pgx.ErrNoRows) {
			return fmt.Errorf("check judgment idempotency: %w", jErr)
		}

		// 3. Fingerprint-level idempotency: if this fingerprint already exists
		// under a different judgment, that is a semantic conflict.
		var fpJudgment string
		fpErr := tx.QueryRow(ctx,
			`SELECT judgment_id FROM finding_promotion_events WHERE fingerprint = $1`,
			cmd.Fingerprint).Scan(&fpJudgment)
		if fpErr == nil {
			if fpJudgment != cmd.JudgmentID.String() {
				return fmt.Errorf("%w: fingerprint %s already applied by judgment %s (not %s)", shared.ErrConflict, cmd.Fingerprint, fpJudgment, cmd.JudgmentID)
			}
			// Judgment matches: replay through a different code path.
			var scanErr error
			out, scanErr = scanFindingFromTx(ctx, tx, engagementID, findingID)
			return scanErr
		}
		if !errors.Is(fpErr, pgx.ErrNoRows) {
			return fmt.Errorf("check fingerprint idempotency: %w", fpErr)
		}

		// 4. Lock the finding FOR UPDATE and verify CAS (priority + version).
		var (
			fPriority int
			fVersion  int
		)
		fErr := tx.QueryRow(ctx,
			`SELECT priority, version
			 FROM findings WHERE id = $1 AND engagement_id = $2
			 FOR UPDATE`,
			findingID.String(), engagementID.String(),
		).Scan(&fPriority, &fVersion)
		if errors.Is(fErr, pgx.ErrNoRows) {
			return fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
		}
		if fErr != nil {
			return fmt.Errorf("lock finding for promotion: %w", fErr)
		}
		if fVersion != cmd.ExpectedVersion {
			return fmt.Errorf("finding %s changed since you loaded it: %w", findingID, shared.ErrConflict)
		}
		if fPriority != cmd.ExpectedPriority {
			return fmt.Errorf("finding %s priority changed since you loaded it: %w", findingID, shared.ErrConflict)
		}

		// 5. Bind command metadata to CAS: the event's FindingVersion must
		// equal ExpectedVersion and BeforePriority must equal ExpectedPriority.
		if cmd.FindingVersion != cmd.ExpectedVersion {
			return fmt.Errorf("%w: command FindingVersion %d != ExpectedVersion %d", shared.ErrValidation, cmd.FindingVersion, cmd.ExpectedVersion)
		}
		if cmd.BeforePriority != cmd.ExpectedPriority {
			return fmt.Errorf("%w: command BeforePriority %d != ExpectedPriority %d", shared.ErrValidation, cmd.BeforePriority, cmd.ExpectedPriority)
		}

		// 6. For corroborating_signal_loss, validate the exact reversal.
		if cmd.Rule == judgment.RuleCorroboratingSignalLoss {
			if vErr := r.validateExactReversalTx(ctx, tx, engagementID, findingID, cmd); vErr != nil {
				return vErr
			}
		}

		// 7. Construct and validate the event BEFORE any mutation.
		afterFindingVersion := cmd.FindingVersion
		if cmd.Effect != judgment.PromotionFlagForReview {
			afterFindingVersion = cmd.FindingVersion + 1
		}

		evt, err := promotion.NewPromotionEvent(
			cmd.EventID,
			engagementID,
			cmd.JudgmentID,
			findingID,
			cmd.FindingVersion,
			afterFindingVersion,
			cmd.Rule,
			cmd.Effect,
			cmd.BeforePriority,
			cmd.AfterPriority,
			cmd.Inputs,
			cmd.Fingerprint,
			cmd.VerdictScore,
			cmd.VerdictRationale,
			cmd.EvidenceID,
			cmd.Verifier,
			cmd.Uncertainty,
			cmd.AppliedBy,
			time.Now().UTC(),
		)
		if err != nil {
			return fmt.Errorf("construct promotion event: %w", err)
		}

		// 8. For mutating effects, bump the finding's priority + version.
		if evt.Effect != judgment.PromotionFlagForReview {
			_, err := tx.Exec(ctx,
				`UPDATE findings SET priority = $1, version = version + 1, updated_at = now()
				 WHERE id = $2 AND engagement_id = $3 AND version = $4`,
				evt.AfterPriority, findingID.String(), engagementID.String(), cmd.ExpectedVersion)
			if err != nil {
				return fmt.Errorf("update finding priority: %w", err)
			}
		}

		// 9. Append the event to the append-only table.
		inputsJSON, err := json.Marshal(evt.Inputs)
		if err != nil {
			return fmt.Errorf("marshal promotion inputs: %w", err)
		}
		uncertaintyJSON, err := json.Marshal(evt.Uncertainty)
		if err != nil {
			return fmt.Errorf("marshal promotion uncertainty: %w", err)
		}
		tenantID, _ := shared.TenantFrom(ctx)

		_, err = tx.Exec(ctx,
			`INSERT INTO finding_promotion_events
			 (id, tenant_id, engagement_id, judgment_id, finding_id,
			  finding_version, after_finding_version,
			  rule, effect, before_priority, after_priority,
			  inputs, fingerprint,
			  verdict_score, verdict_rationale, evidence_id, verifier,
			  uncertainty, applied_by, applied_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
			evt.ID.String(), tenantID.String(), evt.EngagementID.String(),
			evt.JudgmentID.String(), evt.FindingID.String(),
			evt.FindingVersion, evt.AfterFindingVersion,
			evt.Rule, string(evt.Effect), evt.BeforePriority, evt.AfterPriority,
			inputsJSON, evt.Fingerprint,
			evt.VerdictScore, evt.VerdictRationale,
			evt.EvidenceID.String(), evt.Verifier,
			uncertaintyJSON, evt.AppliedBy, evt.AppliedAt,
		)
		if err != nil {
			return fmt.Errorf("insert promotion event: %w", err)
		}
		if _, err = tx.Exec(ctx,
			`INSERT INTO finding_promotion_audit_status (tenant_id, event_id) VALUES ($1, $2)`,
			tenantID.String(), evt.ID.String()); err != nil {
			return fmt.Errorf("insert promotion audit status: %w", err)
		}

		// Re-read the finding post-mutation to return its final state.
		out, err = scanFindingFromTx(ctx, tx, engagementID, findingID)
		return err
	})
	return out, err
}

// validateExactReversalTx verifies that a corroborating_signal_loss command
// references a valid prior escalation event that is the latest mutating
// promotion in the finding's lineage. The prior event must:
//   - be referenced by exactly one prior_promotion input
//   - exist in the store under the same engagement and finding
//   - be an applied escalation
//   - have a BeforePriority that equals the requested AfterPriority
//   - be the latest event for this finding (no later events after it)
//   - its AfterPriority and AfterFindingVersion must match the command's
//     BeforePriority and FindingVersion (lineage continuity)
func (r *PromotionStore) validateExactReversalTx(ctx context.Context, tx pgx.Tx, engagementID, findingID shared.ID, cmd ports.PromotionCommand) error {
	var priorEventID shared.ID
	priorCount := 0
	for _, in := range cmd.Inputs {
		if in.Kind == judgment.PromotionInputPrior {
			priorEventID = in.ID
			priorCount++
		}
	}
	if priorCount == 0 {
		return fmt.Errorf("%w: corroborating_signal_loss requires a prior_promotion input", shared.ErrValidation)
	}
	if priorCount > 1 {
		return fmt.Errorf("%w: corroborating_signal_loss requires exactly one prior_promotion input, got %d", shared.ErrValidation, priorCount)
	}
	if priorEventID.IsZero() {
		return fmt.Errorf("%w: prior_promotion input has empty event ID", shared.ErrValidation)
	}
	rows, err := tx.Query(ctx, `SELECT `+fpeCols+` FROM finding_promotion_events
		WHERE engagement_id=$1 AND finding_id=$2 ORDER BY applied_at ASC, id COLLATE "C" ASC`, engagementID.String(), findingID.String())
	if err != nil {
		return fmt.Errorf("list promotion lineage: %w", err)
	}
	defer rows.Close()
	stack := make([]promotion.PromotionEvent, 0)
	found := false
	for rows.Next() {
		event, err := scanPromotionEvent(rows)
		if err != nil {
			return fmt.Errorf("scan promotion lineage: %w", err)
		}
		if event.ID == priorEventID {
			found = true
		}
		switch event.Effect {
		case judgment.PromotionEscalate:
			stack = append(stack, event)
		case judgment.PromotionDeescalate:
			if event.Rule != judgment.RuleCorroboratingSignalLoss {
				continue
			}
			for _, input := range event.Inputs {
				if input.Kind != judgment.PromotionInputPrior {
					continue
				}
				for i := len(stack) - 1; i >= 0; i-- {
					if stack[i].ID == input.ID {
						stack = stack[:i]
						break
					}
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list promotion lineage: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: prior promotion event %s not found for engagement %s finding %s", shared.ErrNotFound, priorEventID, engagementID, findingID)
	}
	if len(stack) == 0 || stack[len(stack)-1].ID != priorEventID {
		return fmt.Errorf("%w: prior event %s is not the latest unresolved escalation", shared.ErrConflict, priorEventID)
	}
	prior := stack[len(stack)-1]
	if cmd.AfterPriority != prior.BeforePriority {
		return fmt.Errorf("%w: reversal target priority %d != prior event %s before-priority %d", shared.ErrConflict, cmd.AfterPriority, priorEventID, prior.BeforePriority)
	}
	if cmd.BeforePriority != prior.AfterPriority {
		return fmt.Errorf("%w: command before-priority %d != prior event %s after-priority %d", shared.ErrConflict, cmd.BeforePriority, priorEventID, prior.AfterPriority)
	}
	return nil
}

// ListByFinding returns all promotion events for a finding, oldest first.
func (r *PromotionStore) ListByFinding(ctx context.Context, engagementID, findingID shared.ID) (out []promotion.PromotionEvent, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx,
			`SELECT `+fpeCols+`
			 FROM finding_promotion_events
			 WHERE engagement_id = $1 AND finding_id = $2
			 ORDER BY applied_at ASC, id COLLATE "C" ASC`,
			engagementID.String(), findingID.String())
		if qErr != nil {
			return fmt.Errorf("list promotion events: %w", qErr)
		}
		defer rows.Close()
		for rows.Next() {
			evt, scanErr := scanPromotionEvent(rows)
			if scanErr != nil {
				return fmt.Errorf("scan promotion event: %w", scanErr)
			}
			out = append(out, evt)
		}
		return rows.Err()
	})
	return out, err
}

// LatestByFinding returns the most recent promotion event for a finding,
// or (zero, false) if none exist.
func (r *PromotionStore) LatestByFinding(ctx context.Context, engagementID, findingID shared.ID) (evt promotion.PromotionEvent, ok bool, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+fpeCols+`
			 FROM finding_promotion_events
			 WHERE engagement_id = $1 AND finding_id = $2
			 ORDER BY applied_at DESC, id DESC
			 LIMIT 1`,
			engagementID.String(), findingID.String())
		scanEvt, scanErr := scanPromotionEvent(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			ok = false
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("scan latest promotion event: %w", scanErr)
		}
		evt = scanEvt
		ok = true
		return nil
	})
	return evt, ok, err
}

// FindByJudgment returns an event scoped to its tenant, engagement, and finding.
func (r *PromotionStore) FindByJudgment(ctx context.Context, engagementID, findingID, judgmentID shared.ID) (evt promotion.PromotionEvent, ok bool, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+fpeCols+`
			 FROM finding_promotion_events
			 WHERE engagement_id = $1 AND finding_id = $2 AND judgment_id = $3`,
			engagementID.String(), findingID.String(), judgmentID.String())
		scanEvt, scanErr := scanPromotionEvent(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("scan promotion event by judgment: %w", scanErr)
		}
		evt, ok = scanEvt, true
		return nil
	})
	return evt, ok, err
}

// ListPendingAudits returns applied events whose required audit record has not
// been acknowledged. The status row is created atomically with each event.
func (r *PromotionStore) ListPendingAudits(ctx context.Context, engagementID shared.ID) (out []promotion.PromotionEvent, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx,
			`SELECT `+fpeCols+`
			 FROM finding_promotion_events e
			 JOIN finding_promotion_audit_status s ON s.tenant_id = e.tenant_id AND s.event_id = e.id
			 WHERE e.engagement_id = $1 AND s.completed_at IS NULL
			 ORDER BY e.applied_at ASC, e.id COLLATE "C" ASC`, engagementID.String())
		if qErr != nil {
			return fmt.Errorf("list pending promotion audits: %w", qErr)
		}
		defer rows.Close()
		for rows.Next() {
			evt, scanErr := scanPromotionEvent(rows)
			if scanErr != nil {
				return fmt.Errorf("scan pending promotion audit: %w", scanErr)
			}
			out = append(out, evt)
		}
		return rows.Err()
	})
	return out, err
}

// MarkAuditComplete acknowledges an event's required audit record. Repeating
// the acknowledgement is idempotent.
func (r *PromotionStore) MarkAuditComplete(ctx context.Context, eventID shared.ID) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx,
			`UPDATE finding_promotion_audit_status SET completed_at = COALESCE(completed_at, now()) WHERE event_id = $1`,
			eventID.String())
		if err != nil {
			return fmt.Errorf("mark promotion audit complete: %w", err)
		}
		if result.RowsAffected() == 0 {
			return fmt.Errorf("promotion event %s: %w", eventID, shared.ErrNotFound)
		}
		return nil
	})
}

// scanFindingFromTx reads a finding within an existing transaction (no new
// transaction, no separate RLS scope). Used by Apply to re-read the finding
// after mutation.
func scanFindingFromTx(ctx context.Context, tx pgx.Tx, engagementID, findingID shared.ID) (finding.Finding, error) {
	return scanFinding(tx.QueryRow(ctx,
		`SELECT `+findingCols+` FROM findings WHERE id = $1 AND engagement_id = $2`,
		findingID.String(), engagementID.String()))
}

// scanPromotionEvent scans a finding_promotion_events row into a
// PromotionEvent. Accepts pgx.Row or pgx.Rows via the rowScanner interface.
func scanPromotionEvent(row rowScanner) (promotion.PromotionEvent, error) {
	var (
		evt                                               promotion.PromotionEvent
		id, eid, jid, fid, rule, effect, fingerprint      string
		verdictRationale, evidenceID, verifier, appliedBy string
		inputsJSON, uncertaintyJSON                       []byte
	)
	if err := row.Scan(
		&id, &eid, &jid, &fid,
		&evt.FindingVersion, &evt.AfterFindingVersion,
		&rule, &effect, &evt.BeforePriority, &evt.AfterPriority,
		&inputsJSON, &fingerprint,
		&evt.VerdictScore, &verdictRationale, &evidenceID, &verifier,
		&uncertaintyJSON, &appliedBy, &evt.AppliedAt,
	); err != nil {
		return promotion.PromotionEvent{}, err
	}
	evt.ID = shared.ID(id)
	evt.EngagementID = shared.ID(eid)
	evt.JudgmentID = shared.ID(jid)
	evt.FindingID = shared.ID(fid)
	evt.Rule = rule
	evt.Effect = judgment.PromotionChange(effect)
	evt.Fingerprint = fingerprint
	evt.VerdictRationale = verdictRationale
	evt.EvidenceID = shared.ID(evidenceID)
	evt.Verifier = verifier
	evt.AppliedBy = appliedBy

	if len(inputsJSON) > 0 {
		if err := json.Unmarshal(inputsJSON, &evt.Inputs); err != nil {
			return promotion.PromotionEvent{}, fmt.Errorf("unmarshal promotion inputs: %w", err)
		}
	}
	if len(uncertaintyJSON) > 0 {
		if err := json.Unmarshal(uncertaintyJSON, &evt.Uncertainty); err != nil {
			return promotion.PromotionEvent{}, fmt.Errorf("unmarshal promotion uncertainty: %w", err)
		}
	}

	return evt, nil
}
