// Package audit is the read/verify use case over the append-only audit log. It adds
// an OPTIONAL ed25519 attestation over the verified chain head, bringing the audit
// chain to parity with the evidence chain: both are hash-chained AND
// origin-attested. Verification of the chain itself lives in the repositories behind
// ports.AuditReader; this service orchestrates "verify then sign the head".
//
// Scope of the guarantee (same as evidence): the attestation proves the head was
// signed by THIS instance's key (origin / non-repudiation), and the hash chain makes
// edits/deletions that leave a verifiable suffix detectable. It does NOT, on its own,
// stop a privileged operator who reforges the whole chain and re-signs – that needs an
// external anchor (RFC-3161 via ports.TimestampAuthority, wired through SetTimestamper). The
// signed head is also returned on read so an external party can archive it out-of-band.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	auditdom "github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ChainAudit names the audit chain in the out-of-band timestamp store. The audit chain
// is global (not per-engagement), so it is anchored under the empty engagement id.
const ChainAudit = "audit"

// anchorTimeout bounds the per-call wait on the TSA so a slow/down authority never
// hangs the verify path.
const anchorTimeout = 5 * time.Second

// VerifiedReport is the audit chain's verification status plus, when a signer is
// configured and the chain is intact, a detached attestation over the chain head.
// The embedded Report is flattened in JSON; Attestation is an added optional field,
// so the wire shape stays backward compatible.
type VerifiedReport struct {
	auditdom.Report
	Attestation *evidence.Attestation `json:"attestation,omitempty"`
	// Anchored/Timestamp carry the external RFC-3161 anchor over the head (tamper-proof,
	// E13). Empty/false = tamper-evident + signed only.
	Anchored  bool                  `json:"anchored"`
	Timestamp *ports.TimestampToken `json:"timestamp,omitempty"`
}

// Service reads and verifies the append-only audit log.
type Service struct {
	reader  ports.AuditReader
	signer  ports.ChainSigner        // optional; nil leaves the chain integrity-only
	tsa     ports.TimestampAuthority // optional; external RFC-3161 anchoring
	tsStore ports.TimestampStore     // optional; the out-of-band token store
	log     *slog.Logger
}

// NewService validates its reader and returns the service.
func NewService(reader ports.AuditReader) (*Service, error) {
	if reader == nil {
		return nil, fmt.Errorf("%w: audit service requires an audit reader", shared.ErrValidation)
	}
	return &Service{reader: reader}, nil
}

// SetSigner enables chain-head attestation. Optional – nil leaves the audit chain
// integrity-only (the same signer the evidence vault uses is wired here for parity).
func (s *Service) SetSigner(signer ports.ChainSigner) { s.signer = signer }

// SetTimestamper enables external RFC-3161 anchoring of the audit head, at parity
// with the evidence chain. Best-effort + bounded; the token is stored/returned
// out-of-band. Optional.
func (s *Service) SetTimestamper(tsa ports.TimestampAuthority, store ports.TimestampStore) {
	s.tsa, s.tsStore = tsa, store
}

// SetLogger sets the logger for best-effort anchor warnings; defaults to slog.Default().
func (s *Service) SetLogger(l *slog.Logger) { s.log = l }

func (s *Service) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}
	return slog.Default()
}

// List returns the most recent audit entries (newest first), capped at limit.
func (s *Service) List(ctx context.Context, limit int) ([]ports.AuditEntry, error) {
	return s.reader.List(ctx, limit)
}

// Verify re-derives the audit hash chain and, when a signer is set and the chain is
// intact + non-empty, attests the head. A signing failure is non-fatal: integrity
// still holds, so the report is returned without an attestation rather than failing
// the read (mirrors the evidence vault).
func (s *Service) Verify(ctx context.Context) (VerifiedReport, error) {
	rep, err := s.reader.Verify(ctx)
	if err != nil {
		return VerifiedReport{}, err
	}
	out := VerifiedReport{Report: rep}
	if s.signer != nil && rep.Intact && rep.Head != "" {
		if att, err := s.signer.Sign(ctx, rep.Head); err == nil {
			out.Attestation = &att
		}
	}
	s.anchorHead(ctx, &out)
	return out, nil
}

// anchorHead attaches an external RFC-3161 timestamp to the verified audit head,
// out-of-band. First checks the store (the common case), then requests one under a
// bounded timeout. A missing/slow TSA leaves the head pending-anchor and never fails
// the verify. Mirrors the evidence vault's anchoring.
func (s *Service) anchorHead(ctx context.Context, out *VerifiedReport) {
	if s.tsStore == nil || !out.Intact || out.Head == "" {
		return
	}
	if tok, err := s.tsStore.Get(ctx, ChainAudit, "", out.Head); err == nil && tok != nil {
		out.Timestamp, out.Anchored = tok, true
		return
	}
	if s.tsa == nil {
		return
	}
	actx, cancel := context.WithTimeout(ctx, anchorTimeout)
	defer cancel()
	tok, err := s.tsa.Timestamp(actx, []byte(out.Head))
	if err != nil {
		s.logger().Warn("audit head not externally anchored (pending)", "err", err)
		return
	}
	if err := s.tsStore.Put(ctx, ChainAudit, "", out.Head, tok); err != nil {
		s.logger().Error("audit timestamp not stored", "err", err)
	}
	out.Timestamp, out.Anchored = &tok, true
}
