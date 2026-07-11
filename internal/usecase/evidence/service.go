// Package evidence is the tamper-evident evidence vault: it appends sealed,
// hash-chained links, stores artifacts content-addressed in a blob store, and
// verifies the chain on read – emitting an append-only tamper ALERT on any
// mismatch. SCA, recon, and manual capture all
// funnel through it, so there is ONE chain and one verify path per engagement.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service is the evidence vault use case.
type Service struct {
	store   ports.EvidenceStore
	blobs   ports.BlobStore // optional; nil disables artifact capture/retrieval
	audit   ports.AuditLogger
	clock   ports.Clock
	ids     ports.IDGenerator
	signer  ports.ChainSigner        // optional; nil disables chain-head attestation
	tsa     ports.TimestampAuthority // optional; nil disables external RFC-3161 anchoring
	tsStore ports.TimestampStore     // optional; the out-of-band token store
	log     *slog.Logger             // optional; defaults to slog.Default()
}

// anchorTimeout bounds the per-call wait on the TSA so a slow/down authority never
// hangs the seal/verify path (the report still succeeds, the
// head just stays pending-anchor).
const anchorTimeout = 5 * time.Second

// SetLogger sets the logger used to surface dropped audit/alert writes (a dropped
// tamper alert must not vanish silently). Optional – defaults to slog.Default().
func (s *Service) SetLogger(l *slog.Logger) { s.log = l }

// SetSigner enables chain-head attestation: when set, Verify attaches
// a deterministic ed25519 signature over the chain head, proving origin on top of
// integrity. Optional – nil leaves the chain integrity-only.
func (s *Service) SetSigner(signer ports.ChainSigner) { s.signer = signer }

// SetTimestamper enables external RFC-3161 anchoring: when both are set, Verify
// attaches a trusted timestamp over the verified head (tamper-PROOF, not just
// tamper-evident). The token is stored + returned OUT-OF-BAND so report bytes are
// unchanged. Best-effort + bounded: an unreachable TSA leaves the head
// pending-anchor, never failing the verify/report.
func (s *Service) SetTimestamper(tsa ports.TimestampAuthority, store ports.TimestampStore) {
	s.tsa, s.tsStore = tsa, store
}

// AttestationEnabled reports whether chain-head attestation (signer) or external anchoring
// (TSA) is wired. It is the cue for a writer such as the recon worker to proactively
// Verify+attest+anchor a head it just sealed (tamper-proof at seal time), rather than leaving
// the head un-anchored until a later read. False ⇒ a proactive Verify would only add a chain
// read with no attestation, so the caller can skip it.
func (s *Service) AttestationEnabled() bool { return s.signer != nil || s.tsa != nil }

func (s *Service) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}
	return slog.Default()
}

// NewService validates its dependencies and returns the vault. blobs may be nil
// (artifact capture is then unavailable, but sealing + verification still work).
func NewService(store ports.EvidenceStore, blobs ports.BlobStore, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: evidence vault requires store, audit, clock, and ids", shared.ErrValidation)
	}
	return &Service{store: store, blobs: blobs, audit: audit, clock: clock, ids: ids}, nil
}

// Report is an engagement's evidence ledger plus its verification status. When a
// signer is configured and the chain is intact, Attestation carries a detached
// ed25519 signature over Head (origin / non-repudiation).
type Report struct {
	Items       []evdom.Evidence   `json:"items"`
	Intact      bool               `json:"intact"`
	Head        string             `json:"head"`
	Verified    int                `json:"verified"` // number of links in the chain
	Error       string             `json:"error,omitempty"`
	Attestation *evdom.Attestation `json:"attestation,omitempty"`
	// Anchored is true when Head carries an external RFC-3161 timestamp (tamper-proof);
	// Timestamp is that token. Both empty/false = tamper-evident + signed only.
	Anchored  bool                  `json:"anchored"`
	Timestamp *ports.TimestampToken `json:"timestamp,omitempty"`
}

// artifactPayload is the canonical sealed content for a captured artifact. The
// blob's sha256 is INSIDE the sealed content, so tampering the stored blob is
// detectable against the chain.
type artifactPayload struct {
	Kind       string `json:"kind"`
	Filename   string `json:"filename,omitempty"`
	Note       string `json:"note,omitempty"`
	BlobSHA256 string `json:"blob_sha256"`
	Size       int    `json:"size"`
	CapturedAt string `json:"captured_at"`
}

// Seal appends one sealed link (kind + canonical content) bound to the chain head.
// Used by SCA scan summaries and recon.
func (s *Service) Seal(ctx context.Context, engagementID shared.ID, kind string, content []byte, createdBy string) (evdom.Evidence, error) {
	return s.sealRef(ctx, engagementID, kind, content, "", createdBy)
}

func (s *Service) sealRef(ctx context.Context, engagementID shared.ID, kind string, content []byte, storageRef, createdBy string) (evdom.Evidence, error) {
	// Concurrency-safe append: two writers (e.g. the API + the worker) sealing to
	// the same engagement chain can both read the same head and FORK it. The store enforces
	// one child per parent (unique engagement+previous_hash → ErrConflict); on conflict we
	// re-read the now-advanced head and re-chain, so the chain stays strictly linear under
	// multi-writer contention – never a forked (corrupt) custody chain.
	const maxAttempts = 16
	for attempt := 0; ; attempt++ {
		prev, err := s.store.Head(ctx, engagementID)
		if err != nil {
			// Never fork the append-only chain with an empty previous_hash on a transient
			// Head failure – fail the seal instead.
			return evdom.Evidence{}, fmt.Errorf("evidence head: %w", err)
		}
		link := evdom.Evidence{
			ID:           s.ids.NewID(),
			EngagementID: engagementID,
			Kind:         kind,
			Content:      content,
			StorageRef:   storageRef,
			PreviousHash: prev,
			CreatedBy:    createdBy,
			CreatedAt:    s.clock.Now(),
		}.Seal()
		err = s.store.Append(ctx, []evdom.Evidence{link})
		if err == nil {
			// Retain (externally anchor) the freshly-sealed head so out-of-band tail-truncation
			// detection covers EVERY writer's heads – recon, SCA, manual capture, agent – not
			// just paths that later call Verify. Best-effort + bounded; no-op without a TSA.
			s.anchorSealedHead(ctx, engagementID, link.Hash)
			return link, nil
		}
		if errors.Is(err, shared.ErrConflict) && attempt < maxAttempts {
			continue // another writer linked this head first – re-read + re-chain
		}
		return evdom.Evidence{}, fmt.Errorf("append evidence: %w", err)
	}
}

// CaptureArtifact stores a binary artifact content-addressed in the blob store and
// seals an evidence link referencing it by sha256, then audits the capture. The
// engagement owns the chain; kind tags the evidence (screenshot|http|terminal_log|…).
func (s *Service) CaptureArtifact(ctx context.Context, engagementID shared.ID, actor, kind, filename string, data []byte, note string) (evdom.Evidence, error) {
	if s.blobs == nil {
		return evdom.Evidence{}, fmt.Errorf("%w: artifact storage is not configured", shared.ErrValidation)
	}
	if len(data) == 0 {
		return evdom.Evidence{}, fmt.Errorf("%w: artifact is empty", shared.ErrValidation)
	}
	sum := sha256.Sum256(data)
	blobSHA := hex.EncodeToString(sum[:])
	if err := s.blobs.Put(ctx, blobSHA, data); err != nil {
		return evdom.Evidence{}, fmt.Errorf("store artifact: %w", err)
	}
	payload, err := json.Marshal(artifactPayload{
		Kind:       kind,
		Filename:   filename,
		Note:       note,
		BlobSHA256: blobSHA,
		Size:       len(data),
		CapturedAt: s.clock.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return evdom.Evidence{}, fmt.Errorf("marshal artifact payload: %w", err)
	}
	link, err := s.sealRef(ctx, engagementID, kind, payload, blobSHA, actor)
	if err != nil {
		return evdom.Evidence{}, err
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   "evidence.captured",
		Target:   engagementID.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "kind": kind, "blob_sha256": blobSHA},
		At:       s.clock.Now(),
	}); err != nil {
		s.logger().Error("evidence capture not audited", "engagement", engagementID.String(), "err", err)
	}
	return link, nil
}

// Verify lists the chain, verifies it, and on a mismatch records an append-only
// tamper ALERT before returning Intact=false. This is the single
// verify-on-read path used by the API and before any report is produced.
func (s *Service) Verify(ctx context.Context, engagementID shared.ID) (Report, error) {
	items, err := s.store.ListByEngagement(ctx, engagementID)
	if err != nil {
		return Report{}, fmt.Errorf("list evidence: %w", err)
	}
	rep := Report{Items: items, Verified: len(items), Intact: true}
	if len(items) > 0 {
		rep.Head = items[len(items)-1].Hash
	}
	if err := evdom.VerifyChain(items); err != nil {
		rep.Intact = false
		rep.Error = err.Error()
		s.alertTampered(ctx, engagementID, err)
		return rep, nil
	}
	// Out-of-band TAIL-TRUNCATION detection: the append-only trigger (migration 0033)
	// blocks an in-band DELETE, but a superuser who disables the trigger could delete the tail –
	// and VerifyChain on the shortened-but-still-linear chain would pass. Every sealed head is
	// anchored, so its hash is RETAINED out-of-band in the timestamp store; if the latest retained
	// head is no longer present in the current chain, links were truncated from the end. Detect it.
	if s.tsStore != nil {
		if retained, ok, herr := s.tsStore.LatestHead(ctx, ChainEvidence, engagementID); herr == nil && ok && retained != "" && !containsHash(items, retained) {
			rep.Intact = false
			rep.Error = "tail-truncation detected: a retained (externally-anchored) head is missing from the chain"
			s.alertTampered(ctx, engagementID, errors.New(rep.Error))
			return rep, nil
		}
	}
	// Attest the verified head: a deterministic signature proving this chain
	// originated here. Only on an intact, non-empty chain – never sign a broken or
	// empty head. A signing failure is non-fatal: integrity still holds, so the
	// report is returned without an attestation rather than failing the read.
	if s.signer != nil && rep.Head != "" {
		att, err := s.signer.Sign(ctx, rep.Head)
		if err != nil {
			s.logger().Error("evidence head not attested", "engagement", engagementID.String(), "err", err)
		} else {
			rep.Attestation = &att
		}
	}
	// External anchor: attach an RFC-3161 timestamp over the verified head,
	// out-of-band so report bytes are unchanged. Best-effort + bounded.
	s.anchorHead(ctx, ChainEvidence, engagementID, &rep)
	return rep, nil
}

// ChainEvidence/ChainAudit name the two custody chains in the out-of-band token store.
const ChainEvidence = "evidence"

// anchorHead attaches an external RFC-3161 timestamp to an intact, non-empty head: it
// first looks for an already-stored token (cheap, the common case), and only if absent
// requests one from the TSA under a bounded timeout and stores it. A missing/slow TSA
// leaves the head pending-anchor (Anchored=false) and never fails the caller – the
// report still succeeds. Exported as AnchorHead for the audit service
// to reuse the same logic over its head.
func (s *Service) anchorHead(ctx context.Context, chain string, engagementID shared.ID, rep *Report) {
	if s.tsStore == nil || !rep.Intact || rep.Head == "" {
		return
	}
	if tok, err := s.tsStore.Get(ctx, chain, engagementID, rep.Head); err == nil && tok != nil {
		rep.Timestamp, rep.Anchored = tok, true
		return
	}
	if s.tsa == nil {
		return // a store but no authority can only attach already-anchored tokens
	}
	actx, cancel := context.WithTimeout(ctx, anchorTimeout)
	defer cancel()
	tok, err := s.tsa.Timestamp(actx, []byte(rep.Head))
	if err != nil {
		s.logger().Warn("evidence head not externally anchored (pending)", "engagement", engagementID.String(), "err", err)
		return
	}
	if err := s.tsStore.Put(ctx, chain, engagementID, rep.Head, tok); err != nil {
		s.logger().Error("evidence timestamp not stored", "engagement", engagementID.String(), "err", err)
	}
	rep.Timestamp, rep.Anchored = &tok, true
}

// anchorSealedHead externally timestamps (RFC-3161) a freshly-sealed head so it is RETAINED
// out-of-band in the token store – the basis for tail-truncation detection over EVERY writer's
// heads, not only paths that later call Verify. Best-effort + bounded; a no-op when no TSA is
// configured (the in-band 0033 append-only trigger still applies) and never fails the seal.
func (s *Service) anchorSealedHead(ctx context.Context, engagementID shared.ID, head string) {
	if s.tsa == nil || s.tsStore == nil || head == "" {
		return
	}
	if tok, err := s.tsStore.Get(ctx, ChainEvidence, engagementID, head); err == nil && tok != nil {
		return // already retained
	}
	actx, cancel := context.WithTimeout(ctx, anchorTimeout)
	defer cancel()
	tok, err := s.tsa.Timestamp(actx, []byte(head))
	if err != nil {
		s.logger().Warn("sealed head not externally anchored (pending)", "engagement", engagementID.String(), "err", err)
		return
	}
	if err := s.tsStore.Put(ctx, ChainEvidence, engagementID, head, tok); err != nil {
		s.logger().Error("sealed head timestamp not stored", "engagement", engagementID.String(), "err", err)
	}
}

// containsHash reports whether any chain item carries the given head hash – used by
// tail-truncation detection to confirm a retained (anchored) head is still present.
func containsHash(items []evdom.Evidence, h string) bool {
	for i := range items {
		if items[i].Hash == h {
			return true
		}
	}
	return false
}

// List returns the engagement's chain (oldest first) for the timeline.
func (s *Service) List(ctx context.Context, engagementID shared.ID) ([]evdom.Evidence, error) {
	return s.store.ListByEngagement(ctx, engagementID)
}

var _ ports.ReportEvidenceProvider = (*Service)(nil)

// ListArtifacts returns the captured binary artifacts in the engagement's chain
// (oldest first), parsed from their sealed payloads – for the report's evidence
// exhibits. Only links that reference an out-of-line blob (StorageRef set) are
// artifacts; sealed scan/summary links are skipped.
func (s *Service) ListArtifacts(ctx context.Context, engagementID shared.ID) ([]ports.EvidenceArtifact, error) {
	items, err := s.store.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	var out []ports.EvidenceArtifact
	for _, it := range items {
		if it.StorageRef == "" {
			continue
		}
		var p artifactPayload
		if err := json.Unmarshal(it.Content, &p); err != nil {
			continue // tolerate a non-artifact payload that happens to carry a ref
		}
		out = append(out, ports.EvidenceArtifact{
			Kind:     p.Kind,
			Filename: p.Filename,
			Note:     p.Note,
			SHA256:   it.StorageRef,
			Size:     p.Size,
		})
	}
	return out, nil
}

// ArtifactBytes returns a captured artifact's bytes, engagement-scoped and
// re-verified against its sha (the vault's tamper-checked read path).
func (s *Service) ArtifactBytes(ctx context.Context, engagementID shared.ID, sha256hex string) ([]byte, error) {
	return s.ArtifactForEngagement(ctx, engagementID, sha256hex)
}

// ImportVerified re-verifies a hash chain and, only if it is intact, appends it
// verbatim (hashes + content preserved) to the ledger. Used by engagement import
// a bundle whose chain does not verify is rejected before any write, so a
// tampered chain can never be materialized. Callers may remap EngagementID/ID/
// FindingID first – those fields are not part of the chain hash, so the chain still
// verifies.
func (s *Service) ImportVerified(ctx context.Context, items []evdom.Evidence) error {
	if err := evdom.VerifyChain(items); err != nil {
		return fmt.Errorf("%w: imported evidence chain failed verification – import rejected", shared.ErrValidation)
	}
	if len(items) == 0 {
		return nil
	}
	// Import only into an engagement with NO existing chain (audit): the imported chain
	// carries its own genesis (previous_hash=""), so merging it onto a non-empty chain would
	// create two genesis links – which the fork-guard (unique engagement+previous_hash)
	// rejects on Postgres AND the in-memory guard rejects too. Check upfront for a CLEAR
	// error rather than a generic append conflict; re-basing isn't an option (it would
	// change previous_hash and break the verified seals).
	head, err := s.store.Head(ctx, items[0].EngagementID)
	if err != nil {
		return fmt.Errorf("evidence head: %w", err)
	}
	if head != "" {
		return fmt.Errorf("%w: cannot import an evidence chain onto an engagement that already has evidence", shared.ErrConflict)
	}
	if err := s.store.Append(ctx, items); err != nil {
		return fmt.Errorf("append imported evidence: %w", err)
	}
	return nil
}

// ArtifactForEngagement returns a captured artifact's bytes – but ONLY if a sealed
// link in that engagement's chain references the blob. This scopes reads to the
// engagement (no cross-engagement custody leak) and closes the existence oracle a
// global-by-sha lookup would expose. The sha must be a 64-char lowercase hex
// digest; the bytes are re-verified against it on read (tamper check).
func (s *Service) ArtifactForEngagement(ctx context.Context, engagementID shared.ID, sha256hex string) ([]byte, error) {
	if s.blobs == nil {
		return nil, fmt.Errorf("%w: artifact storage is not configured", shared.ErrValidation)
	}
	if !isSHA256Hex(sha256hex) {
		return nil, fmt.Errorf("%w: artifact id must be a sha256 hex digest", shared.ErrValidation)
	}
	items, err := s.store.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	referenced := false
	for _, it := range items {
		if it.StorageRef == sha256hex {
			referenced = true
			break
		}
	}
	if !referenced {
		return nil, fmt.Errorf("%w: artifact is not in this engagement's chain", shared.ErrNotFound)
	}
	data, err := s.blobs.Get(ctx, sha256hex)
	if err != nil {
		return nil, fmt.Errorf("get artifact: %w", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != sha256hex {
		return nil, fmt.Errorf("%w: artifact bytes do not match their hash (tampered)", evdom.ErrChainBroken)
	}
	return data, nil
}

// isSHA256Hex reports whether s is exactly 64 lowercase hex chars.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// alertTampered records the tamper alert on the append-only audit log. Best-effort:
// a failed alert write must not mask the tamper (the caller still gets Intact=false).
func (s *Service) alertTampered(ctx context.Context, engagementID shared.ID, cause error) {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    "system",
		Action:   "evidence.tampered",
		Target:   engagementID.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "error": cause.Error()},
		At:       s.clock.Now(),
	}); err != nil {
		// A dropped tamper alert must not vanish silently – it is the custody signal.
		s.logger().Error("evidence tamper alert not recorded", "engagement", engagementID.String(), "err", err)
	}
}
