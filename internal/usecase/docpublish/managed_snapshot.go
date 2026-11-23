package docpublish

import (
	"context"
	"fmt"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// executeManagedSnapshot makes every provider mutation a separately guarded
// checkpoint.  In particular, an interrupted send or append remains uncertain:
// allocation receipts alone never authorize repeating a possibly applied write.
func (s *Service) executeManagedSnapshot(ctx context.Context, c ports.DocumentCommand, p ports.DocumentSnapshotProvider) (domain.Intent, error) {
	if c.Intent.Action != domain.Create && c.Intent.Action != domain.Snapshot && c.Intent.Action != domain.Trash {
		return s.refuse(ctx, c, "unsupported_release_contract")
	}
	if c.Intent.Action != domain.Trash && p.ValidateDocumentSnapshot(c.Artifact) != nil {
		return s.refuse(ctx, c, "invalid_artifact")
	}
	for step := 0; step < 24; step++ {
		if err := ctx.Err(); err != nil {
			return c.Intent, err
		}
		if _, err := s.guard(ctx, c); err != nil {
			return s.refuse(ctx, c, "release_authority_changed")
		}
		if c.Progress.Step != "snapshot_shell" && c.Progress.Step != "snapshot_observe" && c.Progress.Step != "trash_confirm" {
			if err := s.managedSnapshotGuard(ctx, c, p); err != nil {
				if deferred, deferErr, handled := s.deferProviderRetry(ctx, c, err, ports.DocumentRetryRelease, ""); handled {
					return deferred, deferErr
				}
				return s.refuse(ctx, c, "remote_identity_changed")
			}
		}
		if c.Intent.LeaseUntil == nil || !s.clock.Now().Before(*c.Intent.LeaseUntil) {
			return c.Intent, shared.ErrConflict
		}
		if c.Intent.Action == domain.Trash {
			switch c.Progress.Step {
			case "trash":
				checkpointed, err := s.outstanding(ctx, c, "trash", c.Progress.Remote.ID, c.Intent.ContentHash)
				if err != nil {
					return c.Intent, err
				}
				c = checkpointed
				if _, err := s.guard(ctx, c); err != nil {
					return s.refuse(ctx, c, "release_authority_changed")
				}
				if err := p.TrashDocument(ctx, c.Progress.Remote); err != nil {
					return s.writeFailure(ctx, c, err)
				}
				c.Progress.Step = "trash_confirm"
				return s.checkpointAndYield(ctx, c)
			case "trash_confirm":
				ok, err := p.ConfirmDocumentTrash(ctx, c.Progress.Remote.ID, c.Intent.Container)
				if err != nil {
					if deferred, deferErr, handled := s.deferProviderRetry(ctx, c, err, ports.DocumentRetryRelease, ""); handled {
						return deferred, deferErr
					}
					return s.uncertain(ctx, c)
				}
				if !ok {
					return s.uncertain(ctx, c)
				}
				if err := s.record(ctx, c, "document.trashed", c.Progress.Remote.ID); err != nil {
					return c.Intent, err
				}
				return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.Acknowledge, Remote: &c.Progress.Remote}, s.clock.Now().UTC())
			default:
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
		}
		files := attachments(c)
		switch c.Progress.Step {
		case "snapshot_shell":
			if c.Progress.Remote.ID != "" {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			sheller, ok := any(p).(interface {
				CreateDocumentShell(context.Context, string, string) (domain.RemotePage, error)
			})
			if !ok {
				return s.refuse(ctx, c, "unsupported_release_contract")
			}
			checkpointed, err := s.outstanding(ctx, c, "snapshot_shell", c.Intent.Marker, c.Intent.PayloadDigest)
			if err != nil {
				return c.Intent, err
			}
			c = checkpointed
			if _, err := s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			remote, err := sheller.CreateDocumentShell(ctx, c.Intent.Container, c.Intent.Marker)
			if err != nil {
				return s.writeFailure(ctx, c, err)
			}
			c.Progress.Remote, c.Progress.Step = remote, "snapshot_observe"
			return s.checkpointAndYield(ctx, c)
		case "snapshot_observe":
			state, err := p.ObserveDocumentDestination(ctx, c.Progress.Remote.ID, c.Intent.Container)
			if err != nil {
				if deferred, deferErr, handled := s.deferProviderRetry(ctx, c, err, ports.DocumentRetryRelease, ""); handled {
					return deferred, deferErr
				}
				return s.uncertain(ctx, c)
			}
			if state.ID != c.Progress.Remote.ID || state.Container != c.Intent.Container || state.Marker != c.Intent.Marker || !state.Neutral {
				return s.uncertain(ctx, c)
			}
			c.Progress.Remote, c.Progress.Step = state.RemotePage, "snapshot_uploads"
			return s.checkpointAndYield(ctx, c)
		case "snapshot_uploads":
			if len(c.Progress.UploadedReceipts) > len(files) || c.Progress.Uploaded > len(c.Progress.UploadedReceipts) {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			if c.Progress.Uploaded < len(c.Progress.UploadedReceipts) {
				c.Progress.Step = "snapshot_upload_send"
				checkpointed, err := s.checkpoint(ctx, c)
				if err != nil {
					return c.Intent, err
				}
				c = checkpointed
				continue
			}
			if len(c.Progress.UploadedReceipts) == len(files) {
				c.Progress.Step = "snapshot_append"
				checkpointed, err := s.checkpoint(ctx, c)
				if err != nil {
					return c.Intent, err
				}
				c = checkpointed
				continue
			}
			i := len(c.Progress.UploadedReceipts)
			file := files[i]
			key := uploadKey(i, file)
			checkpointed, err := s.outstanding(ctx, c, "snapshot_upload_allocate", key, digest(file.Data))
			if err != nil {
				return c.Intent, err
			}
			c = checkpointed
			if _, err := s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			id, err := p.AllocateDocumentUpload(ctx, file)
			if err != nil {
				return s.writeFailure(ctx, c, err)
			}
			if strings.TrimSpace(id) == "" || len(id) > 512 {
				return s.refuse(ctx, c, "provider_refused")
			}
			c.Progress.UploadedReceipts = append(c.Progress.UploadedReceipts, ports.DocumentUploadReceipt{Key: key, Digest: digest(file.Data), UploadID: id})
			c.Progress.Step = "snapshot_upload_send"
			return s.checkpointAndYield(ctx, c)
		case "snapshot_upload_send":
			if c.Progress.Uploaded >= len(c.Progress.UploadedReceipts) || c.Progress.Uploaded >= len(files) {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			i := c.Progress.Uploaded
			file, receipt := files[i], c.Progress.UploadedReceipts[i]
			if receipt.Key != uploadKey(i, file) || receipt.Digest != digest(file.Data) || receipt.UploadID == "" {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			checkpointed, err := s.outstanding(ctx, c, "snapshot_upload_send", receipt.UploadID, receipt.Digest)
			if err != nil {
				return c.Intent, err
			}
			c = checkpointed
			if _, err := s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			if err := p.SendDocumentUpload(ctx, receipt.UploadID, file); err != nil {
				return s.writeFailure(ctx, c, err)
			}
			c.Progress.Uploaded++
			c.Progress.Step = "snapshot_uploads"
			return s.checkpointAndYield(ctx, c)
		case "snapshot_append":
			if c.Progress.SnapshotReceipt != nil || c.Progress.Uploaded != len(files) {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			checkpointed, err := s.outstanding(ctx, c, "snapshot_append", c.Intent.Marker, c.Intent.ContentHash)
			if err != nil {
				return c.Intent, err
			}
			c = checkpointed
			if _, err := s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			receipt, err := p.AppendDocumentSnapshot(ctx, c.Progress.Remote, c.Artifact, c.Progress.UploadedReceipts, c.Intent.Marker, c.Intent.ContentHash)
			if err != nil {
				return s.writeFailure(ctx, c, err)
			}
			if !validSnapshotReceipt(receipt) {
				return s.uncertain(ctx, c)
			}
			c.Progress.SnapshotReceipt = &receipt
			c.Progress.Remote = receipt.Remote
			c.Progress.Step = "snapshot_title"
			return s.checkpointAndYield(ctx, c)
		case "snapshot_title":
			if c.Progress.SnapshotReceipt == nil {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			checkpointed, err := s.outstanding(ctx, c, "snapshot_title", c.Progress.Remote.ID, digest([]byte(c.Artifact.Title)))
			if err != nil {
				return c.Intent, err
			}
			c = checkpointed
			if _, err := s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			remote, err := p.SetDocumentSnapshotTitle(ctx, c.Progress.Remote, c.Artifact.Title)
			if err != nil {
				return s.writeFailure(ctx, c, err)
			}
			c.Progress.Remote = remote
			c.Progress.SnapshotReceipt.Remote = remote
			c.Progress.Step = "snapshot_verify"
			return s.checkpointAndYield(ctx, c)
		case "snapshot_verify":
			if c.Progress.SnapshotReceipt == nil {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			remote, err := p.VerifyDocumentSnapshot(ctx, c.Progress.Remote.ID, *c.Progress.SnapshotReceipt, c.Intent.Marker)
			if err != nil {
				if deferred, deferErr, handled := s.deferProviderRetry(ctx, c, err, ports.DocumentRetryRelease, ""); handled {
					return deferred, deferErr
				}
				return s.uncertain(ctx, c)
			}
			if remote != c.Progress.Remote {
				return s.uncertain(ctx, c)
			}
			if err := s.record(ctx, c, "document.published", remote.ID); err != nil {
				return c.Intent, err
			}
			return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.Acknowledge, Remote: &remote}, s.clock.Now().UTC())
		default:
			return s.refuse(ctx, c, "invalid_checkpoint")
		}
	}
	return c.Intent, fmt.Errorf("%w: managed document checkpoint bound exceeded", shared.ErrConflict)
}

// managedSnapshotGuard proves only the exact destination identity and marker;
// it deliberately does not represent an ACL proof. The normal guard runs both
// before this observation and immediately before each mutation.
func (s *Service) managedSnapshotGuard(ctx context.Context, c ports.DocumentCommand, p ports.DocumentSnapshotProvider) error {
	if _, err := s.guard(ctx, c); err != nil {
		return err
	}
	state, err := p.ObserveDocumentDestination(ctx, c.Progress.Remote.ID, c.Intent.Container)
	if err != nil {
		return err
	}
	if state.ID != c.Progress.Remote.ID || state.Container != c.Intent.Container || (c.Intent.Action != domain.Trash && state.Marker != c.Intent.Marker) || !sameRemoteRevision(state.RemotePage, c.Progress.Remote) {
		return shared.ErrConflict
	}
	if _, err := s.guard(ctx, c); err != nil {
		return err
	}
	return nil
}

func validSnapshotReceipt(r ports.DocumentSnapshotReceipt) bool {
	if r.Digest == "" || len(r.Digest) != 64 || len(r.BlockIDs) < 1 || len(r.BlockIDs) > 100 || r.Remote.ID == "" || r.Remote.Version < 1 {
		return false
	}
	for _, id := range r.BlockIDs {
		if strings.TrimSpace(id) == "" || len(id) > 512 {
			return false
		}
	}
	return true
}
