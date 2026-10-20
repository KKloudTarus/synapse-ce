package docpublish

import (
	"context"
	"errors"
	"fmt"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (s *Service) Execute(ctx context.Context, tenant, id shared.ID) (domain.Intent, error) {
	ctx = shared.WithTenant(ctx, tenant)
	if err := ctx.Err(); err != nil {
		return domain.Intent{}, err
	}
	c, err := s.store.GetDocumentCommand(ctx, tenant, id)
	if err != nil {
		return domain.Intent{}, err
	}
	if c.Intent.State == writeintent.Done {
		return c.Intent, nil
	}
	in, err := s.guard(ctx, c)
	if err != nil {
		return c.Intent, err
	}
	if err := ctx.Err(); err != nil {
		return c.Intent, err
	}
	p, err := s.providers.DocumentProvider(ctx, in)
	if err != nil {
		return c.Intent, err
	}
	defer closeProvider(p)
	if c.Progress.Step == "shell" {
		if err := ctx.Err(); err != nil {
			return c.Intent, err
		}
		if err := s.preflightDocumentRelease(ctx, in, c.Intent.Container, c.ReadGroup); err != nil {
			return c.Intent, err
		}
	}
	if c.Intent.State == writeintent.InFlight {
		if c.Intent.LeaseUntil != nil && !s.clock.Now().Before(*c.Intent.LeaseUntil) {
			c.Intent, err = s.store.TransitionIntent(ctx, tenant, id, c.Intent.Version, domain.IntentTransition{Event: writeintent.LeaseExpired}, s.clock.Now().UTC())
			if err != nil {
				return c.Intent, err
			}
		} else {
			return c.Intent, nil
		}
	}
	if c.Intent.State == writeintent.Uncertain {
		if err := ctx.Err(); err != nil {
			return c.Intent, err
		}
		return s.reconcile(ctx, c, p)
	}
	if c.Intent.State == writeintent.Failed {
		// Retrying a classified, definite refusal cannot repeat an unknown write.
		if c.Intent.Attempts >= 5 {
			return c.Intent, nil
		}
		c.Intent, err = s.store.TransitionIntent(ctx, tenant, id, c.Intent.Version, domain.IntentTransition{Event: writeintent.RetryFailed}, s.clock.Now().UTC())
		if err != nil {
			return c.Intent, err
		}
	}
	if c.Intent.State != writeintent.Pending {
		return c.Intent, shared.ErrConflict
	}
	now := s.clock.Now().UTC()
	lease := now.Add(documentLease)
	c.Intent, err = s.store.TransitionIntent(ctx, tenant, id, c.Intent.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		return c.Intent, err
	}
	if c.Intent.Action != domain.Purge {
		if err = validateArtifact(c.Artifact); err != nil {
			return s.refuse(ctx, c, "invalid_artifact")
		}
		if artifactHash(c.Artifact) != c.Intent.ContentHash {
			return s.refuse(ctx, c, "artifact_integrity_failed")
		}
		if err = validateLiterals(p, c.Artifact); err != nil {
			return s.refuse(ctx, c, "unsafe_artifact")
		}
	}
	for step := 0; step < 16; step++ {
		// A canceled caller may not begin another provider operation. A remote
		// acknowledgement is durably checkpointed below with a short detached
		// context before this check can run again.
		if err = ctx.Err(); err != nil {
			return c.Intent, err
		}
		if _, err = s.guard(ctx, c); err != nil {
			return s.refuse(ctx, c, "release_authority_changed")
		}
		if c.Intent.LeaseUntil == nil || !s.clock.Now().Before(*c.Intent.LeaseUntil) {
			return c.Intent, shared.ErrConflict
		}
		switch c.Progress.Step {
		case "shell":
			if c.Intent.Action != domain.Create || c.Progress.Remote.ID != "" {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			if c, err = s.outstanding(ctx, c, "shell", c.Intent.Marker, c.Intent.PayloadDigest); err != nil {
				return c.Intent, err
			}
			if _, err = s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			remote, writeErr := p.CreateDocumentShell(ctx, c.Intent.Container, c.Intent.Marker)
			if writeErr != nil {
				return s.writeFailure(ctx, c, writeErr)
			}
			c.Progress.Remote = remote
			c.Progress.Step = "restrictions"
			return s.checkpointAndYield(ctx, c)
		case "restrictions":
			if err = s.verifyRemote(ctx, c, p); err != nil {
				return s.refuse(ctx, c, "remote_identity_changed")
			}
			if c, err = s.outstanding(ctx, c, "restrictions", c.ReadGroup, digest([]byte(c.ReadGroup))); err != nil {
				return c.Intent, err
			}
			if _, err = s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			if err = p.RestrictDocument(ctx, c.Progress.Remote.ID, c.ReadGroup); err != nil {
				return s.writeFailure(ctx, c, err)
			}
			// If cancellation raced the acknowledgement, persist it without another
			// provider read. A later slice repeats the idempotent restriction and
			// proves the completed neutral shell before content can leave.
			if ctx.Err() != nil {
				return s.checkpointAndYield(ctx, c)
			}
			if err = p.VerifyDocumentRestriction(ctx, c.Progress.Remote.ID, c.Intent.Container, c.ReadGroup); err != nil {
				return s.uncertain(ctx, c)
			}
			// Some providers complete a neutral shell while applying its ACL. Read
			// the exact bound shell back so its final opaque revision fences every
			// attachment and body write. A changed identity, marker, or non-neutral
			// representation can never be adopted as the pending publication.
			refreshed, readErr := p.GetDocument(ctx, c.Progress.Remote.ID)
			if readErr != nil {
				return s.uncertain(ctx, c)
			}
			if refreshed.ID != c.Progress.Remote.ID || refreshed.Container != c.Intent.Container {
				return s.uncertain(ctx, c)
			}
			if c.Intent.Action == domain.Create {
				if !refreshed.Neutral || refreshed.Marker != c.Intent.Marker {
					return s.uncertain(ctx, c)
				}
			} else if !sameRemoteRevision(refreshed.RemotePage, c.Progress.Remote) {
				return s.uncertain(ctx, c)
			}
			c.Progress.Remote = refreshed.RemotePage
			c.Progress.Step = "attachments"
			return s.checkpointAndYield(ctx, c)
		case "attachments":
			files := attachments(c)
			if len(c.Progress.UploadedReceipts) > len(files) {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			if len(c.Progress.UploadedReceipts) == len(files) {
				c.Progress.Step = "body"
				if c, err = s.checkpoint(ctx, c); err != nil {
					return c.Intent, err
				}
				continue
			}
			i := len(c.Progress.UploadedReceipts)
			file := files[i]
			key := uploadKey(i, file)
			if err = s.sensitiveGuard(ctx, c, p); err != nil {
				return s.refuse(ctx, c, "restricted_sharing_unverified")
			}
			if c, err = s.outstanding(ctx, c, "attachment", key, digest(file.Data)); err != nil {
				return c.Intent, err
			}
			if _, err = s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			if err = p.UploadDocumentAttachment(ctx, c.Progress.Remote.ID, file); err != nil {
				return s.writeFailure(ctx, c, err)
			}
			c.Progress.UploadedReceipts = append(c.Progress.UploadedReceipts, ports.DocumentUploadReceipt{Key: key, Digest: digest(file.Data)})
			c.Progress.Uploaded = len(c.Progress.UploadedReceipts)
			return s.checkpointAndYield(ctx, c)
		case "body":
			if err = s.sensitiveGuard(ctx, c, p); err != nil {
				return s.refuse(ctx, c, "restricted_sharing_unverified")
			}
			body := storageDocument(c)
			if c, err = s.outstanding(ctx, c, "body", c.Intent.Marker, digest([]byte(body))); err != nil {
				return c.Intent, err
			}
			if _, err = s.guard(ctx, c); err != nil {
				return s.refuse(ctx, c, "release_authority_changed")
			}
			var remote domain.RemotePage
			var writeErr error
			if c.Progress.Remote.Revision != "" {
				writer, ok := p.(ports.DocumentRevisionWriter)
				if !ok {
					return s.refuse(ctx, c, "unsupported_release_contract")
				}
				remote, writeErr = writer.WriteDocumentRevision(ctx, c.Progress.Remote, c.Artifact.Title, body, c.Intent.Marker)
			} else {
				remote, writeErr = p.WriteDocument(ctx, c.Progress.Remote.ID, c.Progress.Remote.Version, c.Artifact.Title, body, c.Intent.Marker)
			}
			if writeErr != nil {
				return s.writeFailure(ctx, c, writeErr)
			}
			c.Progress.Remote = remote
			c.Progress.Step = "complete"
			return s.checkpointAndYield(ctx, c)
		case "complete":
			if err = s.record(ctx, c, "document.published", c.Progress.Remote.ID); err != nil {
				return c.Intent, err
			}
			return s.store.TransitionIntent(ctx, tenant, id, c.Intent.Version, domain.IntentTransition{Event: writeintent.Acknowledge, Remote: &c.Progress.Remote}, s.clock.Now().UTC())
		case "purge":
			if c.Intent.Action != domain.Purge {
				return s.refuse(ctx, c, "invalid_checkpoint")
			}
			if err = s.verifyRemote(ctx, c, p); err != nil {
				return s.refuse(ctx, c, "remote_identity_changed")
			}
			if c, err = s.outstanding(ctx, c, "purge", c.Progress.Remote.ID, c.Intent.ContentHash); err != nil {
				return c.Intent, err
			}
			if err = p.PurgeDocument(ctx, c.Progress.Remote.ID, func(guardCtx context.Context) error { _, err := s.guard(guardCtx, c); return err }); err != nil {
				return s.writeFailure(ctx, c, err)
			}
			c.Progress.Step = "purged"
			return s.checkpointAndYield(ctx, c)
		case "purged":
			if err = s.record(ctx, c, "document.unpublished", c.Progress.Remote.ID); err != nil {
				return c.Intent, err
			}
			return s.store.TransitionIntent(ctx, tenant, id, c.Intent.Version, domain.IntentTransition{Event: writeintent.Acknowledge, Remote: &c.Progress.Remote}, s.clock.Now().UTC())
		default:
			return s.refuse(ctx, c, "invalid_checkpoint")
		}
	}
	return c.Intent, fmt.Errorf("%w: document checkpoint bound exceeded", shared.ErrConflict)
}

// checkpointAndYield stores an acknowledged provider effect before handing the
// command back to the queue. The detached, bounded context is deliberately
// limited to local persistence: a caller cancellation must not cause a second
// provider request after the first has been acknowledged.
func (s *Service) checkpointAndYield(ctx context.Context, c ports.DocumentCommand) (domain.Intent, error) {
	localCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	checkpointed, err := s.checkpoint(localCtx, c)
	if err != nil {
		return c.Intent, err
	}
	yielded, err := s.store.YieldDocumentCommand(
		localCtx,
		checkpointed.Intent.TenantID,
		checkpointed.Intent.ID,
		checkpointed.Intent.Version,
		checkpointed.Progress.Version,
		s.clock.Now().UTC(),
	)
	if err != nil {
		return checkpointed.Intent, err
	}
	return yielded.Intent, nil
}

func (s *Service) sensitiveGuard(ctx context.Context, c ports.DocumentCommand, p ports.DocumentProvider) error {
	if _, err := s.guard(ctx, c); err != nil {
		return err
	}
	if err := s.verifyRemote(ctx, c, p); err != nil {
		return err
	}
	return p.VerifyDocumentRestriction(ctx, c.Progress.Remote.ID, c.Intent.Container, c.ReadGroup)
}
func (s *Service) verifyRemote(ctx context.Context, c ports.DocumentCommand, p ports.DocumentProvider) error {
	remote, err := p.GetDocument(ctx, c.Progress.Remote.ID)
	if err != nil {
		return err
	}
	if remote.ID != c.Progress.Remote.ID || remote.Container != c.Intent.Container {
		return shared.ErrConflict
	}
	// A provider may expose a durable folder reservation before the neutral body
	// exists. It is usable only for the still-neutral restriction checkpoint and
	// only when the intent marker binds it to this command. After restriction we
	// refresh and freeze the actual body revision above.
	if remote.Neutral && remote.Marker == c.Intent.Marker && c.Progress.Step == "restrictions" {
		return nil
	}
	if !sameRemoteRevision(remote.RemotePage, c.Progress.Remote) {
		return shared.ErrConflict
	}
	return nil
}
func (s *Service) outstanding(ctx context.Context, c ports.DocumentCommand, operation, key, hash string) (ports.DocumentCommand, error) {
	c.Progress.OutstandingOperation = operation
	c.Progress.OutstandingKey = key
	c.Progress.OutstandingDigest = hash
	c.Progress.ExpectedRemoteVersion = c.Progress.Remote.Version
	c.Progress.ExpectedRemoteRevision = c.Progress.Remote.Revision
	return s.saveProgress(ctx, c)
}
func (s *Service) checkpoint(ctx context.Context, c ports.DocumentCommand) (ports.DocumentCommand, error) {
	c.Progress.OutstandingOperation = ""
	c.Progress.OutstandingKey = ""
	c.Progress.OutstandingDigest = ""
	c.Progress.ExpectedRemoteVersion = 0
	c.Progress.ExpectedRemoteRevision = ""
	return s.saveProgress(ctx, c)
}
func (s *Service) saveProgress(ctx context.Context, c ports.DocumentCommand) (ports.DocumentCommand, error) {
	c.Progress.IntentVersion = c.Intent.Version
	c.Progress.LeaseUntil = c.Intent.LeaseUntil
	c.Progress.UpdatedAt = s.clock.Now().UTC()
	return s.store.SaveDocumentProgress(ctx, c.Intent.TenantID, c.Intent.ID, c.Progress.Version, c.Progress)
}
func (s *Service) refuse(ctx context.Context, c ports.DocumentCommand, code string) (domain.Intent, error) {
	if c.Progress.OutstandingOperation != "" {
		var err error
		c, err = s.checkpoint(ctx, c)
		if err != nil {
			return c.Intent, err
		}
	}
	return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.Reject, ErrorCode: code}, s.clock.Now().UTC())
}
func (s *Service) writeFailure(ctx context.Context, c ports.DocumentCommand, cause error) (domain.Intent, error) {
	var classified *ports.DocumentProviderError
	if errors.As(cause, &classified) && !classified.Ambiguous {
		return s.refuse(ctx, c, "provider_refused")
	}
	return s.uncertain(ctx, c)
}

// uncertain keeps the stored operation fence when an acknowledged mutation can
// no longer be verified. A later read refusal cannot undo its remote effect.
func (s *Service) uncertain(ctx context.Context, c ports.DocumentCommand) (domain.Intent, error) {
	return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.Ambiguous}, s.clock.Now().UTC())
}
