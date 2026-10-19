package docpublish

import (
	"context"
	"errors"
	"fmt"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (s *Service) Execute(ctx context.Context, tenant, id shared.ID) (domain.Intent, error) {
	ctx = shared.WithTenant(ctx, tenant)
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
	p, err := s.providers.DocumentProvider(ctx, in)
	if err != nil {
		return c.Intent, err
	}
	defer closeProvider(p)
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
			if c, err = s.checkpoint(ctx, c); err != nil {
				return c.Intent, err
			}
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
			if err = p.VerifyDocumentRestriction(ctx, c.Progress.Remote.ID, c.Intent.Container, c.ReadGroup); err != nil {
				return s.writeFailure(ctx, c, err)
			}
			c.Progress.Step = "attachments"
			if c, err = s.checkpoint(ctx, c); err != nil {
				return c.Intent, err
			}
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
			if c, err = s.checkpoint(ctx, c); err != nil {
				return c.Intent, err
			}
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
			remote, writeErr := p.WriteDocument(ctx, c.Progress.Remote.ID, c.Progress.Remote.Version, c.Artifact.Title, body, c.Intent.Marker)
			if writeErr != nil {
				return s.writeFailure(ctx, c, writeErr)
			}
			c.Progress.Remote = remote
			c.Progress.Step = "complete"
			if c, err = s.checkpoint(ctx, c); err != nil {
				return c.Intent, err
			}
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
			if c, err = s.checkpoint(ctx, c); err != nil {
				return c.Intent, err
			}
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
	if remote.ID != c.Progress.Remote.ID || remote.Container != c.Intent.Container || remote.Version != c.Progress.Remote.Version {
		return shared.ErrConflict
	}
	return nil
}
func (s *Service) outstanding(ctx context.Context, c ports.DocumentCommand, operation, key, hash string) (ports.DocumentCommand, error) {
	c.Progress.OutstandingOperation = operation
	c.Progress.OutstandingKey = key
	c.Progress.OutstandingDigest = hash
	c.Progress.ExpectedRemoteVersion = c.Progress.Remote.Version
	return s.saveProgress(ctx, c)
}
func (s *Service) checkpoint(ctx context.Context, c ports.DocumentCommand) (ports.DocumentCommand, error) {
	c.Progress.OutstandingOperation = ""
	c.Progress.OutstandingKey = ""
	c.Progress.OutstandingDigest = ""
	c.Progress.ExpectedRemoteVersion = 0
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
	return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.Ambiguous}, s.clock.Now().UTC())
}
