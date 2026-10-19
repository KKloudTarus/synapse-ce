package docpublish

import (
	"context"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (s *Service) reconcile(ctx context.Context, c ports.DocumentCommand, p ports.DocumentProvider) (domain.Intent, error) {
	if c.Intent.State != writeintent.Uncertain {
		return c.Intent, shared.ErrConflict
	}
	if c.Intent.Action != domain.Purge && (validateArtifact(c.Artifact) != nil || artifactHash(c.Artifact) != c.Intent.ContentHash) {
		return c.Intent, shared.ErrConflict
	}
	if c.Progress.Step == "purged" && c.Progress.OutstandingOperation == "" {
		if err := s.record(ctx, c, "document.unpublished", c.Progress.Remote.ID); err != nil {
			return c.Intent, err
		}
		return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.ReconcileFound, Remote: &c.Progress.Remote}, s.clock.Now().UTC())
	}
	if c.Progress.OutstandingOperation == "shell" {
		matches, err := p.FindDocumentMarker(ctx, c.Intent.Container, c.Intent.Marker)
		if err != nil {
			return c.Intent, err
		}
		if len(matches) > 1 {
			return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.ReconcileMultiple}, s.clock.Now().UTC())
		}
		// An eventually consistent zero-result search proves no absence. Only
		// one exact neutral shell can resolve this particular outstanding write.
		if len(matches) != 1 || !matches[0].Neutral || matches[0].Container != c.Intent.Container || matches[0].Marker != c.Intent.Marker {
			return c.Intent, nil
		}
		c.Progress.Remote = matches[0].RemotePage
		c.Progress.Step = "restrictions"
		return s.resume(ctx, c)
	}
	if c.Progress.Remote.ID == "" {
		return c.Intent, nil
	}
	remote, err := p.GetDocument(ctx, c.Progress.Remote.ID)
	if err != nil {
		return c.Intent, err
	}
	if remote.ID != c.Progress.Remote.ID || remote.Container != c.Intent.Container {
		return c.Intent, shared.ErrConflict
	}
	if c.Progress.OutstandingOperation == "attachment" || c.Progress.OutstandingOperation == "purge" {
		// A filename/hash in attachment metadata or a 404 after deletion cannot
		// prove the uploaded bytes or a purge. Preserve the uncertainty fence.
		return c.Intent, nil
	}
	complete := c.Progress.Step == "complete" || c.Progress.OutstandingOperation == "body"
	if complete {
		if len(c.Progress.UploadedReceipts) != len(attachments(c)) || !validReceipts(c) || remote.Marker != c.Intent.Marker || remote.Title != c.Artifact.Title || remote.Storage != storageDocument(c) {
			return c.Intent, nil
		}
		expected := c.Progress.Remote.Version
		if c.Progress.OutstandingOperation == "body" {
			expected = c.Progress.ExpectedRemoteVersion + 1
		}
		if remote.Version != expected {
			return c.Intent, nil
		}
		if _, err := s.guard(ctx, c); err != nil {
			return c.Intent, err
		}
		if err := p.VerifyDocumentRestriction(ctx, remote.ID, c.Intent.Container, c.ReadGroup); err != nil {
			return c.Intent, err
		}
		if err := s.record(ctx, c, "document.published", remote.ID); err != nil {
			return c.Intent, err
		}
		return s.store.TransitionIntent(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, domain.IntentTransition{Event: writeintent.ReconcileFound, Remote: &remote.RemotePage}, s.clock.Now().UTC())
	}
	if remote.Version != c.Progress.Remote.Version {
		return c.Intent, shared.ErrConflict
	}
	if c.Progress.OutstandingOperation == "restrictions" {
		if err := p.VerifyDocumentRestriction(ctx, remote.ID, c.Intent.Container, c.ReadGroup); err != nil {
			return c.Intent, err
		}
		c.Progress.Step = "attachments"
		return s.resume(ctx, c)
	}
	if c.Progress.OutstandingOperation == "" && validReceipts(c) {
		// A checkpoint committed after a definite acknowledgement leaves no
		// outstanding effect. Resume its next step, never shell creation.
		return s.resume(ctx, c)
	}
	return c.Intent, nil
}

func validReceipts(c ports.DocumentCommand) bool {
	if c.Intent.Action == domain.Purge {
		return len(c.Progress.UploadedReceipts) == 0
	}
	files := attachments(c)
	if len(c.Progress.UploadedReceipts) > len(files) {
		return false
	}
	for i, r := range c.Progress.UploadedReceipts {
		if r.Key != uploadKey(i, files[i]) || r.Digest != digest(files[i].Data) {
			return false
		}
	}
	return true
}
func (s *Service) resume(ctx context.Context, c ports.DocumentCommand) (domain.Intent, error) {
	c.Progress.OutstandingOperation = ""
	c.Progress.OutstandingKey = ""
	c.Progress.OutstandingDigest = ""
	c.Progress.ExpectedRemoteVersion = 0
	c.Progress.IntentVersion = c.Intent.Version
	c.Progress.LeaseUntil = nil
	c.Progress.UpdatedAt = s.clock.Now().UTC()
	saved, err := s.store.ResumeDocumentCommand(ctx, c.Intent.TenantID, c.Intent.ID, c.Intent.Version, c.Progress.Version, c.Progress, s.clock.Now().UTC())
	return saved.Intent, err
}
