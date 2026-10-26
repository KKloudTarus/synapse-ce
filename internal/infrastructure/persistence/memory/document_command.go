package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.DocumentCommandStore = (*DocumentStore)(nil)

type memoryDocumentCommandCheck struct {
	checkedAt time.Time
	version   int
}

const (
	maxDocumentArtifactBytes = 32 << 20
	maxDocumentPDFBytes      = 10 << 20
	maxDocumentReceipts      = 256
)

func cloneDocumentArtifact(in ports.DocumentArtifact) ports.DocumentArtifact {
	out := in
	out.Paragraphs = slices.Clone(in.Paragraphs)
	out.PDF = slices.Clone(in.PDF)
	if in.Images != nil {
		out.Images = make([]ports.DocumentImage, len(in.Images))
		for n := range in.Images {
			out.Images[n] = in.Images[n]
			out.Images[n].Data = slices.Clone(in.Images[n].Data)
		}
	}
	return out
}

func cloneDocumentProgress(in ports.DocumentProgress) ports.DocumentProgress {
	out := in
	if in.LeaseUntil != nil {
		at := *in.LeaseUntil
		out.LeaseUntil = &at
	}
	out.UploadedReceipts = slices.Clone(in.UploadedReceipts)
	if in.SnapshotReceipt != nil {
		receipt := *in.SnapshotReceipt
		receipt.BlockIDs = slices.Clone(in.SnapshotReceipt.BlockIDs)
		out.SnapshotReceipt = &receipt
	}
	return out
}

func cloneDocumentCommand(in ports.DocumentCommand) ports.DocumentCommand {
	out := in
	out.Intent = in.Intent.Clone()
	out.Artifact = cloneDocumentArtifact(in.Artifact)
	out.Progress = cloneDocumentProgress(in.Progress)
	return out
}

func documentArtifactDigest(artifact ports.DocumentArtifact) (string, error) {
	if len(artifact.PDF) == 0 || len(artifact.PDF) > maxDocumentPDFBytes || artifact.GeneratedAt.IsZero() ||
		strings.TrimSpace(artifact.Title) == "" ||
		strings.TrimSpace(artifact.SourceRevision) == "" || len(artifact.Paragraphs) == 0 {
		return "", shared.ErrValidation
	}
	encoded, err := json.Marshal(artifact)
	if err != nil || len(encoded) > maxDocumentArtifactBytes {
		return "", shared.ErrValidation
	}
	imageBytes := 0
	for _, image := range artifact.Images {
		if strings.TrimSpace(image.Name) == "" || strings.TrimSpace(image.MediaType) == "" || len(image.Data) == 0 {
			return "", shared.ErrValidation
		}
		imageBytes += len(image.Data)
	}
	if imageBytes > maxDocumentPDFBytes {
		return "", shared.ErrValidation
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validDocumentProgress(progress ports.DocumentProgress, current docpublish.Intent, now time.Time) bool {
	if progress.Version < 1 || progress.IntentVersion != current.Version || progress.UpdatedAt.IsZero() ||
		progress.UpdatedAt.Before(current.UpdatedAt) || progress.Uploaded < 0 || len(progress.UploadedReceipts) > maxDocumentReceipts {
		return false
	}
	if current.State == writeintent.InFlight {
		if current.LeaseUntil == nil || progress.LeaseUntil == nil || !progress.LeaseUntil.Equal(*current.LeaseUntil) {
			return false
		}
	}
	for _, receipt := range progress.UploadedReceipts {
		if strings.TrimSpace(receipt.Key) == "" || len(receipt.Key) > 512 || len(receipt.Digest) != 64 || (receipt.UploadID != "" && len(receipt.UploadID) > 512) {
			return false
		}
	}
	if progress.SnapshotReceipt != nil && !validMemorySnapshotReceipt(*progress.SnapshotReceipt) {
		return false
	}
	return !now.IsZero()
}

func validMemorySnapshotReceipt(receipt ports.DocumentSnapshotReceipt) bool {
	if len(receipt.BlockIDs) < 1 || len(receipt.BlockIDs) > 100 || len(receipt.Digest) != 64 || receipt.Remote.ID == "" || receipt.Remote.Version < 1 {
		return false
	}
	for _, id := range receipt.BlockIDs {
		if strings.TrimSpace(id) == "" || len(id) > 512 {
			return false
		}
	}
	return true
}

func sameDocumentCommand(left, right ports.DocumentCommand) bool {
	if (left.Intent.Action == docpublish.Purge || left.Intent.Action == docpublish.Trash) && left.Intent.Action == right.Intent.Action {
		return left.Intent.SameCommand(right.Intent) && left.Actor == right.Actor &&
			left.ConnectionRevision == right.ConnectionRevision && left.CredentialRevision == right.CredentialRevision && left.ReadGroup == right.ReadGroup && left.AccessProfile == right.AccessProfile
	}
	leftDigest, leftErr := documentArtifactDigest(left.Artifact)
	rightDigest, rightErr := documentArtifactDigest(right.Artifact)
	return leftErr == nil && rightErr == nil && left.Intent.SameCommand(right.Intent) &&
		left.Actor == right.Actor && left.ConnectionRevision == right.ConnectionRevision &&
		left.CredentialRevision == right.CredentialRevision && left.ReadGroup == right.ReadGroup && left.AccessProfile == right.AccessProfile && leftDigest == rightDigest
}

func validDocumentCommand(command ports.DocumentCommand) bool {
	if command.Intent.Validate() != nil || command.Intent.State != writeintent.Pending || command.Intent.Version != 1 ||
		command.Intent.Attempts != 0 || command.Intent.LeaseUntil != nil || command.Actor.UserID.IsZero() ||
		command.ConnectionRevision < 1 || command.CredentialRevision < 0 || strings.TrimSpace(command.ReadGroup) == "" || len(command.ReadGroup) > 255 || command.AccessProfile != command.Intent.AccessProfile {
		return false
	}
	if command.Intent.Action == docpublish.Purge || command.Intent.Action == docpublish.Trash {
		return true
	}
	_, err := documentArtifactDigest(command.Artifact)
	return err == nil
}

func activeDocumentTargetFence(intent docpublish.Intent) bool {
	return intent.State == writeintent.Pending || intent.State == writeintent.InFlight || intent.State == writeintent.Uncertain
}

func (s *DocumentStore) CreateDocumentCommand(ctx context.Context, tenant shared.ID, command ports.DocumentCommand) (ports.DocumentCommand, bool, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, false, err
	}
	if tenant.IsZero() || command.Intent.TenantID != tenant || !validDocumentCommand(command) {
		return ports.DocumentCommand{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.intents[tenant] {
		if existing.IntegrationID != command.Intent.IntegrationID || existing.RequestKey != command.Intent.RequestKey {
			continue
		}
		stored, ok := s.commands[tenant][existing.ID]
		if !ok || !sameDocumentCommand(stored, command) {
			return ports.DocumentCommand{}, false, shared.ErrConflict
		}
		return cloneDocumentCommand(stored), false, nil
	}
	for _, existing := range s.intents[tenant] {
		checkpointedFailure := false
		if stored, ok := s.commands[tenant][existing.ID]; ok {
			checkpointedFailure = existing.State == writeintent.Failed && strings.TrimSpace(stored.Progress.Remote.ID) != ""
		}
		if existing.Target == command.Intent.Target && (activeDocumentTargetFence(existing) || checkpointedFailure) {
			return ports.DocumentCommand{}, false, shared.ErrConflict
		}
	}
	if err := s.validateScope(ctx, tenant, command.Intent.Scope, command.Intent.ScopeID); err != nil {
		return ports.DocumentCommand{}, false, err
	}
	link, linked := s.linkForTarget(tenant, command.Intent.Target)
	initial := ports.DocumentProgress{Version: 1, IntentVersion: command.Intent.Version, Step: "shell", UpdatedAt: command.Intent.CreatedAt}
	switch command.Intent.Action {
	case docpublish.Create:
		if linked {
			return ports.DocumentCommand{}, false, shared.ErrConflict
		}
		if command.AccessProfile == docpublish.DestinationManagedSnapshotProfile {
			initial.Step = "snapshot_shell"
		}
	case docpublish.Update, docpublish.Purge, docpublish.Snapshot, docpublish.Trash:
		if !linked || link.ID != command.Intent.LinkID {
			return ports.DocumentCommand{}, false, shared.ErrNotFound
		}
		if link.RetiredAt != nil && command.Intent.Action != docpublish.Snapshot {
			return ports.DocumentCommand{}, false, shared.ErrConflict
		}
		if command.Intent.ExpectedLinkRevision > 0 && link.Revision != command.Intent.ExpectedLinkRevision {
			return ports.DocumentCommand{}, false, shared.ErrConflict
		}
		initial.Remote = docpublish.RemotePage{ID: link.RemotePageID, Version: link.RemoteVersion, Revision: link.RemoteRevision, URL: link.RemoteURL}
		if command.Intent.Action == docpublish.Update {
			initial.Step = "restrictions"
		} else if command.Intent.Action == docpublish.Snapshot {
			initial.Step = "snapshot_shell"
			initial.Remote = docpublish.RemotePage{}
		} else if command.Intent.Action == docpublish.Trash {
			initial.Step = "trash"
		} else {
			initial.Step = "purge"
		}
	}
	if s.intents[tenant] == nil {
		s.intents[tenant] = make(map[shared.ID]docpublish.Intent)
	}
	if s.commands[tenant] == nil {
		s.commands[tenant] = make(map[shared.ID]ports.DocumentCommand)
	}
	command.Progress = initial
	command.QueueVersion = 1
	s.intents[tenant][command.Intent.ID] = command.Intent.Clone()
	s.commands[tenant][command.Intent.ID] = cloneDocumentCommand(command)
	return cloneDocumentCommand(command), true, nil
}

func (s *DocumentStore) GetDocumentCommand(ctx context.Context, tenant, intentID shared.ID) (ports.DocumentCommand, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, err
	}
	if tenant.IsZero() || intentID.IsZero() {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.commands[tenant][intentID]
	if !ok {
		return ports.DocumentCommand{}, shared.ErrNotFound
	}
	return cloneDocumentCommand(item), nil
}

func (s *DocumentStore) FindDocumentCommand(ctx context.Context, tenant, integrationID shared.ID, requestKey string) (ports.DocumentCommand, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, err
	}
	if tenant.IsZero() || integrationID.IsZero() || strings.TrimSpace(requestKey) == "" {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.commands[tenant] {
		if item.Intent.IntegrationID == integrationID && item.Intent.RequestKey == requestKey {
			return cloneDocumentCommand(item), nil
		}
	}
	return ports.DocumentCommand{}, shared.ErrNotFound
}

func (s *DocumentStore) SaveDocumentProgress(ctx context.Context, tenant, intentID shared.ID, expected int, progress ports.DocumentProgress) (ports.DocumentCommand, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, err
	}
	if tenant.IsZero() || intentID.IsZero() || expected < 1 {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	command, ok := s.commands[tenant][intentID]
	if !ok {
		return ports.DocumentCommand{}, shared.ErrNotFound
	}
	current := s.intents[tenant][intentID]
	if command.Progress.Version != expected || current.State != writeintent.InFlight || !validDocumentProgress(progress, current, progress.UpdatedAt) {
		return ports.DocumentCommand{}, shared.ErrConflict
	}
	progress.Version = expected + 1
	command.Progress = cloneDocumentProgress(progress)
	command.Intent = current.Clone()
	s.commands[tenant][intentID] = cloneDocumentCommand(command)
	return cloneDocumentCommand(command), nil
}

func cleanDocumentYieldCheckpoint(progress ports.DocumentProgress, intent docpublish.Intent, at time.Time) bool {
	if progress.Step != "restrictions" && progress.Step != "attachments" && progress.Step != "body" && progress.Step != "complete" && progress.Step != "purged" && progress.Step != "snapshot_observe" && progress.Step != "snapshot_uploads" && progress.Step != "snapshot_upload_send" && progress.Step != "snapshot_append" && progress.Step != "snapshot_title" && progress.Step != "snapshot_verify" && progress.Step != "trash_confirm" {
		return false
	}
	if strings.TrimSpace(progress.Remote.ID) == "" || progress.Remote.Version < 1 || strings.TrimSpace(progress.Remote.URL) == "" {
		return false
	}
	return intent.State == writeintent.InFlight && intent.LeaseUntil != nil && at.Before(*intent.LeaseUntil) &&
		progress.IntentVersion == intent.Version && progress.LeaseUntil != nil && progress.LeaseUntil.Equal(*intent.LeaseUntil) &&
		progress.OutstandingOperation == "" && progress.OutstandingKey == "" && progress.OutstandingDigest == "" &&
		progress.ExpectedRemoteVersion == 0 && progress.ExpectedRemoteRevision == ""
}

// cleanDocumentRetryCheckpoint is deliberately no broader than a clean yield:
// a provider throttle may release an in-flight lease only when no outbound
// effect remains to reconcile. Purge and Trash are included because their
// pre-write identity reads have the same no-effect property.
func cleanDocumentRetryCheckpoint(progress ports.DocumentProgress, intent docpublish.Intent, at time.Time) bool {
	if !cleanDocumentYieldCheckpoint(progress, intent, at) && progress.Step != "purge" && progress.Step != "trash" {
		return false
	}
	if (progress.Step == "purge" || progress.Step == "trash") && (strings.TrimSpace(progress.Remote.ID) == "" || progress.Remote.Version < 1 || strings.TrimSpace(progress.Remote.URL) == "") {
		return false
	}
	return intent.State == writeintent.InFlight && intent.LeaseUntil != nil && at.Before(*intent.LeaseUntil) &&
		progress.IntentVersion == intent.Version && progress.LeaseUntil != nil && progress.LeaseUntil.Equal(*intent.LeaseUntil) &&
		progress.OutstandingOperation == "" && progress.OutstandingKey == "" && progress.OutstandingDigest == "" &&
		progress.ExpectedRemoteVersion == 0 && progress.ExpectedRemoteRevision == ""
}

func liveDocumentRetryLease(progress ports.DocumentProgress, intent docpublish.Intent, at time.Time) bool {
	return intent.State == writeintent.InFlight && intent.LeaseUntil != nil && at.Before(*intent.LeaseUntil) &&
		progress.IntentVersion == intent.Version && progress.LeaseUntil != nil && progress.LeaseUntil.Equal(*intent.LeaseUntil)
}

func documentRetryDeadline(current, requested time.Time) time.Time {
	if current.After(requested) {
		return current.UTC()
	}
	return requested.UTC()
}

func (s *DocumentStore) DeferDocumentCommand(ctx context.Context, tenant, intentID shared.ID, expectedIntent, expectedProgress, expectedQueue int, deadline, at time.Time, outcome ports.DocumentRetryOutcome, code string) (ports.DocumentCommand, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, err
	}
	if tenant.IsZero() || intentID.IsZero() || expectedIntent < 1 || expectedProgress < 1 || expectedQueue < 1 || deadline.IsZero() || !deadline.After(at) || at.IsZero() {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	command, ok := s.commands[tenant][intentID]
	if !ok {
		return ports.DocumentCommand{}, shared.ErrNotFound
	}
	current := s.intents[tenant][intentID]
	if current.Version != expectedIntent || command.Progress.Version != expectedProgress || command.QueueVersion != expectedQueue {
		return ports.DocumentCommand{}, shared.ErrConflict
	}
	next := current
	progress := cloneDocumentProgress(command.Progress)
	switch outcome {
	case ports.DocumentRetryKeep:
		if current.State != writeintent.Pending && current.State != writeintent.Uncertain {
			return ports.DocumentCommand{}, shared.ErrConflict
		}
	case ports.DocumentRetryRelease:
		if !cleanDocumentRetryCheckpoint(progress, current, at) {
			return ports.DocumentCommand{}, shared.ErrConflict
		}
		var err error
		next, err = current.Apply(docpublish.IntentTransition{Event: docpublish.RetryDeferred}, at)
		if err != nil {
			return ports.DocumentCommand{}, err
		}
		progress.IntentVersion, progress.LeaseUntil = next.Version, nil
		progress.Version++
		progress.UpdatedAt = at.UTC()
	case ports.DocumentRetryReject:
		if !liveDocumentRetryLease(progress, current, at) || strings.TrimSpace(code) == "" {
			return ports.DocumentCommand{}, shared.ErrConflict
		}
		var err error
		next, err = current.Apply(docpublish.IntentTransition{Event: writeintent.Reject, ErrorCode: code}, at)
		if err != nil {
			return ports.DocumentCommand{}, err
		}
		progress.IntentVersion, progress.LeaseUntil = next.Version, nil
		progress.OutstandingOperation, progress.OutstandingKey, progress.OutstandingDigest = "", "", ""
		progress.ExpectedRemoteVersion, progress.ExpectedRemoteRevision = 0, ""
		progress.Version++
		progress.UpdatedAt = at.UTC()
	case ports.DocumentRetryUncertain:
		if !liveDocumentRetryLease(progress, current, at) {
			return ports.DocumentCommand{}, shared.ErrConflict
		}
		var err error
		next, err = current.Apply(docpublish.IntentTransition{Event: writeintent.Ambiguous}, at)
		if err != nil {
			return ports.DocumentCommand{}, err
		}
		progress.IntentVersion, progress.LeaseUntil = next.Version, nil
		progress.Version++
		progress.UpdatedAt = at.UTC()
	default:
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	command.Intent = next.Clone()
	command.Progress = progress
	command.NextAttemptAt = documentRetryDeadline(command.NextAttemptAt, deadline)
	command.QueueVersion++
	s.intents[tenant][intentID] = next.Clone()
	s.commands[tenant][intentID] = cloneDocumentCommand(command)
	return cloneDocumentCommand(command), nil
}

func (s *DocumentStore) YieldDocumentCommand(ctx context.Context, tenant, intentID shared.ID, expectedIntent, expectedProgress int, at time.Time) (ports.DocumentCommand, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, err
	}
	if tenant.IsZero() || intentID.IsZero() || expectedIntent < 1 || expectedProgress < 1 || at.IsZero() {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	command, ok := s.commands[tenant][intentID]
	if !ok {
		return ports.DocumentCommand{}, shared.ErrNotFound
	}
	current := s.intents[tenant][intentID]
	if current.Version != expectedIntent || command.Progress.Version != expectedProgress || !cleanDocumentYieldCheckpoint(command.Progress, current, at) {
		return ports.DocumentCommand{}, shared.ErrConflict
	}
	next, err := current.Apply(docpublish.IntentTransition{Event: docpublish.CheckpointYield}, at)
	if err != nil {
		return ports.DocumentCommand{}, err
	}
	progress := cloneDocumentProgress(command.Progress)
	progress.Version = expectedProgress + 1
	progress.IntentVersion = next.Version
	progress.LeaseUntil = nil
	progress.UpdatedAt = at.UTC()
	command.Intent, command.Progress = next, progress
	s.intents[tenant][intentID], s.commands[tenant][intentID] = next, cloneDocumentCommand(command)
	return cloneDocumentCommand(command), nil
}

func (s *DocumentStore) ResumeDocumentCommand(ctx context.Context, tenant, intentID shared.ID, expectedIntent, expectedProgress int, progress ports.DocumentProgress, at time.Time) (ports.DocumentCommand, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, err
	}
	if tenant.IsZero() || intentID.IsZero() || expectedIntent < 1 || expectedProgress < 1 || at.IsZero() {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	command, ok := s.commands[tenant][intentID]
	if !ok {
		return ports.DocumentCommand{}, shared.ErrNotFound
	}
	current := s.intents[tenant][intentID]
	if current.Version != expectedIntent || command.Progress.Version != expectedProgress || current.State != writeintent.Uncertain || !validDocumentProgress(progress, current, at) {
		return ports.DocumentCommand{}, shared.ErrConflict
	}
	next, err := current.Apply(docpublish.IntentTransition{Event: docpublish.ReconcileResumable, Resumable: true}, at)
	if err != nil {
		return ports.DocumentCommand{}, err
	}
	progress.Version = expectedProgress + 1
	progress.IntentVersion = next.Version
	progress.LeaseUntil = nil
	progress.UpdatedAt = at.UTC()
	command.Intent, command.Progress = next, cloneDocumentProgress(progress)
	s.intents[tenant][intentID], s.commands[tenant][intentID] = next, cloneDocumentCommand(command)
	return cloneDocumentCommand(command), nil
}

func (s *DocumentStore) ListDocumentCommands(ctx context.Context, tenant shared.ID, limit int, at time.Time) ([]ports.DocumentCommand, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > docpublish.MaxListLimit || at.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.DocumentCommand, 0, limit)
	for id, item := range s.commands[tenant] {
		intent := s.intents[tenant][id]
		due := item.NextAttemptAt.IsZero() || !item.NextAttemptAt.After(at)
		eligible := due && (intent.State == writeintent.Pending || intent.State == writeintent.Uncertain ||
			(intent.State == writeintent.Failed && intent.Attempts < 5) ||
			(intent.State == writeintent.InFlight && intent.LeaseUntil != nil && !intent.LeaseUntil.After(at)))
		if eligible {
			out = append(out, cloneDocumentCommand(item))
		}
	}
	slices.SortFunc(out, func(a, b ports.DocumentCommand) int {
		left := s.commandChecks[tenant][a.Intent.ID]
		right := s.commandChecks[tenant][b.Intent.ID]
		if left.checkedAt.IsZero() != right.checkedAt.IsZero() {
			if left.checkedAt.IsZero() {
				return -1
			}
			return 1
		}
		if order := left.checkedAt.Compare(right.checkedAt); order != 0 {
			return order
		}
		if left.version != right.version {
			return left.version - right.version
		}
		if order := a.Intent.UpdatedAt.Compare(b.Intent.UpdatedAt); order != 0 {
			return order
		}
		return strings.Compare(a.Intent.ID.String(), b.Intent.ID.String())
	})
	if len(out) > limit {
		out = out[:limit]
	}
	if s.commandChecks[tenant] == nil {
		s.commandChecks[tenant] = map[shared.ID]memoryDocumentCommandCheck{}
	}
	for i, item := range out {
		check := s.commandChecks[tenant][item.Intent.ID]
		check.checkedAt, check.version = at.UTC(), check.version+1
		s.commandChecks[tenant][item.Intent.ID] = check
		stored := s.commands[tenant][item.Intent.ID]
		stored.QueueVersion++
		s.commands[tenant][item.Intent.ID] = cloneDocumentCommand(stored)
		out[i] = cloneDocumentCommand(stored)
	}
	return out, nil
}
