package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DocumentActor retains server-derived human identity, never a credential.
type DocumentActor struct {
	UserID       shared.ID
	MembershipID shared.ID
	PersonID     shared.ID
}

type DocumentAuthorityReader interface {
	CanReleaseDocument(context.Context, shared.ID, DocumentActor) (bool, error)
}

// DocumentCommand freezes a release's inputs. Progress is separate from the
// immutable command; it records a neutral shell even before content is released.
type DocumentCommand struct {
	Intent             docpublish.Intent
	Actor              DocumentActor
	ConnectionRevision int
	CredentialRevision int
	ReadGroup          string
	Artifact           DocumentArtifact
	Progress           DocumentProgress
}

type DocumentProgress struct {
	Version int
	// IntentVersion and LeaseUntil fence a worker which lost its claim from
	// checkpointing a newer attempt.
	IntentVersion         int
	LeaseUntil            *time.Time
	Remote                docpublish.RemotePage
	Step                  string
	Uploaded              int
	OutstandingOperation  string
	OutstandingKey        string
	OutstandingDigest     string
	ExpectedRemoteVersion int
	UploadedReceipts      []DocumentUploadReceipt
	UpdatedAt             time.Time
}

// DocumentUploadReceipt is an immutable record of an upload proven complete.
// It contains no provider response body or credential material.
type DocumentUploadReceipt struct {
	Key    string
	Digest string
}

type DocumentCommandStore interface {
	DocumentStore
	// Admission serializes the target, answers exact replays before mutable
	// target checks, and rejects another pending/in-flight/uncertain command.
	CreateDocumentCommand(context.Context, shared.ID, DocumentCommand) (DocumentCommand, bool, error)
	GetDocumentCommand(context.Context, shared.ID, shared.ID) (DocumentCommand, error)
	FindDocumentCommand(context.Context, shared.ID, shared.ID, string) (DocumentCommand, error)
	SaveDocumentProgress(context.Context, shared.ID, shared.ID, int, DocumentProgress) (DocumentCommand, error)
	// ResumeDocumentCommand atomically stores a reconciliation-proven checkpoint
	// and moves one uncertain command back to pending.  Ordinary checkpoint saves
	// are limited to the current in-flight lease.
	ResumeDocumentCommand(context.Context, shared.ID, shared.ID, int, int, DocumentProgress, time.Time) (DocumentCommand, error)
	// ListDocumentCommands claims a bounded fair work slice at at. Terminal
	// commands are omitted; selected commands advance their durable queue turn
	// before any remote work begins.
	ListDocumentCommands(context.Context, shared.ID, int, time.Time) ([]DocumentCommand, error)
}
