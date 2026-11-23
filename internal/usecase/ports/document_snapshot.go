package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
)

// DestinationManagedSnapshot is an opt-in publication contract. The destination
// owner controls effective readers, including inherited and anonymous access.
// Observations under this contract are never complete ACL verification.
const DestinationManagedSnapshot = docpublish.DestinationManagedSnapshotProfile

// DocumentSnapshotReceipt records one acknowledged bounded append. Digest covers
// the provider's canonical readback, excluding expiring download signatures.
type DocumentSnapshotReceipt struct {
	BlockIDs []string
	Digest   string
	Remote   docpublish.RemotePage
}

// DocumentSnapshotProvider exposes individual mutations for owner-managed
// destinations. The application guards and checkpoints every call. A remote
// observation is not an atomic write precondition, nor an ACL proof.
// Implementations must refuse the strict restriction and purge methods.
type DocumentSnapshotProvider interface {
	DocumentAccessProfile() string
	ValidateDocumentSnapshot(DocumentArtifact) error
	ObserveDocumentDestination(context.Context, string, string) (DocumentRemoteState, error)
	AllocateDocumentUpload(context.Context, DocumentImage) (string, error)
	SendDocumentUpload(context.Context, string, DocumentImage) error
	AppendDocumentSnapshot(context.Context, docpublish.RemotePage, DocumentArtifact, []DocumentUploadReceipt, string, string) (DocumentSnapshotReceipt, error)
	SetDocumentSnapshotTitle(context.Context, docpublish.RemotePage, string) (docpublish.RemotePage, error)
	VerifyDocumentSnapshot(context.Context, string, DocumentSnapshotReceipt, string) (docpublish.RemotePage, error)
	TrashDocument(context.Context, docpublish.RemotePage) error
	ConfirmDocumentTrash(context.Context, string, string) (bool, error)
}
