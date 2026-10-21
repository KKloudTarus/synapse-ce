package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
)

// DocumentProvider exposes individual writes so the application can recheck
// current release authority and legal holds before every sensitive upload.
type DocumentProvider interface {
	CreateDocumentShell(context.Context, string, string) (docpublish.RemotePage, error) // container, marker; neutral content only
	RestrictDocument(context.Context, string, string) error                             // page, exact read group
	VerifyDocumentRestriction(context.Context, string, string, string) error            // exact page/container identity and group; complete current ACL and public-sharing protection
	GetDocument(context.Context, string) (DocumentRemoteState, error)
	FindDocumentMarker(context.Context, string, string) ([]DocumentRemoteState, error)
	UploadDocumentAttachment(context.Context, string, DocumentImage) error
	WriteDocument(context.Context, string, int, string, string, string) (docpublish.RemotePage, error) // page, expected version, title, allowlisted storage, marker
	PurgeDocument(context.Context, string, func(context.Context) error) error
	ValidateDocumentText(string) error // pure configured-credential guard
}

// DocumentRevisionWriter is implemented by providers whose conditional write
// precondition is an opaque revision token rather than a numeric version.
type DocumentRevisionWriter interface {
	WriteDocumentRevision(context.Context, docpublish.RemotePage, string, string, string) (docpublish.RemotePage, error)
}

// DocumentRestrictedReader combines a fresh exact remote identity/revision read
// with its complete current restriction proof. The result is valid for this call
// only; adapters must still recheck immediately before each outward write.
type DocumentRestrictedReader interface {
	ReadRestrictedDocument(context.Context, string, string, string) (DocumentRemoteState, error)
}

// DocumentReleasePreflighter refuses an unsupported provider or destination
// before an artifact or neutral remote shell is created.
type DocumentReleasePreflighter interface {
	CheckDocumentRelease(context.Context, string, string) error
}

type DocumentRemoteState struct {
	docpublish.RemotePage
	Container   string
	Marker      string
	ContentHash string
	Title       string
	Storage     string
	Neutral     bool
}

// DocumentProviderError never contains a response body, destination or credential.
type DocumentProviderError struct {
	Code      string
	Status    int
	Ambiguous bool
	// RestrictionLost means a current remote observation contradicted the
	// required access or identity boundary. Missing proof, transport, credentials
	// and local configuration failures must leave this false.
	RestrictionLost bool
	// RetryAfter is the provider's minimum deferral for a definite refusal.
	RetryAfter time.Duration
}

func (e *DocumentProviderError) Error() string {
	return fmt.Sprintf("document request failed (%s)", e.Code)
}
