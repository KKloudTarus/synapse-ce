package ports

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
)

// DocumentProvider exposes individual writes so the application can recheck
// current release authority and legal holds before every sensitive upload.
type DocumentProvider interface {
	CreateDocumentShell(context.Context, string, string) (docpublish.RemotePage, error) // container, marker; neutral content only
	RestrictDocument(context.Context, string, string) error                             // page, exact read group
	VerifyDocumentRestriction(context.Context, string, string, string) error            // page, container, group; includes public-sharing protection
	GetDocument(context.Context, string) (DocumentRemoteState, error)
	FindDocumentMarker(context.Context, string, string) ([]DocumentRemoteState, error)
	UploadDocumentAttachment(context.Context, string, DocumentImage) error
	WriteDocument(context.Context, string, int, string, string, string) (docpublish.RemotePage, error) // page, expected version, title, allowlisted storage, marker
	PurgeDocument(context.Context, string, func(context.Context) error) error
	ValidateDocumentText(string) error // pure configured-credential guard
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
}

func (e *DocumentProviderError) Error() string {
	return fmt.Sprintf("document request failed (%s)", e.Code)
}
