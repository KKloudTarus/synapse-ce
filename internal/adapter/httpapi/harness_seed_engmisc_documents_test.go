package httpapi

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	documentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// engmiscDocuments is a document-publication stand-in that answers tenantA's link for every caller and
// for whichever scope was asked. It filters nothing by tenant, so the route's own guard (the engagement
// tenant check, or the project lookup) is the only thing between tenantB and the link.
//
// The real publishing service needs a provider registry and an integration store to be built at all,
// and the generated sweep only ever reads links. Every write is refused here: the harness never
// publishes through this router.
type engmiscDocuments struct{}

var _ documentPublishing = engmiscDocuments{}

func (engmiscDocuments) Links(_ context.Context, _ shared.ID, scope docpublish.Scope, scopeID shared.ID) ([]docpublish.Link, error) {
	return []docpublish.Link{{
		ID: "engmisc-link", TenantID: "tenantA",
		Target: docpublish.Target{
			IntegrationID: "engmisc-integration", SourceKind: docpublish.EngagementReport, SourceRef: "report-" + engmiscMarker,
			Scope: scope, ScopeID: scopeID, Container: "SEC",
		},
		RemotePageID: "page-1", RemoteVersion: 1, RemoteURL: "https://wiki.example/pages/" + engmiscMarker,
		ContentHash: "hash-1", Revision: 1, RestrictionStatus: "restricted", CreatedAt: engmiscNow, UpdatedAt: engmiscNow,
	}}, nil
}

func (engmiscDocuments) Publish(context.Context, shared.ID, ports.DocumentActor, documentuc.PublishInput) (documentuc.ReleaseResult, error) {
	return documentuc.ReleaseResult{}, engmiscDocumentsRefused()
}

func (engmiscDocuments) Unpublish(context.Context, shared.ID, ports.DocumentActor, shared.ID, string) (documentuc.ReleaseResult, error) {
	return documentuc.ReleaseResult{}, engmiscDocumentsRefused()
}

func (engmiscDocuments) ResumePreparedPublication(context.Context, shared.ID, ports.DocumentActor, shared.ID, int) (docpublish.Intent, error) {
	return docpublish.Intent{}, engmiscDocumentsRefused()
}

func (engmiscDocuments) Intent(context.Context, shared.ID, shared.ID) (docpublish.Intent, error) {
	return docpublish.Intent{}, engmiscDocumentsRefused()
}

func engmiscDocumentsRefused() error {
	return fmt.Errorf("%w: the harness never publishes a document", shared.ErrForbidden)
}

func seedEngmiscDocuments(w *harnessWorld) {
	w.rt.SetDocumentPublishing(engmiscDocuments{})
}
