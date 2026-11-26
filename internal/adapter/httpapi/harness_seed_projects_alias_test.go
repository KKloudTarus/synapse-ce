package httpapi

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

// projectIDAlias lets the generated sweep address a hotspot and an issue by the fixed path value it
// substitutes for every {id} parameter.
//
// The store derives a hotspot or issue id from a hash of tenant, project and finding key, so no id
// can be planted to equal the sweep's literal. Rather than replace the store, this decorator rewrites
// only that one id to the real planted one and forwards the call, with the caller's own tenant and
// project, to the real in-memory store. It adds no tenant filter and removes none: the store still
// decides whether the row is visible, so what the sweep exercises is the real lookup path.
type projectIDAlias struct {
	*memory.ProjectAnalysisStore
	sweepID   shared.ID
	hotspotID shared.ID
	issueID   shared.ID
}

func newProjectIDAlias(store *memory.ProjectAnalysisStore, sweepID, hotspotID, issueID shared.ID) *projectIDAlias {
	return &projectIDAlias{ProjectAnalysisStore: store, sweepID: sweepID, hotspotID: hotspotID, issueID: issueID}
}

func (a *projectIDAlias) resolve(id, planted shared.ID) shared.ID {
	if id == a.sweepID {
		return planted
	}
	return id
}

func (a *projectIDAlias) GetHotspot(ctx context.Context, tenantID, projectID, hotspotID shared.ID) (hotspot.Hotspot, error) {
	return a.ProjectAnalysisStore.GetHotspot(ctx, tenantID, projectID, a.resolve(hotspotID, a.hotspotID))
}

func (a *projectIDAlias) HotspotHistory(ctx context.Context, tenantID, projectID, hotspotID shared.ID) ([]hotspot.ReviewEvent, error) {
	return a.ProjectAnalysisStore.HotspotHistory(ctx, tenantID, projectID, a.resolve(hotspotID, a.hotspotID))
}

// The write sweep addresses the same hotspot and issue by the same literal when it moves them, so a
// transition is rewritten the same way and still runs against the caller's own tenant and project.
func (a *projectIDAlias) TransitionHotspot(ctx context.Context, cmd hotspot.TransitionCommand) (hotspot.Hotspot, hotspot.ReviewEvent, error) {
	cmd.HotspotID = a.resolve(cmd.HotspotID, a.hotspotID)
	return a.ProjectAnalysisStore.TransitionHotspot(ctx, cmd)
}

func (a *projectIDAlias) TransitionIssue(ctx context.Context, cmd issue.TransitionCommand) (issue.Issue, issue.ReviewEvent, error) {
	cmd.IssueID = a.resolve(cmd.IssueID, a.issueID)
	return a.ProjectAnalysisStore.TransitionIssue(ctx, cmd)
}

func (a *projectIDAlias) GetIssue(ctx context.Context, tenantID, projectID, issueID shared.ID) (issue.Issue, error) {
	return a.ProjectAnalysisStore.GetIssue(ctx, tenantID, projectID, a.resolve(issueID, a.issueID))
}

func (a *projectIDAlias) IssueHistory(ctx context.Context, tenantID, projectID, issueID shared.ID) ([]issue.ReviewEvent, error) {
	return a.ProjectAnalysisStore.IssueHistory(ctx, tenantID, projectID, a.resolve(issueID, a.issueID))
}
