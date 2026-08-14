package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskstory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// riskStoryReader is the narrow read side the HTTP layer needs for the unified per-asset risk story
// (#427): the engagement's assembled stories and a single asset's story. *riskstoryuc.Service satisfies
// it. Reads are tenant-gated by withEngTenant + the underlying stores' tenant scoping, and the
// assembler additionally derives the tenant from ctx and fails closed, so a cross-tenant read returns
// nothing.
type riskStoryReader interface {
	StoriesForEngagement(ctx context.Context, engagementID shared.ID) ([]riskstory.Story, error)
	StoryForAsset(ctx context.Context, engagementID, assetID shared.ID) (riskstory.Story, error)
}

// SetRiskStoryReader wires the risk-story read routes (#427). Left unset, the routes report an empty
// result rather than 500 — the correlation view is simply not enabled.
func (rt *Router) SetRiskStoryReader(r riskStoryReader) {
	if r != nil {
		rt.riskStories = r
	}
}

// listRiskStories returns one assembled risk story per asset in the engagement (ordered by asset id).
// With ?view=export it returns each story alongside its flattened, deduplicated evidence references, so
// an auditor/report consumer can trace every element to a backing record. PermView + withEngTenant; a
// cross-tenant engagement is already a 404 before this runs.
func (rt *Router) listRiskStories(w http.ResponseWriter, r *http.Request) {
	engID := shared.ID(r.PathValue("id"))
	if rt.riskStories == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stories": []riskstory.Story{}})
		return
	}
	stories, err := rt.riskStories.StoriesForEngagement(r.Context(), engID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if r.URL.Query().Get("view") == "export" {
		writeJSON(w, http.StatusOK, map[string]any{"exports": exportStories(stories)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stories": stories})
}

// getRiskStory returns the single risk story for one asset in the engagement. With ?view=export it also
// carries the flattened evidence references. A 404 is returned when the asset has no correlated signal.
func (rt *Router) getRiskStory(w http.ResponseWriter, r *http.Request) {
	engID := shared.ID(r.PathValue("id"))
	assetID := shared.ID(r.PathValue("assetID"))
	if rt.riskStories == nil {
		writeError(w, rt.log, shared.ErrNotFound)
		return
	}
	story, err := rt.riskStories.StoryForAsset(r.Context(), engID, assetID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if r.URL.Query().Get("view") == "export" {
		writeJSON(w, http.StatusOK, exportStory(story))
		return
	}
	writeJSON(w, http.StatusOK, story)
}

// riskStoryExport is the auditor/report representation: the story plus its full, deduplicated evidence
// reference set, so the narrative is always traceable to its backing records.
type riskStoryExport struct {
	Story    riskstory.Story        `json:"story"`
	Evidence []riskstory.Provenance `json:"evidence"`
}

func exportStory(s riskstory.Story) riskStoryExport {
	return riskStoryExport{Story: s, Evidence: s.EvidenceRefs()}
}

func exportStories(stories []riskstory.Story) []riskStoryExport {
	out := make([]riskStoryExport, 0, len(stories))
	for _, s := range stories {
		out = append(out, exportStory(s))
	}
	return out
}
