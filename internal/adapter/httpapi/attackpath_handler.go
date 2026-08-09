package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type attackPathService interface {
	Query(context.Context, shared.ID, attackpath.Query) (attackpath.Result, error)
}

func (rt *Router) SetAttackPaths(s attackPathService) { rt.attackPaths = s }

func (rt *Router) listAttackPaths(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := attackpath.Query{Target: shared.ID(q.Get("target")), Entrypoint: shared.ID(q.Get("entrypoint")), Finding: shared.ID(q.Get("finding"))}
	if kind := attackpath.TargetKind(q.Get("finding_kind")); kind != "" {
		if query.Finding == "" {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "finding_kind requires finding"})
			return
		}
		if !kind.Valid() {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "finding_kind must be canonical or imported"})
			return
		}
		query.FindingTarget = &attackpath.FindingTarget{ID: query.Finding, Kind: kind}
	}
	result, err := rt.attackPaths.Query(r.Context(), fleetTenant(r.Context()), query)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if result.Paths == nil {
		result.Paths = []attackpath.Path{}
	}
	writeJSON(w, http.StatusOK, result)
}
