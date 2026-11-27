package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// TestGitHubActionsAreQueriedByPackageAndPlacedLocally pins the versionless path: OSV.dev returns nothing for
// a versioned GitHub Actions query, so the adapter asks for the package and keeps an advisory only when its
// range includes the action's version (#1665).
func TestGitHubActionsAreQueriedByPackageAndPlacedLocally(t *testing.T) {
	var got batchReq
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		results := make([]batchResult, len(got.Queries))
		for i := range results {
			results[i] = batchResult{Vulns: []batchVuln{{ID: "GHSA-cxww-7g56-2vh6"}}}
		}
		_ = json.NewEncoder(w).Encode(batchResp{Results: results})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(osvVuln{
			ID: r.PathValue("id"), Aliases: []string{"CVE-2024-42471"},
			Affected: []osvAffected{{
				Package: osvPackage{Ecosystem: "GitHub Actions", Name: "actions/download-artifact"},
				Ranges:  []osvRange{{Type: "ECOSYSTEM", Events: []map[string]string{{"introduced": "4.0.0"}, {"fixed": "4.1.3"}}}},
			}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "actions/download-artifact", Version: "4.1.2", PURL: "pkg:githubactions/actions/download-artifact@4.1.2"},
		{Name: "actions/download-artifact", Version: "4.1.3", PURL: "pkg:githubactions/actions/download-artifact@4.1.3"},
		// A commit SHA cannot be placed in a range: it must match nothing.
		{Name: "actions/download-artifact", Version: "fa0a91b85d4f404e444e00e005971372dc801d16", PURL: "pkg:githubactions/actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16"},
	}}
	vulns, err := New(srv.URL, srv.Client()).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got.Queries) == 0 || got.Queries[0].Package.PURL != "" || got.Queries[0].Package.Name != "actions/download-artifact" || got.Queries[0].Package.Ecosystem != "GitHub Actions" {
		t.Fatalf("the action was not queried by package: %+v", got.Queries)
	}
	if len(vulns) != 1 || vulns[0].Version != "4.1.2" {
		t.Fatalf("matches = %+v, want only 4.1.2", vulns)
	}
	if vulns[0].AdvisoryID != "CVE-2024-42471" {
		t.Fatalf("advisory id = %q", vulns[0].AdvisoryID)
	}
}
