package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	dastworkflowuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastworkflow"
)

// dastScanBody accepts only secret-free configuration. Credential values must already
// be stored in the engagement credential vault and are named by reference.
type dastScanBody struct {
	Target           string      `json:"target"`
	Session          sessionBody `json:"session"`
	Crawler          crawlerBody `json:"crawler"`
	SelectedCheckIDs []string    `json:"selected_check_ids"`
}

type sessionBody struct {
	Scheme       dastsession.Scheme `json:"scheme"`
	Credentials  []credentialBody   `json:"credentials"`
	LoginRequest requestBody        `json:"login_request"`
	Success      successBody        `json:"success"`
	CheckRequest requestBody        `json:"check_request"`
	DenyPaths    []string           `json:"deny_paths"`
	MaxReauth    int                `json:"max_reauth"`
}

type credentialBody struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
	Field     string `json:"field"`
}

type requestBody struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type successBody struct {
	StatusCode    int    `json:"status_code"`
	BodyContains  string `json:"body_contains"`
	HeaderPresent string `json:"header_present"`
	CookiePresent string `json:"cookie_present"`
}

type crawlerBody struct {
	Seeds       []dastsurface.Request `json:"seeds"`
	Robots      string                `json:"robots"`
	Sitemaps    []string              `json:"sitemaps"`
	OpenAPI     []string              `json:"openapi"`
	GraphQL     []string              `json:"graphql"`
	RatePerSec  int                   `json:"rate_per_sec"`
	Concurrency int                   `json:"concurrency"`
	MaxDepth    int                   `json:"max_depth"`
	MaxPages    int                   `json:"max_pages"`
	MaxRequests int                   `json:"max_requests"`
	WallClock   string                `json:"wall_clock"`
}

func (b dastScanBody) config() (dastworkflowuc.ScanConfig, error) {
	wallClock := time.Duration(0)
	if b.Crawler.WallClock != "" {
		var err error
		wallClock, err = time.ParseDuration(b.Crawler.WallClock)
		if err != nil {
			return dastworkflowuc.ScanConfig{}, err
		}
	}
	credentials := make([]dastsession.CredentialBinding, len(b.Session.Credentials))
	for i, c := range b.Session.Credentials {
		credentials[i] = dastsession.CredentialBinding{Name: c.Name, Reference: c.Reference, Field: c.Field}
	}
	return dastworkflowuc.ScanConfig{
		Target: b.Target,
		Session: dastsession.Config{Scheme: b.Session.Scheme, Credentials: credentials,
			LoginRequest: dastsession.Request{Method: b.Session.LoginRequest.Method, Path: b.Session.LoginRequest.Path},
			Success:      dastsession.SuccessSignal{StatusCode: b.Session.Success.StatusCode, BodyContains: b.Session.Success.BodyContains, HeaderPresent: b.Session.Success.HeaderPresent, CookiePresent: b.Session.Success.CookiePresent},
			CheckRequest: dastsession.Request{Method: b.Session.CheckRequest.Method, Path: b.Session.CheckRequest.Path},
			DenyPaths:    b.Session.DenyPaths, MaxReauth: b.Session.MaxReauth},
		Crawler:    dastcrawl.Input{Target: b.Target, Seeds: b.Crawler.Seeds, Robots: b.Crawler.Robots, Sitemaps: b.Crawler.Sitemaps, OpenAPI: b.Crawler.OpenAPI, GraphQL: b.Crawler.GraphQL},
		Limits:     dastcrawl.Limits{Depth: b.Crawler.MaxDepth, Pages: b.Crawler.MaxPages, Requests: b.Crawler.MaxRequests, WallClock: wallClock},
		RatePerSec: b.Crawler.RatePerSec, Concurrency: b.Crawler.Concurrency, SelectedCheckIDs: b.SelectedCheckIDs,
	}, nil
}

func decodeDASTScan(w http.ResponseWriter, r *http.Request) (dastworkflowuc.ScanConfig, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		return dastworkflowuc.ScanConfig{}, err
	}
	if strings.Contains(strings.ToLower(string(body)), "{{secret:") {
		return dastworkflowuc.ScanConfig{}, shared.ErrValidation
	}
	var request dastScanBody
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		return dastworkflowuc.ScanConfig{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return dastworkflowuc.ScanConfig{}, shared.ErrValidation
	}
	return request.config()
}

func (rt *Router) proposeDASTScan(w http.ResponseWriter, r *http.Request) {
	config, err := decodeDASTScan(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid DAST scan configuration"})
		return
	}
	out, err := rt.dastScan.ProposeScan(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), config)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, out)
}

func (rt *Router) runDASTScan(w http.ResponseWriter, r *http.Request) {
	config, err := decodeDASTScan(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid DAST scan configuration"})
		return
	}
	out, err := rt.dastScan.RunScan(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("aid")), config)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
