// Package ports defines application boundaries.
package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DASTRequest is the request a helper must obtain approval for before network I/O.
// URL is canonical and never contains credentials.
type DASTRequest struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

// DASTAuthorization is the parent-to-helper decision for one request.
type DASTAuthorization struct {
	Allowed bool `json:"allowed"`
}

// DASTPlan contains only public configuration. Credentials are named environment
// variables whose values are substituted by the sandbox credential vault.
// DASTCrawlPlan is the secret-free, bounded crawl configuration executed by one helper process.
type DASTCrawlPlan struct {
	Target    string                `json:"target"`
	Seeds     []dastsurface.Request `json:"seeds"`
	Robots    string                `json:"robots,omitempty"`
	Sitemaps  []string              `json:"sitemaps,omitempty"`
	OpenAPI   []string              `json:"openapi,omitempty"`
	GraphQL   []string              `json:"graphql,omitempty"`
	Depth     int                   `json:"depth"`
	Pages     int                   `json:"pages"`
	Requests  int                   `json:"requests"`
	WallClock time.Duration         `json:"wall_clock"`
}

type DASTPlan struct {
	HelperBin           string                `json:"-"`
	ConfigDigest        string                `json:"-"`
	Target              string                `json:"target"`
	Session             dastsession.Config    `json:"session"`
	Requests            []dastsurface.Request `json:"requests"`
	Crawl               *DASTCrawlPlan        `json:"crawl,omitempty"`
	RatePerSec          int                   `json:"rate_per_sec"`
	Concurrency         int                   `json:"concurrency"`
	EngagementID        shared.ID             `json:"-"`
	EgressPolicy        *EgressPolicy         `json:"-"`
	EgressExecutionKind string                `json:"-"`
	EgressExecutionID   string                `json:"-"`
}

// DASTObservation is bounded, secret-free proof of one completed request.
type DASTObservation struct {
	Method        string   `json:"method"`
	URL           string   `json:"url"`
	Status        int      `json:"status"`
	BodySHA256    string   `json:"body_sha256"`
	BodyBytes     int      `json:"body_bytes"`
	BodyTruncated bool     `json:"body_truncated"`
	BodyExcerpt   string   `json:"body_excerpt,omitempty"`
	Headers       []string `json:"headers,omitempty"`
}

// DASTOutcome is emitted by the helper. Incomplete denotes a bounded authentication
// or liveness failure; it is not a successful scan.
type DASTOutcome struct {
	Observations []DASTObservation    `json:"observations"`
	Surface      dastsurface.Surface  `json:"surface"`
	Coverage     dastsurface.Coverage `json:"coverage"`
	Incomplete   bool                 `json:"incomplete"`
	Reason       string               `json:"reason,omitempty"`
}

// DASTFinding is a deterministic passive-check finding, kept at the use-case boundary.
type DASTFinding struct {
	CheckID  string    `json:"check_id"`
	CWE      string    `json:"cwe"`
	Version  int       `json:"version"`
	Endpoint string    `json:"endpoint"`
	Proof    DASTProof `json:"proof"`
}

// DASTProof is closed, secret-free evidence for a passive DAST finding.
type DASTProof struct {
	CheckID            string                `json:"check_id"`
	Version            int                   `json:"version"`
	NormalizedEndpoint string                `json:"normalized_endpoint"`
	Observation        DASTClosedObservation `json:"observation"`
	Hash               string                `json:"hash"`
}

type DASTClosedObservation struct {
	Method          string   `json:"method"`
	Status          int      `json:"status"`
	BodySHA256      string   `json:"body_sha256"`
	Headers         []string `json:"headers,omitempty"`
	Signature       string   `json:"signature,omitempty"`
	PredicateTokens []string `json:"predicate_tokens,omitempty"`
}

// DASTCheckEvaluator evaluates observations using an immutable check catalog.
type DASTCheckEvaluator interface {
	Evaluate([]DASTObservation, []string) ([]DASTFinding, error)
}

// DASTProofVerifier independently re-evaluates a closed first-party proof.
type DASTProofVerifier interface {
	VerifyProof(DASTProof) error
}

// DASTEngine executes a secret-free plan in a helper process. It never performs
// HTTP in the caller process.
type DASTEngine interface {
	Run(ctx context.Context, plan DASTPlan, secretEnv []string, authorize func(context.Context, DASTRequest) error) (DASTOutcome, error)
}

// DASTDefaults keep each canonical target conservative by default.
const (
	DefaultDASTRatePerSec  = 5
	DefaultDASTConcurrency = 4
	DefaultDASTTimeout     = 30 * time.Second
)
