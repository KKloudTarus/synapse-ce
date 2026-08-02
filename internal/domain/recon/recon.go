// Package recon holds the domain types for reconnaissance runs.
// A run is one argv-based tool execution against an in-scope engagement target;
// its raw output is sealed into the evidence chain and its progress
// is tracked so the UI can tail logs and survive reloads. The package is pure: it
// knows nothing about how tools execute (that is the ToolRunner port / adapters).
package recon

import (
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Status is the lifecycle of a recon run.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	switch s {
	case StatusQueued, StatusRunning, StatusSucceeded, StatusFailed:
		return true
	default:
		return false
	}
}

// Terminal reports whether the run has finished (success or failure).
func (s Status) Terminal() bool { return s == StatusSucceeded || s == StatusFailed }

// Run records one recon tool execution against an engagement target so the UI can
// track progress, survive reloads, and link to the sealed evidence.
type Run struct {
	ID           shared.ID  `json:"id"`
	TenantID     shared.ID  `json:"-"`
	EngagementID shared.ID  `json:"engagementId"`
	Tool         string     `json:"tool"`   // recon tool name, e.g. "subfinder"
	Target       string     `json:"target"` // the in-scope target value the run was launched against
	Status       Status     `json:"status"`
	Stage        string     `json:"stage"`
	Error        string     `json:"error,omitempty"`
	ResultCount  int        `json:"resultCount"`           // in-scope results discovered
	Containment  string     `json:"containment,omitempty"` // human-readable confinement posture
	EvidenceID   shared.ID  `json:"evidenceId,omitempty"`
	StartedAt    time.Time  `json:"startedAt"`
	FinishedAt   *time.Time `json:"finishedAt,omitempty"`
}

// ResultKind classifies a discovered asset.
type ResultKind string

const (
	ResultSubdomain ResultKind = "subdomain"
	ResultURL       ResultKind = "url"
	ResultPort      ResultKind = "port"
	ResultHost      ResultKind = "host"
)

// Result is a single asset a recon tool discovered. The recon use case re-checks
// every Result against the engagement scope before keeping it (discovered hosts
// are re-validated before they feed any further action).
type Result struct {
	Kind   ResultKind `json:"kind"`
	Value  string     `json:"value"`  // the discovered host / url / host:port
	Detail string     `json:"detail"` // tool-specific extra (status code, title, …)
}
