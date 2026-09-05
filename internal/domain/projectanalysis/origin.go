package projectanalysis

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Origin says which side produced an analysis: the server acquiring the source and scanning it
// itself, or a CI job that ran synapse-cli on its own checkout and pushed the result.
//
// The distinction matters to a reader of the history page. A server analysis carries the source the
// server retained and a comparison it computed; a CI analysis carries whatever the pipeline chose to
// send, and its branch and commit are the pipeline's word rather than the server's. Both are real
// analyses with a real gate verdict, and the page must not pretend they are the same kind of thing.
type Origin string

const (
	// OriginServer is an analysis the server produced by acquiring and scanning the source itself.
	OriginServer Origin = "server"
	// OriginCI is an analysis a pipeline produced with synapse-cli and pushed through the import route.
	OriginCI Origin = "ci"
)

// Valid reports whether o is a known origin.
func (o Origin) Valid() bool {
	switch o {
	case OriginServer, OriginCI:
		return true
	default:
		return false
	}
}

// CIContext is what a pipeline says about the run that produced an analysis. Every field is the
// pipeline's own claim, carried so the history page can name the branch, link the run and attribute
// the actor; none of it is verified by the server, and none of it participates in the gate.
type CIContext struct {
	// Provider names the CI system, for example "github-actions", "gitlab-ci", "jenkins".
	Provider string `json:"provider,omitempty"`
	// RunURL links back to the pipeline run that produced the analysis.
	RunURL string `json:"run_url,omitempty"`
	// RunID is the provider's identifier for the run.
	RunID string `json:"run_id,omitempty"`
	// Branch is the branch or ref the pipeline built.
	Branch string `json:"branch,omitempty"`
	// Actor is who or what triggered the run, in the provider's own terms.
	Actor string `json:"actor,omitempty"`
}

const maxCIFieldRunes = 512

// Normalize trims every field and rejects a context that could not have come from a pipeline: an
// over-long field, a run URL that is not an absolute http(s) URL, or control characters. It is
// deliberately lenient about what a valid branch or provider name is, because those conventions
// belong to the provider, and strict about the shape a link must have before the dashboard renders
// it as one.
func (c CIContext) Normalize() (CIContext, error) {
	out := CIContext{
		Provider: strings.TrimSpace(c.Provider),
		RunURL:   strings.TrimSpace(c.RunURL),
		RunID:    strings.TrimSpace(c.RunID),
		Branch:   strings.TrimSpace(c.Branch),
		Actor:    strings.TrimSpace(c.Actor),
	}
	for name, value := range map[string]string{"provider": out.Provider, "run_url": out.RunURL, "run_id": out.RunID, "branch": out.Branch, "actor": out.Actor} {
		if utf8.RuneCountInString(value) > maxCIFieldRunes {
			return CIContext{}, fmt.Errorf("ci %s exceeds %d characters", name, maxCIFieldRunes)
		}
		for _, r := range value {
			if r < 0x20 || r == 0x7f {
				return CIContext{}, fmt.Errorf("ci %s contains a control character", name)
			}
		}
	}
	if out.RunURL != "" {
		u, err := url.Parse(out.RunURL)
		if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return CIContext{}, fmt.Errorf("ci run_url must be an absolute http(s) URL")
		}
	}
	return out, nil
}

// Empty reports whether the pipeline said nothing about itself.
func (c CIContext) Empty() bool {
	return c.Provider == "" && c.RunURL == "" && c.RunID == "" && c.Branch == "" && c.Actor == ""
}
