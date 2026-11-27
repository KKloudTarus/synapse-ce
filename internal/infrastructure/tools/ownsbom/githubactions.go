package ownsbom

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// GitHubActions catalogs the actions a repository's CI runs: every `uses: owner/repo@ref` in a workflow under
// .github/workflows and in a composite action's action.yml. OSV publishes advisories against actions (for
// example GHSA-cxww-7g56-2vh6 for actions/download-artifact), and a workflow was previously checked only as
// configuration, so a vulnerable action pinned by version matched nothing (#1665).
//
// The component is the action repository, keyed as OSV keys it ("owner/repo", lower case); a step that
// names a subdirectory (owner/repo/path@ref) and a reusable workflow (owner/repo/.github/workflows/x.yml@ref)
// run code from the same repository. A version tag becomes the component
// version without its leading v. A commit SHA, a branch or a major-only tag is kept as written: no advisory
// range can place it, so it matches nothing rather than something guessed. Local (./) and docker:// steps are
// not actions from a registry and are skipped.
//
// Actions run with the repository's CI credentials, so they are gated, but they are not shipped code: the scope
// is development.
type GitHubActions struct{}

func (GitHubActions) Ecosystem() string { return "github-actions" }

// Markers is empty: workflows and composite actions are both recognized by path, so the doctor's
// basename-based readiness check is not changed by a file it does not scan.
func (GitHubActions) Markers() []string { return nil }

// MatchesPath recognizes a workflow GitHub runs, a .yml or .yaml file directly under the root
// .github/workflows directory, and a composite action manifest, action.yml or action.yaml anywhere.
func (GitHubActions) MatchesPath(rel string) bool {
	lower := strings.ToLower(rel)
	base := lower[strings.LastIndexByte(lower, '/')+1:]
	if base == "action.yml" || base == "action.yaml" {
		return true
	}
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	return lower == ".github/workflows/"+base
}

// ghaStep and ghaFile are the only parts of a workflow or composite action that name an action: a job's
// reusable workflow (jobs.<id>.uses), a job step (jobs.<id>.steps[].uses), and a composite step
// (runs.steps[].uses). Reading the YAML rather than lines keeps text inside run scripts and with: inputs out.
type ghaStep struct {
	Uses string `yaml:"uses"`
}

type ghaFile struct {
	Jobs map[string]struct {
		Uses  string    `yaml:"uses"`
		Steps []ghaStep `yaml:"steps"`
	} `yaml:"jobs"`
	Runs struct {
		Steps []ghaStep `yaml:"steps"`
	} `yaml:"runs"`
}

// actionRef is owner/repo[/path]@ref with GitHub's owner and repository name characters.
var actionRef = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([A-Za-z0-9._-]+)(?:/[^@]*)?@([A-Za-z0-9._/-]+)$`)

// versionTag is a release tag with at least major.minor; a bare major tag floats and is not a version.
var versionTag = regexp.MustCompile(`^[vV]?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)$`)

func (GitHubActions) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	var file ghaFile
	if err := yaml.Unmarshal(in.Content, &file); err != nil {
		lower := strings.ToLower(filepath.Base(in.Path))
		if lower == "action.yml" || lower == "action.yaml" {
			// An action.yml outside the root workflows directory may be a fixture or a template; one that
			// does not parse is not an action GitHub would run, so it is skipped rather than failing the scan.
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("parse workflow: %w", err)
	}
	var refs []string
	jobIDs := make([]string, 0, len(file.Jobs))
	for id := range file.Jobs {
		jobIDs = append(jobIDs, id)
	}
	sort.Strings(jobIDs)
	for _, id := range jobIDs {
		job := file.Jobs[id]
		refs = append(refs, job.Uses)
		for _, step := range job.Steps {
			refs = append(refs, step.Uses)
		}
	}
	for _, step := range file.Runs.Steps {
		refs = append(refs, step.Uses)
	}

	var comps []sbom.Component
	seen := map[string]bool{}
	for _, raw := range refs {
		ref := strings.TrimSpace(raw)
		if ref == "" || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		parts := actionRef.FindStringSubmatch(ref)
		if parts == nil {
			continue
		}
		// GitHub resolves owner and repository names case-insensitively, and OSV keys them in lower case.
		name := strings.ToLower(parts[1] + "/" + parts[2])
		version := parts[3]
		if tag := versionTag.FindStringSubmatch(version); tag != nil {
			version = tag[1]
		}
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		comps = append(comps, sbom.Component{
			Name: name, Version: version,
			PURL:     "pkg:githubactions/" + name + "@" + version,
			Location: in.Path, Scope: sbom.ScopeDevelopment,
		})
	}
	return comps, nil, nil
}
