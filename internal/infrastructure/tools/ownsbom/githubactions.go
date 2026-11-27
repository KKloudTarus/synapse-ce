package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// GitHubActions catalogs the actions a repository's CI runs: every `uses: owner/repo@ref` in a workflow under
// .github/workflows and in a composite action's action.yml. OSV publishes advisories against actions (for
// example GHSA-cxww-7g56-2vh6 for actions/download-artifact), and a workflow was previously checked only as
// configuration, so a vulnerable action pinned by version matched nothing (#1665).
//
// The component is the action repository, keyed as OSV keys it ("owner/repo"); a step that names a
// subdirectory (owner/repo/path@ref) runs code from the same repository. A version tag becomes the component
// version without its leading v. A commit SHA, a branch or a major-only tag is kept as written: no advisory
// range can place it, so it matches nothing rather than something guessed. Local (./) and docker:// steps are
// not actions from a registry and are skipped.
//
// Actions run with the repository's CI credentials, so they are gated, but they are not shipped code: the scope
// is development.
type GitHubActions struct{}

func (GitHubActions) Ecosystem() string { return "github-actions" }

// Markers are the composite action manifests; workflows are recognized by path.
func (GitHubActions) Markers() []string { return []string{"action.yml", "action.yaml"} }

// MatchesPath recognizes a workflow: a .yml or .yaml file directly under a .github/workflows directory.
func (GitHubActions) MatchesPath(rel string) bool {
	lower := strings.ToLower(rel)
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	dir := lower[:max(strings.LastIndexByte(lower, '/'), 0)]
	return dir == ".github/workflows" || strings.HasSuffix(dir, "/.github/workflows")
}

var usesLine = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*["']?([^"'\s#]+)`)

// actionRef is owner/repo[/path]@ref with GitHub's owner and repository name characters.
var actionRef = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([A-Za-z0-9._-]+)(?:/[^@]*)?@([A-Za-z0-9._/-]+)$`)

// versionTag is a release tag with at least major.minor; a bare major tag floats and is not a version.
var versionTag = regexp.MustCompile(`^v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)$`)

func (GitHubActions) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	var comps []sbom.Component
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(in.Content))
	scanner.Buffer(make([]byte, 0, 64*1024), maxManifestBytes)
	for scanner.Scan() {
		m := usesLine.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		ref := m[1]
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		parts := actionRef.FindStringSubmatch(ref)
		if parts == nil {
			continue
		}
		name := parts[1] + "/" + parts[2]
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
	return comps, nil, scanner.Err()
}
