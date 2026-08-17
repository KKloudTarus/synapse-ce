package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// This file guards documentation REACHABILITY. A page that exists, is accurate, and is linked from prose
// is still invisible to a reader if MkDocs never publishes it — which is exactly how the vulnerability
// intelligence guide went missing from the site while looking present in the repository.
//
// It also guards the published mirrors under docs/guide/repository/. Their canonical sources live outside
// mkdocs.yml's docs_dir, so a mirror is the only copy a site reader sees; an un-checked mirror would
// quietly become the stale version of a security policy.

// mkdocsConfig is the narrow slice of mkdocs.yml these tests need. The nav is a recursive structure of
// single-key maps, so it is decoded as free-form YAML and walked.
type mkdocsConfig struct {
	DocsDir string      `yaml:"docs_dir"`
	Nav     []yaml.Node `yaml:"nav"`
}

// navExclusions lists Markdown files under the guide directory that are intentionally absent from the
// navigation. It is empty on purpose: every current guide is reachable. An entry added here must carry a
// reason, so "not in nav" stays a decision rather than an oversight.
var navExclusions = map[string]string{}

// TestEveryGuidePageIsPublished fails when a Markdown file under the MkDocs docs_dir is missing from the
// navigation. Such a page builds but is unreachable except by direct URL.
func TestEveryGuidePageIsPublished(t *testing.T) {
	root := repoRoot(t)
	cfg := loadMkdocs(t, root)
	guideDir := filepath.Join(root, filepath.FromSlash(cfg.DocsDir))

	navTargets := navMarkdownTargets(t, cfg)
	var unpublished []string

	err := filepath.WalkDir(guideDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		rel, relErr := filepath.Rel(guideDir, path)
		if relErr != nil {
			return relErr
		}
		slash := filepath.ToSlash(rel)
		if navTargets[slash] {
			return nil
		}
		if _, excluded := navExclusions[slash]; excluded {
			return nil
		}
		unpublished = append(unpublished, slash)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", guideDir, err)
	}
	sort.Strings(unpublished)

	for _, rel := range unpublished {
		t.Errorf("docs/guide/%s exists but is not in mkdocs.yml nav, so the site never publishes it; "+
			"add it to nav, or add it to navExclusions with a reason", rel)
	}
}

// TestNavTargetsExist fails when the navigation points at a file that is not on disk. MkDocs reports this
// under --strict, but asserting it in Go means a plain `make test` catches it too, without the Python
// toolchain installed.
func TestNavTargetsExist(t *testing.T) {
	root := repoRoot(t)
	cfg := loadMkdocs(t, root)
	guideDir := filepath.Join(root, filepath.FromSlash(cfg.DocsDir))

	targets := make([]string, 0, len(navMarkdownTargets(t, cfg)))
	for target := range navMarkdownTargets(t, cfg) {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	for _, target := range targets {
		if _, err := os.Stat(filepath.Join(guideDir, filepath.FromSlash(target))); err != nil {
			t.Errorf("mkdocs.yml nav references %s but it does not exist under %s", target, cfg.DocsDir)
		}
	}
}

// localLink matches a relative Markdown link to another .md file, with an optional anchor.
var localLink = regexp.MustCompile(`\]\((\.{0,2}[A-Za-z0-9._/-]*\.md)(#[A-Za-z0-9._-]+)?\)`)

// TestGuideInternalLinksResolve fails when a guide links to a Markdown file that does not exist. Only
// local links are checked; external URLs are deliberately left to a separate, network-dependent job so
// the normal test suite stays deterministic and offline.
func TestGuideInternalLinksResolve(t *testing.T) {
	root := repoRoot(t)
	cfg := loadMkdocs(t, root)
	guideDir := filepath.Join(root, filepath.FromSlash(cfg.DocsDir))

	err := filepath.WalkDir(guideDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		source, _ := filepath.Rel(guideDir, path)
		for _, match := range localLink.FindAllStringSubmatch(string(data), -1) {
			target := match[1]
			resolved := filepath.Join(filepath.Dir(path), filepath.FromSlash(target))
			if _, statErr := os.Stat(resolved); statErr != nil {
				t.Errorf("docs/guide/%s links to %q, which does not resolve",
					filepath.ToSlash(source), target)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", guideDir, err)
	}
}

// publishedMirrors maps each published mirror to the canonical document it represents. The mirror exists
// because mkdocs.yml publishes only docs_dir, so a repository-only document would otherwise never reach
// the site.
var publishedMirrors = map[string]string{
	"docs/guide/repository/telemetry-store-adr.md": "docs/adr/0001-telemetry-store.md",
	"docs/guide/repository/cspm-helper-adr.md":     "docs/adr/0004-cspm-helper-authorization.md",
	"docs/guide/repository/promotion-rules.md":     "docs/architecture/promotion-rules.md",
	"docs/guide/repository/offensive-policy.md":    "docs/redteam/offensive-policy.md",
}

// TestPublishedMirrorsMatchCanonicalSources fails when a mirror is missing its authority notice or when
// any canonical content differs. Mirrors are generated as a one-line notice followed by the complete
// canonical document, so additions, removals, and prose edits are checked bidirectionally.
func TestPublishedMirrorsMatchCanonicalSources(t *testing.T) {
	root := repoRoot(t)

	mirrors := make([]string, 0, len(publishedMirrors))
	for mirror := range publishedMirrors {
		mirrors = append(mirrors, mirror)
	}
	sort.Strings(mirrors)

	for _, mirror := range mirrors {
		canonical := publishedMirrors[mirror]
		canonicalBody, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(canonical)))
		if err != nil {
			t.Errorf("%s mirrors %s, but the canonical source cannot be read: %v", mirror, canonical, err)
			continue
		}
		mirrorBody, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(mirror)))
		if err != nil {
			t.Errorf("published mirror %s is missing: %v", mirror, err)
			continue
		}

		notice := "> Canonical source: [`" + canonical + "`](https://github.com/KKloudTarus/synapse-ce/blob/main/" + canonical + "). Do not edit this published mirror directly.\n\n"
		want := notice + string(canonicalBody)
		if string(mirrorBody) != want {
			t.Errorf("%s has drifted from %s; regenerate the mirror as its canonical-source notice plus the complete canonical file", mirror, canonical)
		}
	}
}

// loadMkdocs decodes mkdocs.yml.
func loadMkdocs(t *testing.T, root string) mkdocsConfig {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "mkdocs.yml"))
	if err != nil {
		t.Fatalf("read mkdocs.yml: %v", err)
	}
	var cfg mkdocsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse mkdocs.yml: %v", err)
	}
	if strings.TrimSpace(cfg.DocsDir) == "" {
		t.Fatal("mkdocs.yml does not set docs_dir")
	}
	if len(cfg.Nav) == 0 {
		t.Fatal("mkdocs.yml has an empty nav")
	}
	return cfg
}

// navMarkdownTargets collects every .md path reachable from the nav tree. The nav nests arbitrarily, so
// every scalar in the structure is inspected rather than assuming a fixed depth.
func navMarkdownTargets(t *testing.T, cfg mkdocsConfig) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for i := range cfg.Nav {
		collectNavTargets(&cfg.Nav[i], out)
	}
	if len(out) == 0 {
		t.Fatal("found no Markdown targets in the mkdocs nav; the parser is wrong")
	}
	return out
}

func collectNavTargets(node *yaml.Node, out map[string]bool) {
	if node == nil {
		return
	}
	if node.Kind == yaml.ScalarNode {
		if strings.HasSuffix(node.Value, ".md") {
			out[node.Value] = true
		}
		return
	}
	for _, child := range node.Content {
		collectNavTargets(child, out)
	}
}
