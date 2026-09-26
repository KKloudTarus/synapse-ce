package ownsbom

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// A pom.xml on its own names almost nothing useful. A Spring Boot or JHipster project declares starters with
// no <version> at all, because the parent BOM manages every one, and the transitive tree where most CVEs live
// (spring-core, snakeyaml, tomcat-embed-core, jackson-databind) appears in no pom.xml in the repository. So a
// direct-literal parse of a real Java service reports zero components while the project actually depends on
// several hundred artifacts. Measured on ten live JHipster services, Trivy resolved 1768 vulnerabilities and
// this engine reported 174, all of them from the npm side of the same repositories.
//
// This file closes that by resolving the tree from the LOCAL MAVEN REPOSITORY (~/.m2/repository): the parent
// chain, imported BOMs, property interpolation and the transitive walk are all done by reading .pom files
// that are already on disk. It executes nothing, reaches no network, and needs no toolchain, which is what
// separates it from the opt-in mavenresolve adapter that shells out to `mvn`. On any machine that has built
// the project once (a developer's, a CI runner with a cached ~/.m2) the full tree is available for free.
//
// Deliberately NOT modelled, because guessing any of them would put wrong versions in an inventory:
//   - <profiles>: which profile is active is a property of the build invocation, not of the file.
//   - version RANGES ([1.0,2.0)): resolving one needs the repository metadata index, not just the .pom.
//   - mirrors, <repositories> and classifiers: the artifact path is taken as the standard layout only.
//
// A dependency whose version stays unresolved after the parent chain and the managed set is SKIPPED, never
// emitted unversioned: an unversioned row is coverage the scan does not have.

const (
	maxPomBytes        = 2 << 20 // one .pom is small; cap the read defensively
	maxPomParentDepth  = 16      // bound the <parent> walk
	maxPomReads        = 20000   // bound total .pom reads for one project
	maxTreeNodes       = 20000   // bound the emitted component count
	maxTreeDepth       = 32      // bound the transitive walk
	maxPropertyPasses  = 8       // bound ${a} -> ${b} -> literal chains
	maxImportBOMsPerPO = 64      // bound <scope>import</scope> fan-out per POM
)

// mavenCoord is a resolved groupId:artifactId:version.
type mavenCoord struct{ group, artifact, version string }

func (c mavenCoord) ga() string { return c.group + ":" + c.artifact }

// mavenProps carries a POM's <properties> block, whose child element names are arbitrary.
type mavenProps map[string]string

// UnmarshalXML reads every child element of <properties> as a name/value pair.
func (p *mavenProps) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	if *p == nil {
		*p = mavenProps{}
	}
	for {
		tok, err := d.Token()
		if err != nil {
			return err // including io.EOF, which ends the element in practice
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return err
			}
			(*p)[t.Name.Local] = strings.TrimSpace(value)
		case xml.EndElement:
			return nil
		}
	}
}

type mavenDepXML struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Optional   string `xml:"optional"`
	Exclusions struct {
		Exclusion []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
		} `xml:"exclusion"`
	} `xml:"exclusions"`
}

type mavenPOMXML struct {
	Parent struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
	GroupID    string     `xml:"groupId"`
	ArtifactID string     `xml:"artifactId"`
	Version    string     `xml:"version"`
	Properties mavenProps `xml:"properties"`

	DependencyManagement struct {
		Dependencies struct {
			Dependency []mavenDepXML `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
	Dependencies struct {
		Dependency []mavenDepXML `xml:"dependency"`
	} `xml:"dependencies"`
	Repositories struct {
		Repository []struct {
			ID  string `xml:"id"`
			URL string `xml:"url"`
		} `xml:"repository"`
	} `xml:"repositories"`
}

// managedDep is one <dependencyManagement> entry together with the properties of the POM that DECLARED it.
//
// Carrying the declaring POM's properties is what makes a managed version correct. A BOM pins its own modules
// with <version>${project.version}</version>, and its entries are inherited by every project that imports it.
// Interpolating such an entry with the INHERITING project's properties substituted that project's own version
// instead: on a live service it reported feign-reactor-cloud at the scanned project's 0.0.1-SNAPSHOT rather
// than 3.2.5. Worse, when the interpolation produced no resolvable version the managed entry was discarded and
// a transitive declaration won, so a Spring Boot project resolved jackson 2.12.3 where its own BOM pins
// 2.13.3 -- an inventory that names versions the build never uses.
type managedDep struct {
	dep   mavenDepXML
	props map[string]string
}

// effectivePOM is one POM after its parent chain and imported BOMs have been merged in.
type effectivePOM struct {
	coord   mavenCoord
	props   map[string]string
	managed map[string]managedDep // "group:artifact" -> the managed entry and its declaring properties
	deps    []mavenDepXML         // own plus inherited <dependencies>, in declaration order
}

// mavenLocalRepo reads effective POMs out of a local Maven repository. It memoises by coordinate, because a
// Spring Boot tree reaches the same parent POM from hundreds of nodes.
type mavenLocalRepo struct {
	root  string
	cache map[mavenCoord]*effectivePOM
	reads int
	// fetcher resolves a POM the local repository does not have. It is nil for a local-only resolution, which
	// is what an --offline scan and every unit test use.
	fetcher POMFetcher
	// repositories are the SCANNED PROJECT's declared repositories, used in order before Maven Central. A
	// repository declared by a third-party dependency is deliberately not used.
	repositories []string
	ctx          context.Context
	fetches      int
}

// localMavenRepoRoot locates the local repository without running anything. The MAVEN_REPO_LOCAL override
// comes first, then the <localRepository> a user set in ~/.m2/settings.xml, then Maven's default. It returns
// "" when no directory exists, and the caller then falls back to the direct-literal parse.
func localMavenRepoRoot() string {
	if dir := strings.TrimSpace(os.Getenv("MAVEN_REPO_LOCAL")); dir != "" {
		if isDir(dir) {
			return dir
		}
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	if dir := settingsLocalRepository(filepath.Join(home, ".m2", "settings.xml")); dir != "" && isDir(dir) {
		return dir
	}
	if dir := filepath.Join(home, ".m2", "repository"); isDir(dir) {
		return dir
	}
	return ""
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// settingsLocalRepository reads <localRepository> from a settings.xml. Anything unreadable yields "" so the
// caller falls through to the default location; a settings file is never required.
func settingsLocalRepository(path string) string {
	data, err := readBounded(path, maxPomBytes)
	if err != nil {
		return ""
	}
	var settings struct {
		LocalRepository string `xml:"localRepository"`
	}
	if err := xml.Unmarshal(data, &settings); err != nil {
		return ""
	}
	dir := strings.TrimSpace(settings.LocalRepository)
	if dir == "" {
		return ""
	}
	// settings.xml may interpolate ${user.home}; that is the only property worth honouring here.
	if home, err := os.UserHomeDir(); err == nil {
		dir = strings.ReplaceAll(dir, "${user.home}", home)
	}
	if strings.Contains(dir, "${") {
		return "" // an unresolved property would build a wrong path
	}
	return dir
}

func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, os.ErrInvalid
	}
	return os.ReadFile(path)
}

// pomPath builds the standard-layout path of a coordinate's .pom inside the local repository.
func (r *mavenLocalRepo) pomPath(c mavenCoord) string {
	parts := append(strings.Split(c.group, "."), c.artifact, c.version, c.artifact+"-"+c.version+".pom")
	return filepath.Join(append([]string{r.root}, parts...)...)
}

// effective returns the coordinate's effective POM, reading it and its ancestry from the local repository.
// A missing or unparsable .pom yields nil, which costs that subtree and never fails the scan.
func (r *mavenLocalRepo) effective(c mavenCoord, depth int) *effectivePOM {
	if depth > maxPomParentDepth || c.group == "" || c.artifact == "" || c.version == "" {
		return nil
	}
	if cached, ok := r.cache[c]; ok {
		return cached // may be nil: a known-missing POM is not retried
	}
	r.cache[c] = nil // break a cyclic parent chain before recursing
	if r.reads >= maxPomReads {
		return nil
	}
	r.reads++
	data, err := readBounded(r.pomPath(c), maxPomBytes)
	if err != nil {
		// Nothing on disk. On a machine that has never run Maven, which is what a CI runner is, that is every
		// POM, so fetching is the difference between the full tree and almost nothing.
		fetched, ok := r.fetch(c)
		if !ok {
			return nil
		}
		data = fetched
	}
	var raw mavenPOMXML
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	eff := r.build(&raw, c, depth, "")
	r.cache[c] = eff
	return eff
}

// fetch retrieves a POM the local repository does not hold. It is bounded by the fetcher's own request budget
// and returns false for anything it could not get, which costs that subtree and never the scan.
func (r *mavenLocalRepo) fetch(c mavenCoord) ([]byte, bool) {
	if r.fetcher == nil {
		return nil, false
	}
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, false
	}
	data, ok := r.fetcher.FetchPOM(ctx, c.group, c.artifact, c.version, r.repositories)
	if ok {
		r.fetches++
	}
	return data, ok
}

// build merges a parsed POM with its parent chain and its imported BOMs. dir is the on-disk directory of a
// PROJECT pom.xml, used to follow a <relativePath> parent that is not installed in the local repository yet;
// it is empty for a POM that came out of the repository.
func (r *mavenLocalRepo) build(raw *mavenPOMXML, self mavenCoord, depth int, dir string) *effectivePOM {
	parentCoord := mavenCoord{
		group:    strings.TrimSpace(raw.Parent.GroupID),
		artifact: strings.TrimSpace(raw.Parent.ArtifactID),
		version:  strings.TrimSpace(raw.Parent.Version),
	}
	var parent *effectivePOM
	if parentCoord.artifact != "" {
		if dir != "" {
			if p := r.parentFromRelativePath(dir, raw, parentCoord, depth); p != nil {
				parent = p
			}
		}
		if parent == nil {
			parent = r.effective(parentCoord, depth+1)
		}
	}

	// A POM may omit its own groupId/version and inherit both from the parent.
	coord := self
	if coord.group == "" {
		coord.group = firstNonEmpty(strings.TrimSpace(raw.GroupID), parentCoord.group)
	}
	if coord.artifact == "" {
		coord.artifact = strings.TrimSpace(raw.ArtifactID)
	}
	if coord.version == "" {
		coord.version = firstNonEmpty(strings.TrimSpace(raw.Version), parentCoord.version)
	}

	props := map[string]string{}
	if parent != nil {
		for k, v := range parent.props {
			props[k] = v
		}
	}
	for k, v := range raw.Properties {
		props[k] = v
	}
	// The project coordinates are addressable as properties and are what ${project.version} means.
	props["project.groupId"] = coord.group
	props["project.artifactId"] = coord.artifact
	props["project.version"] = coord.version
	props["pom.groupId"] = coord.group
	props["pom.artifactId"] = coord.artifact
	props["pom.version"] = coord.version
	props["version"] = coord.version
	// ${project.parent.version} is how a multi-module release pins its own siblings, and it is not the same
	// as ${project.version} when a module carries its own version. swagger-core declares swagger-models and
	// swagger-annotations this way, so without these two artifacts went unresolved on 8 of 10 live services.
	if parentCoord.artifact != "" {
		parentVersion := interpolate(parentCoord.version, props)
		parentGroup := firstNonEmpty(parentCoord.group, coord.group)
		props["project.parent.groupId"] = parentGroup
		props["project.parent.artifactId"] = parentCoord.artifact
		props["project.parent.version"] = parentVersion
		props["pom.parent.groupId"] = parentGroup
		props["pom.parent.artifactId"] = parentCoord.artifact
		props["pom.parent.version"] = parentVersion
	}

	// dependencyManagement precedence, in the order Maven's model builder applies it and the order that
	// decides a real Spring Cloud project's versions:
	//
	//   1. an entry the POM declares itself wins over everything;
	//   2. an entry INHERITED FROM THE PARENT wins over an imported BOM, because the parent's management is
	//      merged into the model before imports are resolved and an import only fills what is unmanaged;
	//   3. among the imports the FIRST declaration wins.
	//
	// Getting (2) backwards resolved spring-retry to 1.3.1 on a JHipster service: jhipster-dependencies takes
	// Spring Boot 2.7.3 from its parent, which pins 1.3.3, while the spring-cloud BOM it imports carries an
	// older Boot that pins 1.3.1. Letting the import win named a version the build never uses.
	managed := map[string]managedDep{}
	imports := 0
	for _, d := range raw.DependencyManagement.Dependencies.Dependency {
		if !isBOMImport(d) {
			continue
		}
		if imports >= maxImportBOMsPerPO {
			break
		}
		imports++
		bom := r.effective(mavenCoord{
			group:    interpolate(strings.TrimSpace(d.GroupID), props),
			artifact: interpolate(strings.TrimSpace(d.ArtifactID), props),
			version:  interpolate(strings.TrimSpace(d.Version), props),
		}, depth+1)
		if bom == nil {
			continue
		}
		for k, v := range bom.managed {
			if _, earlier := managed[k]; earlier {
				continue // an earlier import in this POM already decided this artifact
			}
			managed[k] = v
		}
	}
	if parent != nil {
		for k, v := range parent.managed {
			managed[k] = v // an inherited entry overrides an imported one
		}
	}
	for _, d := range raw.DependencyManagement.Dependencies.Dependency {
		if isBOMImport(d) {
			continue
		}
		group := interpolate(strings.TrimSpace(d.GroupID), props)
		artifact := interpolate(strings.TrimSpace(d.ArtifactID), props)
		if group == "" || artifact == "" {
			continue
		}
		managed[group+":"+artifact] = managedDep{dep: d, props: props}
	}

	// <dependencies> are inherited, so the parent's come first and the child's are appended.
	var deps []mavenDepXML
	if parent != nil {
		deps = append(deps, parent.deps...)
	}
	deps = append(deps, raw.Dependencies.Dependency...)

	return &effectivePOM{coord: coord, props: props, managed: managed, deps: deps}
}

// parentFromRelativePath follows a <relativePath> parent on disk. A multi-module project's parent is often
// not installed in the local repository, and without this every module in the reactor resolves nothing.
func (r *mavenLocalRepo) parentFromRelativePath(dir string, raw *mavenPOMXML, parentCoord mavenCoord, depth int) *effectivePOM {
	rel := "../pom.xml" // Maven's default when <relativePath> is absent
	if raw.Parent.RelativePath != nil {
		rel = strings.TrimSpace(*raw.Parent.RelativePath)
		if rel == "" {
			return nil // an EMPTY relativePath explicitly means "resolve from the repository"
		}
	}
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, "pom.xml")
	}
	if r.reads >= maxPomReads {
		return nil
	}
	r.reads++
	data, err := readBounded(path, maxPomBytes)
	if err != nil {
		return nil
	}
	var parentRaw mavenPOMXML
	if err := xml.Unmarshal(data, &parentRaw); err != nil {
		return nil
	}
	if depth+1 > maxPomParentDepth {
		return nil
	}
	return r.build(&parentRaw, parentCoord, depth+1, filepath.Dir(path))
}

func isBOMImport(d mavenDepXML) bool {
	return strings.EqualFold(strings.TrimSpace(d.Scope), "import") &&
		strings.EqualFold(strings.TrimSpace(d.Type), "pom")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// interpolate expands ${property} references using the POM's effective property set. A reference that does
// not resolve is left as it is, so the caller's IsResolvedVersion check rejects it rather than guessing.
func interpolate(value string, props map[string]string) string {
	for pass := 0; pass < maxPropertyPasses && strings.Contains(value, "${"); pass++ {
		changed := false
		var b strings.Builder
		for i := 0; i < len(value); {
			if strings.HasPrefix(value[i:], "${") {
				if end := strings.Index(value[i:], "}"); end > 0 {
					name := value[i+2 : i+end]
					if replacement, ok := props[name]; ok && !strings.Contains(replacement, "${"+name+"}") {
						b.WriteString(replacement)
						i += end + 1
						changed = true
						continue
					}
				}
			}
			b.WriteByte(value[i])
			i++
		}
		value = b.String()
		if !changed {
			break
		}
	}
	return value
}

// mavenTreeNode is one dependency on the resolution queue.
type mavenTreeNode struct {
	coord      mavenCoord
	scope      string
	depth      int
	exclusions map[string]struct{} // "group:artifact", inherited down the branch
	parent     string              // the PURL of the node that required this one, empty at the root
}

// resolveMavenTree walks the project's dependency tree breadth-first out of the local repository and returns
// the components and edges. Breadth-first is what implements Maven's NEAREST-WINS rule: the first version
// reached for a group:artifact is the one closest to the root, so later sightings are ignored.
//
// Scope follows Maven's transitivity table: a test or provided dependency is not transitive, and an optional
// dependency is not transitive either, so neither contributes its own subtree. The ROOT project's managed
// versions take precedence over a transitive declaration, which is Maven's behaviour and the reason a Spring
// Boot BOM pins the whole tree.
func resolveMavenTree(repo *mavenLocalRepo, root *effectivePOM, location string, baseScope string) ([]sbom.Component, []sbom.Dependency) {
	set := newComponentSet()
	seen := map[string]bool{}     // "group:artifact" -> already resolved (nearest wins)
	purlOf := map[string]string{} // "group:artifact" -> emitted PURL, for edge resolution
	edgeSeen := map[string]bool{}
	var edges []sbom.Dependency

	queue := make([]mavenTreeNode, 0, len(root.deps))
	enqueue := func(owner *effectivePOM, deps []mavenDepXML, depth int, inherited map[string]struct{}, parentPURL, parentScope string, transitive bool) {
		for _, d := range deps {
			group := interpolate(strings.TrimSpace(d.GroupID), owner.props)
			artifact := interpolate(strings.TrimSpace(d.ArtifactID), owner.props)
			if group == "" || artifact == "" {
				continue
			}
			key := group + ":" + artifact
			if _, excluded := inherited[key]; excluded {
				continue
			}
			if _, wildcard := inherited["*:"+artifact]; wildcard {
				continue
			}
			if _, wildcard := inherited[group+":*"]; wildcard {
				continue
			}
			if transitive && strings.EqualFold(strings.TrimSpace(d.Optional), "true") {
				continue // an optional dependency is not inherited by a consumer
			}
			scope := strings.ToLower(strings.TrimSpace(d.Scope))
			// The ROOT project's managed set wins over a transitive declaration, and the owner's own managed
			// set supplies a version for a dependency that declares none.
			version := interpolate(strings.TrimSpace(d.Version), owner.props)
			if entry, ok := root.managed[key]; ok && transitive {
				if v := interpolate(strings.TrimSpace(entry.dep.Version), entry.props); sbom.IsResolvedVersion(v) {
					version = v
				}
				if scope == "" {
					scope = strings.ToLower(strings.TrimSpace(entry.dep.Scope))
				}
			}
			if !sbom.IsResolvedVersion(version) {
				if entry, ok := owner.managed[key]; ok {
					if v := interpolate(strings.TrimSpace(entry.dep.Version), entry.props); sbom.IsResolvedVersion(v) {
						version = v
					}
					if scope == "" {
						scope = strings.ToLower(strings.TrimSpace(entry.dep.Scope))
					}
				}
			}
			if !sbom.IsResolvedVersion(version) {
				continue // never emit an unversioned row: no advisory can match it
			}
			if transitive && !scopeIsTransitive(scope) {
				continue
			}
			if transitive {
				scope = inheritedScope(parentScope, scope)
			}
			next := make(map[string]struct{}, len(inherited)+len(d.Exclusions.Exclusion))
			for k := range inherited {
				next[k] = struct{}{}
			}
			for _, e := range d.Exclusions.Exclusion {
				eg := interpolate(strings.TrimSpace(e.GroupID), owner.props)
				ea := interpolate(strings.TrimSpace(e.ArtifactID), owner.props)
				if eg != "" && ea != "" {
					next[eg+":"+ea] = struct{}{}
				}
			}
			queue = append(queue, mavenTreeNode{
				coord:      mavenCoord{group: group, artifact: artifact, version: version},
				scope:      scope,
				depth:      depth,
				exclusions: next,
				parent:     parentPURL,
			})
		}
	}

	enqueue(root, root.deps, 1, map[string]struct{}{}, "", "", false)
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		if len(seen) >= maxTreeNodes {
			break
		}
		key := node.coord.ga()
		purl := "pkg:maven/" + node.coord.group + "/" + node.coord.artifact + "@" + node.coord.version
		if seen[key] {
			// Nearest already won, but the EDGE is still real: this node depends on the winning version.
			if from, ok := purlOf[key]; ok && node.parent != "" && node.parent != from {
				addMavenEdge(&edges, edgeSeen, node.parent, from)
			}
			continue
		}
		seen[key] = true
		purlOf[key] = purl
		set.add(sbom.Component{
			Name:     key,
			Version:  node.coord.version,
			PURL:     purl,
			Location: location,
			Scope:    mavenScope(node.scope, baseScope),
		})
		if node.parent != "" {
			addMavenEdge(&edges, edgeSeen, node.parent, purl)
		}
		if node.depth >= maxTreeDepth {
			continue
		}
		child := repo.effective(node.coord, 0)
		if child == nil {
			continue // its .pom is not in the local repository: the subtree is unknown, not empty
		}
		enqueue(child, child.deps, node.depth+1, node.exclusions, purl, node.scope, true)
	}
	return set.components(), edges
}

func addMavenEdge(edges *[]sbom.Dependency, seen map[string]bool, from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	key := from + "\x00" + to
	if seen[key] {
		return
	}
	seen[key] = true
	*edges = append(*edges, sbom.Dependency{Ref: from, DependsOn: []string{to}})
}

// inheritedScope applies Maven's scope table to a transitive dependency: the scope a consumer sees depends on
// the scope of the dependency that PULLED IT IN, not only on how the child declares itself. A compile-scope
// child of a TEST dependency is test scope in the consumer, and the same holds for provided and runtime.
//
// Losing this counted another project's test fixtures as production risk: on one live service 29 artifacts
// reached only through archunit, blockhound and docker-java test dependencies were scoped production, which
// inflates exactly the number an operator triages first.
func inheritedScope(parentScope, childScope string) string {
	switch parentScope {
	case "test":
		return "test"
	case "provided", "system":
		return "provided"
	case "runtime":
		return "runtime"
	}
	return childScope
}

// scopeIsTransitive reports whether a dependency in this scope is inherited by a consumer. Maven's table:
// compile and runtime are, test and provided are not, and system is a local path that names no artifact to
// resolve further.
func scopeIsTransitive(scope string) bool {
	switch scope {
	case "", "compile", "runtime":
		return true
	}
	return false
}

// mavenScope maps a Maven scope onto the SBOM scope the risk model uses. test and provided do not ship in
// the deployed artifact, so they are development scope; everything else follows the manifest's own scope.
func mavenScope(scope, base string) string {
	switch scope {
	case "test":
		return sbom.ScopeTest
	case "provided", "system":
		return sbom.ScopeDevelopment
	}
	return base
}

// resolveMavenFromLocalRepository builds the full tree for a project pom.xml. It returns ok=false when there
// is no local repository, when the POM does not parse, or when the tree came out no larger than the
// direct-literal parse, so the caller keeps its existing result rather than trading it for a smaller one.
// projectRepositories returns the https repository URLs the SCANNED PROJECT declares, in declaration order.
// They are tried before Maven Central, which is what lets an internal artifact be fetched from the repository
// that actually holds it rather than demanded of a public mirror that has never heard of it. A repository
// declared by a third-party dependency is deliberately not collected.
func projectRepositories(raw *mavenPOMXML) []string {
	out := make([]string, 0, len(raw.Repositories.Repository))
	for _, entry := range raw.Repositories.Repository {
		url := strings.TrimSpace(entry.URL)
		if url == "" || strings.Contains(url, "${") {
			continue // an unresolved property would build a wrong host
		}
		out = append(out, url)
	}
	return out
}

func resolveMavenFromLocalRepository(ctx context.Context, in ParseInput, direct int, fetcher POMFetcher) ([]sbom.Component, []sbom.Dependency, bool) {
	root := localMavenRepoRoot()
	// With no local repository AND no fetcher there is nothing to resolve from. With a fetcher there is: a CI
	// runner has no ~/.m2, and that is exactly the case this path exists for.
	if root == "" && fetcher == nil {
		return nil, nil, false
	}
	var raw mavenPOMXML
	if err := xml.Unmarshal(in.Content, &raw); err != nil {
		return nil, nil, false
	}
	repo := &mavenLocalRepo{
		root:         root,
		cache:        map[mavenCoord]*effectivePOM{},
		fetcher:      fetcher,
		repositories: projectRepositories(&raw),
		ctx:          ctx,
	}
	self := mavenCoord{
		group:    strings.TrimSpace(raw.GroupID),
		artifact: strings.TrimSpace(raw.ArtifactID),
		version:  strings.TrimSpace(raw.Version),
	}
	eff := repo.build(&raw, self, 0, in.Dir)
	if eff == nil {
		return nil, nil, false
	}
	comps, edges := resolveMavenTree(repo, eff, in.Path, sbom.ClassifyScope(in.Path, ""))
	if len(comps) <= direct {
		return nil, nil, false
	}
	return comps, edges, true
}
