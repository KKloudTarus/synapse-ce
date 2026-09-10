package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Pnpm is the owned pnpm parser – npm-ecosystem packages resolved by pnpm. It reads the
// FULL resolved set from pnpm-lock.yaml's top-level `packages:` map, whose keys encode each package's
// name@version. The key format varies by lockfile version – v5 `/name/version`, v6 `/name@version(peers)`,
// v9 `name@version` (peers moved to `snapshots:`) – all handled. Rather than pull in a YAML library (the
// owned parsers stay vendor-neutral + dependency-light), it scans for the `packages:` block and reads its
// indent-2 key lines (values, at deeper indent, are ignored – only the keys carry the identity we need).
//
// Dependency EDGES are emitted from each package's `dependencies:`/`optionalDependencies:` sub-maps, which
// live in the `packages:` block (v5/v6) or the `snapshots:` block (v9). Each edge is package→package,
// resolved against the emitted-component index (resolution-as-filter: an edge is kept only when both
// endpoints are emitted components), matching npm.go. There is no synthetic project-root node, so a direct
// (top-level) dependency is simply one nothing else depends on (see sbom.PathToRoot); the `importers:` block
// is not turned into edges here (it would need the root node). Scope is the manifest path's base scope; the
// per-workspace dev/prod refinement (pnpm hoists all workspaces into one root lock) is applied post-SBOM by
// the manifest enricher's pnpm pass, which runs regardless of the SBOM producer.
type Pnpm struct{}

// Ecosystem identifies this parser's package ecosystem (pnpm resolves npm packages).
func (Pnpm) Ecosystem() string { return "npm" }

// Markers are the lockfile basenames Pnpm claims.
func (Pnpm) Markers() []string { return []string{"pnpm-lock.yaml"} }

type pnpmRawDep struct {
	key      string
	optional bool
}

// pnpmRawEdge is one package's accumulated dependency keys, resolved to PURLs after the full scan (so a
// forward reference to a package defined later in the file still resolves).
type pnpmRawEdge struct {
	parent string       // the package/snapshot key spec (edge source)
	deps   []pnpmRawDep // resolved dependency keys with per-edge optionality
}

// Parse extracts the resolved npm packages from a pnpm-lock.yaml `packages:` block as npm components, and the
// dependency edges from every package's `dependencies:`/`optionalDependencies:` sub-map (in `packages:` for
// v5/v6, in `snapshots:` for v9).
func (Pnpm) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	purlByKey := map[string]string{} // "name@version" → PURL: the emitted-component index for edge resolution

	section := ""           // current top-level section
	var cur *sbom.Component // current component (packages section only), held so its integrity (SRI) attaches
	curKey := ""            // current package/snapshot key spec (edge source), set in packages AND snapshots
	inDeps := false         // inside a dependencies:/optionalDependencies: sub-block
	depsOptional := false   // whether the current dependency sub-block is optionalDependencies
	var curDeps []pnpmRawDep
	var rawEdges []pnpmRawEdge

	// flush completes the current package block: emit its component (packages only), index it, and record its
	// accumulated edge. Called on the next indent-2 key, a new section, and EOF.
	flush := func() {
		if cur != nil {
			set.add(*cur)
			purlByKey[cur.Name+"@"+cur.Version] = cur.PURL
			cur = nil
		}
		if curKey != "" && len(curDeps) > 0 {
			rawEdges = append(rawEdges, pnpmRawEdge{parent: curKey, deps: curDeps})
		}
		curKey, curDeps, inDeps, depsOptional = "", nil, false, false
	}

	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue // blank/comment lines don't delimit sections (pnpm-lock blank-separates entries)
		}
		if !indented(raw) { // a col-0 line: a new top-level section.
			flush()
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), ":"))
			continue
		}
		// Components come only from `packages:`; edges from the dependency sub-maps in `packages:` (v5/v6) and
		// `snapshots:` (v9). Other sections (importers/settings/…) carry no package→package edges.
		if section != "packages" && section != "snapshots" {
			continue
		}
		line := strings.TrimSpace(raw)
		switch leadingIndent(raw) {
		case 2:
			// An indent-2 key line: the previous package's block is complete.
			flush()
			if !strings.HasSuffix(line, ":") {
				continue
			}
			spec := strings.Trim(strings.TrimSuffix(line, ":"), `'"`) // the package key, unquoted (scoped keys quote)
			name, version, ok := pnpmSpecNameVersion(spec)
			if !ok {
				continue
			}
			curKey = spec
			if section == "packages" { // the sole source of components
				purlName := name
				if strings.HasPrefix(purlName, "@") {
					purlName = "%40" + purlName[1:] // PURL spec: scoped @ → %40 (matches the npm/yarn parsers)
				}
				cur = &sbom.Component{
					Name:     name,
					Version:  version,
					PURL:     "pkg:npm/" + purlName + "@" + version,
					Location: in.Path,
					Scope:    baseScope,
				}
			}
		case 4:
			// A sub-key of the current package: dependencies:/optionalDependencies: open a deps block; any
			// other sub-key (resolution:/engines:/…) closes it, and may carry the integrity (tamper evidence).
			key := strings.TrimSuffix(line, ":")
			inDeps = key == "dependencies" || key == "optionalDependencies"
			depsOptional = inDeps && key == "optionalDependencies"
			if !inDeps && cur != nil && cur.Checksums == nil {
				if v := pnpmIntegrityFromLine(raw); v != "" {
					cur.Checksums = parseSubresourceIntegrity(v)
				}
			}
		default: // indent >= 6: a dep entry inside a deps block, or a block-form integrity line
			if inDeps && curKey != "" {
				if dk, ok := pnpmDepKey(line); ok {
					curDeps = append(curDeps, pnpmRawDep{key: dk, optional: depsOptional})
				}
			} else if cur != nil && cur.Checksums == nil {
				if v := pnpmIntegrityFromLine(raw); v != "" {
					cur.Checksums = parseSubresourceIntegrity(v)
				}
			}
		}
	}
	flush() // the last package in the file
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan pnpm-lock.yaml: %w", err)
	}
	return set.components(), pnpmResolveEdges(rawEdges, purlByKey, baseScope), nil
}

// pnpmDepKey parses one dependency entry line from a `dependencies:`/`optionalDependencies:` sub-map into the
// "name@version" component key it targets. The value takes one of two forms after its `(peers…)` suffix and
// any `npm:` prefix are stripped: a bare resolved version, in which case the target is `<mapKey>@<version>`;
// or a full `name@version` package id (an ALIAS, where the map key is only the local import name), in which
// case the target is that package. A value that is a range, a `link:`/`file:` path, or otherwise not a
// resolved version/package id yields ok=false and is dropped by the resolution-as-filter.
//
// A v5 `_<peers>` value form is not decoded: any value containing `_` is dropped, so a v5 peer-suffixed value
// (whose peer part can itself contain `@`) is never misread as an alias package id. That makes this path emit
// a safe missed edge for such legacy values, never a wrong edge. v6/v9, which use the `(peers)` form, are full.
func pnpmDepKey(line string) (string, bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", false
	}
	val := strings.Trim(strings.TrimSpace(line[i+1:]), `'"`)
	val = strings.TrimPrefix(val, "npm:") // an npm: alias value is the real package id
	if j := strings.IndexByte(val, '('); j >= 0 {
		val = val[:j] // drop the (peers) suffix (v6/v9)
	}
	if val == "" {
		return "", false
	}
	// A v5 peer suffix is `_<peers>` (which may contain '@'); a bare resolved version and a v6/v9 value never
	// contain '_'. Dropping any '_'-bearing value keeps a v5 peer value from being misread as an alias
	// package id, so this path never emits a wrong edge — a v5 peer-suffixed value is a safe missed edge.
	if strings.IndexByte(val, '_') >= 0 {
		return "", false
	}
	if strings.LastIndexByte(val, '@') > 0 {
		// The value carries its own version separator → it is a package id (alias); it IS the target.
		tn, tv, ok := pnpmSpecNameVersion(val)
		if !ok {
			return "", false
		}
		return tn + "@" + tv, true
	}
	name := strings.Trim(strings.TrimSpace(line[:i]), `'"`)
	if name == "" || !sbom.IsResolvedVersion(val) {
		return "", false
	}
	return name + "@" + val, true
}

// pnpmResolveEdges turns raw dependency keys into sbom.Dependency records resolved against the emitted
// component index. Required/optional metadata is retained even when peer-context snapshot variants collapse
// to the same component Ref; if the same target is seen as both required and optional, required wins.
func pnpmResolveEdges(rawEdges []pnpmRawEdge, purlByKey map[string]string, scope string) []sbom.Dependency {
	var order []string
	targetOptional := map[string]map[string]bool{} // Ref -> target PURL -> optional
	for _, re := range rawEdges {
		pn, pv, ok := pnpmSpecNameVersion(re.parent)
		if !ok {
			continue
		}
		ref := purlByKey[pn+"@"+pv]
		if ref == "" {
			continue // source not emitted (e.g. snapshot without a packages entry)
		}
		if targetOptional[ref] == nil {
			targetOptional[ref] = map[string]bool{}
			order = append(order, ref)
		}
		for _, dep := range re.deps {
			target := purlByKey[dep.key]
			if target == "" || target == ref {
				continue
			}
			old, exists := targetOptional[ref][target]
			if !exists {
				targetOptional[ref][target] = dep.optional
				continue
			}
			if old && !dep.optional {
				targetOptional[ref][target] = false
			}
		}
	}
	var edges []sbom.Dependency
	for _, ref := range order {
		var required, optional []string
		for target, isOptional := range targetOptional[ref] {
			if isOptional {
				optional = append(optional, target)
			} else {
				required = append(required, target)
			}
		}
		sort.Strings(required)
		sort.Strings(optional)
		if len(required) > 0 {
			edges = append(edges, sbom.Dependency{Ref: ref, DependsOn: required, Scope: scope})
		}
		if len(optional) > 0 {
			edges = append(edges, sbom.Dependency{Ref: ref, DependsOn: optional, Scope: scope, Optional: true})
		}
	}
	return edges
}

// pnpmIntegrityFromLine extracts the Subresource Integrity value from a pnpm-lock resolution line, inline
// (`resolution: {integrity: sha512-...}`) or block (`integrity: sha512-...`). Returns "" when the line carries
// no integrity token. The value stops at the next inline-map key (`,`) or the map close (`}`).
func pnpmIntegrityFromLine(raw string) string {
	i := strings.Index(raw, "integrity:")
	if i < 0 {
		return ""
	}
	v := raw[i+len("integrity:"):]
	if j := strings.IndexAny(v, ",}"); j >= 0 {
		v = v[:j]
	}
	return strings.Trim(v, ` '"`)
}

// pnpmSpecNameVersion splits a pnpm-lock `packages:` key into (name, version), across lockfile versions:
//
//	v9: lodash@4.17.21 @babel/core@7.23.0
//	v6: /lodash@4.17.21(react@18.0.0) /@babel/core@7.23.0
//	v5: /lodash/4.17.21 /@babel/core/7.23.0
//
// It strips a leading `/` and any `(peer…)` suffix, then splits on the version separator: the last `@`
// AFTER index 0 (v6/v9 – a leading `@` is the scope, not the separator), else the last `/` (v5). The
// version must be a resolved (pinned) version, else the key is dropped.
func pnpmSpecNameVersion(spec string) (name, version string, ok bool) {
	spec = strings.TrimPrefix(spec, "/")
	if i := strings.IndexByte(spec, '('); i >= 0 {
		spec = spec[:i] // drop the peer-deps suffix (v6); it may itself contain '@', so strip before splitting
	}
	sep := -1
	for i := 1; i < len(spec); i++ { // last '@' after index 0 = the v6/v9 separator
		if spec[i] == '@' {
			sep = i
		}
	}
	if sep < 0 { // no '@' after the scope → v5 `name/version`
		sep = strings.LastIndexByte(spec, '/')
	}
	if sep <= 0 || sep == len(spec)-1 {
		return "", "", false
	}
	name, version = spec[:sep], spec[sep+1:]
	if name == "" || !sbom.IsResolvedVersion(version) {
		return "", "", false
	}
	return name, version, true
}
