package sca

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (s *Service) SetOwnershipSource(reader ports.OwnershipSourceReader, store ports.OwnershipSourceStore) error {
	if reader == nil || store == nil {
		return shared.ErrValidation
	}
	s.ownershipReader, s.ownershipSources = reader, store
	return nil
}

func (s *Service) captureOwnershipSource(ctx context.Context, actor string, eng shared.ID, req ports.AcquireRequest, ws *ports.Workspace) (*ports.OwnershipSourceRecord, error) {
	if s.ownershipSources == nil {
		return nil, nil
	}
	captured, err := s.ownershipReader.ReadOwnershipSource(ctx, req, ws)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Acquisition already succeeded. An unsafe/missing CODEOWNERS capture
		// does not discard security scan findings or promote a head to trusted base.
		s.logger().Warn("ownership source capture unavailable", "err", err)
		captured.Files = nil
		captured.Reason = "capture_failed"
	}
	source := ports.OwnershipSourceRecord{ID: s.ids.NewID(), EngagementID: eng, Repository: normalizedSourceTarget(req), Revision: captured.Revision, BaseRevision: captured.BaseRevision, Reason: captured.Reason, CreatedBy: actor, CreatedAt: s.clock.Now().UTC()}
	source.BaseRequired = req.BaseRef != "" || req.BaseCommit != ""
	tenant, _ := shared.TenantFrom(ctx)
	for _, file := range captured.Files {
		source.Snapshots = append(source.Snapshots, ownership.Snapshot{TenantID: tenant, EngagementID: eng, ID: s.ids.NewID(), Repository: source.Repository, Revision: file.Revision, FilePath: file.Path, Content: file.Content, Hash: ownership.ContentHash(file.Content), ParserVersion: ownership.ParserVersion, Trust: "untrusted", CreatedAt: source.CreatedAt})
	}
	if err := s.ownershipSources.SaveOwnershipSource(ctx, source); err != nil {
		return nil, fmt.Errorf("persist ownership source: %w", err)
	}
	return &source, nil
}

func (s *Service) ownershipFindingContext(ctx context.Context, source *ports.OwnershipSourceRecord, root string, result *ScanResult) context.Context {
	if source == nil {
		return ctx
	}
	batch := ports.OwnershipSourceBatch{Source: *source, Findings: map[string]ports.OwnershipFindingSource{}}
	for _, item := range result.Findings {
		evidence := ports.OwnershipFindingSource{Paths: []string{}}
		if root != "" && item.SourceLocation != nil {
			path, err := s.ownershipReader.OwnershipPath(root, item.SourceLocation.File, false)
			if err != nil {
				evidence.Invalid = true
			} else {
				evidence.Paths = []string{path}
			}
		}
		batch.Findings[finding.Identity(item)] = evidence
	}
	if root != "" && result.SBOM != nil {
		index := newOwnershipManifestIndex(result.SBOM)
		cache := map[string]ports.OwnershipFindingSource{}
		for _, v := range result.Vulnerabilities {
			key := sbom.ComponentID(v.Component, v.Version, v.PackagePURL)
			evidence, ok := cache[key]
			if !ok {
				evidence = s.ownershipManifestPaths(root, index, v)
				cache[key] = evidence
			}
			batch.Findings[vulnDedupKey(v)] = evidence
		}
	}
	return ports.WithOwnershipSource(ctx, batch)
}

type ownershipManifestIndex struct {
	doc           *sbom.SBOM
	components    map[string][]sbom.Component
	byNameVersion map[string][]string
}

func newOwnershipManifestIndex(doc *sbom.SBOM) ownershipManifestIndex {
	index := ownershipManifestIndex{doc: doc, components: map[string][]sbom.Component{}, byNameVersion: map[string][]string{}}
	for _, component := range doc.Components {
		id := sbom.ComponentID(component.Name, component.Version, component.PURL)
		index.components[id] = append(index.components[id], component)
		key := component.Name + "\x00" + component.Version
		index.byNameVersion[key] = append(index.byNameVersion[key], id)
	}
	return index
}

func (s *Service) ownershipManifestPaths(root string, index ownershipManifestIndex, vuln vulnerability.Vulnerability) ports.OwnershipFindingSource {
	out := ports.OwnershipFindingSource{Paths: []string{}}
	targets := slices.Clone(index.byNameVersion[vuln.Component+"\x00"+vuln.Version])
	if vuln.PackagePURL != "" {
		id := sbom.ComponentID(vuln.Component, vuln.Version, vuln.PackagePURL)
		targets = nil
		if len(index.components[id]) > 0 {
			targets = []string{id}
		}
	}
	// Same name/version in different ecosystems without a PURL is ambiguous.
	slices.Sort(targets)
	targets = slices.Compact(targets)
	if len(targets) > 1 && vuln.PackagePURL == "" {
		out.Invalid = true
		return out
	}
	for _, id := range targets {
		introducers := sbom.IntroducedBy(index.doc.Dependencies, id)
		ids := append([]string{id}, introducers...)
		slices.Sort(ids)
		for _, reference := range slices.Compact(ids) {
			found := false
			for _, component := range index.components[reference] {
				for _, raw := range componentLocations(component) {
					path, err := s.ownershipReader.OwnershipPath(root, raw, true)
					if errors.Is(err, ports.ErrOwnershipNonManifest) {
						continue
					}
					if err != nil {
						out.Invalid = true
						continue
					}
					out.Paths = append(out.Paths, path)
					found = true
				}
			}
			// Do not select only the known half of a multi-root dependency graph.
			if reference != id && len(introducers) > 1 && !found {
				out.Invalid = true
			}
		}
	}
	slices.Sort(out.Paths)
	out.Paths = slices.Compact(out.Paths)
	if len(out.Paths) > 128 {
		out.Paths = []string{}
		out.Invalid = true
	}
	return out
}

func (s *Service) captureImportedOwnershipSource(ctx context.Context, actor string, eng shared.ID, target string) (*ports.OwnershipSourceRecord, error) {
	if s.ownershipSources == nil {
		return nil, nil
	}
	if strings.TrimSpace(target) == "" {
		target = "imported-sbom"
	}
	source := ports.OwnershipSourceRecord{ID: s.ids.NewID(), EngagementID: eng, Repository: target, Reason: "imported_sbom_without_source", CreatedBy: actor, CreatedAt: s.clock.Now().UTC()}
	if err := s.ownershipSources.SaveOwnershipSource(ctx, source); err != nil {
		return nil, err
	}
	return &source, nil
}

func (s *Service) ownershipSourceReady(ctx context.Context, source *ports.OwnershipSourceRecord) error {
	if source == nil {
		return nil
	}
	return s.ownershipSources.MarkOwnershipSourceReady(ctx, source.EngagementID, source.ID)
}
