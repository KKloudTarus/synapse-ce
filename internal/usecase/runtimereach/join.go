package runtimereach

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

// findingReader reads an engagement's findings (analysis/finding service satisfies it).
type findingReader interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
}

// Service ties the package-ownership join to the raise-only coordinator: given a host's observed library
// loads and its package file-ownership database, it raises exactly the SCA findings whose vulnerable OS
// package was loaded. It is the entry point the fleet host-vulnerability path drives after a host reports
// runtime evidence.
type Service struct {
	findings    findingReader
	coordinator *Coordinator
}

// NewService validates dependencies and returns the join service.
func NewService(findings findingReader, coordinator *Coordinator) (*Service, error) {
	if findings == nil || coordinator == nil {
		return nil, fmt.Errorf("%w: runtimereach service is missing a dependency", shared.ErrValidation)
	}
	return &Service{findings: findings, coordinator: coordinator}, nil
}

// Attribute resolves each observed load to its owning package, joins the resolved packages to the
// engagement's SCA findings by package ownership, and mints a raise-only runtime-reachability judgment for
// every finding whose package was loaded. It returns the number of judgments minted. A load that resolves
// to no package, or a package no finding is about, mints nothing; nothing is ever de-escalated.
func (s *Service) Attribute(ctx context.Context, engagementID shared.ID, ownership *runtimereach.Ownership, loads []runtimereach.LoadEvent) (int, error) {
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	if ownership == nil || len(loads) == 0 {
		return 0, nil
	}
	findings, err := s.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return 0, fmt.Errorf("list findings: %w", err)
	}
	pkgs := FindingPackages(findings)
	if len(pkgs) == 0 {
		return 0, nil
	}
	hits := runtimereach.Join(loads, ownership, pkgs)
	if len(hits) == 0 {
		return 0, nil
	}
	return s.coordinator.Record(ctx, engagementID, hits)
}

// FindingPackages derives the finding-to-package bindings the domain join keys on, from each SCA finding's
// DedupKey (which parses to advisory+component+version). Only vuln-derived SCA findings carry that key; a
// license, SAST, or non-SCA finding has no owning OS package and is skipped, so a runtime load can only ever
// raise an actual OS-package vulnerability. The component name and version are exactly what the host's
// package database records, so the domain join matches them against a resolved package by identity.
func FindingPackages(findings []finding.Finding) []runtimereach.FindingPackage {
	out := make([]runtimereach.FindingPackage, 0, len(findings))
	for _, f := range findings {
		if f.Kind != "" && f.Kind != finding.KindSCA {
			continue
		}
		_, component, version, ok := vulnerability.ParseDedupKey(f.DedupKey)
		if !ok {
			continue
		}
		component = strings.TrimSpace(component)
		version = strings.TrimSpace(version)
		if component == "" || version == "" {
			continue // an unversioned or componentless key cannot be matched to an installed package
		}
		out = append(out, runtimereach.FindingPackage{
			FindingID: f.ID,
			Package:   runtimereach.PackageRef{Name: component, Version: version},
		})
	}
	return out
}
