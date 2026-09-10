package sca

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// publicSourcePackage freezes metadata without retaining a private locator or
// mutable pointer. The acquisition request carries its locator separately.
func publicSourcePackage(item *sourcepackage.Package) *sourcepackage.Package {
	if item == nil {
		return nil
	}
	copy := *item
	copy.Locator, copy.ObjectKey = "", ""
	return &copy
}

func (s *Service) StartUploadedSourceVersionScanWithOptions(ctx context.Context, actor string, tenantID, engagementID, versionID shared.ID, opts ScanOptions) (ports.ScanJob, error) {
	item, err := s.UploadedSourceMetadata(ctx, tenantID, engagementID)
	if err != nil {
		return ports.ScanJob{}, err
	}
	if !versionID.IsZero() && item.VersionID != versionID {
		return ports.ScanJob{}, fmt.Errorf("%w: uploaded source version does not match this assessment", shared.ErrConflict)
	}
	return s.StartScanWithOptions(ctx, actor, engagementID, ports.AcquireRequest{
		Kind: ports.TargetUpload, Value: item.Target(), Locator: item.Locator, SourcePackage: publicSourcePackage(&item),
	}, opts)
}

// Current is selected at admission. Queued uploads resolve their exact owned
// version and verify frozen metadata; legacy jobs require the same content digest.
func (s *Service) pinUploadedSource(ctx context.Context, engagementID shared.ID, req ports.AcquireRequest) (ports.AcquireRequest, error) {
	if req.Kind != ports.TargetUpload {
		if req.SourcePackage != nil {
			return req, fmt.Errorf("%w: uploaded source metadata requires an upload target", shared.ErrValidation)
		}
		return req, nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || s.uploadedSources == nil {
		return req, fmt.Errorf("%w: tenant-bound uploaded source storage is required", shared.ErrValidation)
	}
	if _, err := s.engagements.GetByIDInTenant(ctx, tenantID, engagementID); err != nil {
		return req, err
	}
	var item sourcepackage.Package
	var err error
	if req.SourcePackage != nil && !req.SourcePackage.VersionID.IsZero() {
		reader, ok := s.uploadedSources.(ports.EngagementSourceVersionReader)
		if !ok {
			return req, fmt.Errorf("%w: uploaded source version lookup is unavailable", shared.ErrValidation)
		}
		item, err = reader.GetByVersion(ctx, tenantID, engagementID, req.SourcePackage.VersionID)
	} else {
		item, err = s.uploadedSources.Get(ctx, tenantID, engagementID)
	}
	if err != nil {
		return req, err
	}
	if err := item.Validate(); err != nil {
		return req, err
	}
	if item.TenantID != tenantID || item.EngagementID != engagementID || item.Locator == "" || req.Value != item.Target() {
		return req, fmt.Errorf("%w: uploaded source ownership or content identity does not match", shared.ErrValidation)
	}
	if req.SourcePackage != nil {
		expected, _ := json.Marshal(publicSourcePackage(req.SourcePackage))
		actual, _ := json.Marshal(publicSourcePackage(&item))
		if string(expected) != string(actual) || req.Locator != item.Locator {
			return req, fmt.Errorf("%w: queued uploaded source metadata changed", shared.ErrConflict)
		}
	}
	req.Locator, req.SourcePackage = item.Locator, publicSourcePackage(&item)
	return req, nil
}
