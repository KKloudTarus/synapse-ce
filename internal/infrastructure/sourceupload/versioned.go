package sourceupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var versionLocatorPattern = regexp.MustCompile(`^engagement-sources/v2/[0-9a-f]{64}/[0-9a-f]{64}/[0-9a-f]{32}$`)
var versionObjectPattern = regexp.MustCompile(`^engagement-sources/(v1/[0-9a-f]{64}/[0-9a-f]{64}|v2/[0-9a-f]{64}/[0-9a-f]{64}/[0-9a-f]{32})/archive\.(zip|tar|tar\.gz|tgz)$`)

var _ ports.EngagementSourceReuser = (*Store)(nil)
var _ ports.EngagementSourceVersionReader = (*Store)(nil)
var _ ports.EngagementSourceCompensator = (*Store)(nil)

func versionLocator(tenantID, engID, versionID shared.ID) string {
	return strings.Replace(locatorFor(tenantID, engID), "/v1/", "/v2/", 1) + "/" + versionID.String()
}

func validateStoredVersion(item sourcepackage.Package) error {
	if err := item.ValidateVersion(); err != nil {
		return err
	}
	if item.Locator != versionLocator(item.TenantID, item.EngagementID, item.VersionID) || !versionObjectPattern.MatchString(item.ObjectKey) {
		return fmt.Errorf("%w: source package storage identity is invalid", shared.ErrValidation)
	}
	tenantHash := sha256.Sum256([]byte(item.TenantID.String()))
	tenantPrefix := hex.EncodeToString(tenantHash[:]) + "/"
	if !strings.HasPrefix(item.ObjectKey, "engagement-sources/v1/"+tenantPrefix) && !strings.HasPrefix(item.ObjectKey, "engagement-sources/v2/"+tenantPrefix) {
		return fmt.Errorf("%w: source package object tenant is invalid", shared.ErrValidation)
	}
	archiveSuffix := "/archive" + sourcepackage.ArchiveExtension(item.Filename)
	if !strings.HasSuffix(item.ObjectKey, archiveSuffix) || item.ReusedFromVersionID.IsZero() && item.ObjectKey != item.Locator+archiveSuffix && item.ObjectKey != locatorFor(item.TenantID, item.EngagementID)+archiveSuffix {
		return fmt.Errorf("%w: source package object ownership is invalid", shared.ErrValidation)
	}
	return nil
}

func (s *Store) saveVersioned(ctx context.Context, tenantID, engID shared.ID, filename, actor string, at time.Time, size int64, digest string, src io.Reader) (sourcepackage.Package, error) {
	if s.objects == nil || src == nil {
		return sourcepackage.Package{}, fmt.Errorf("%w: source upload storage is unavailable", shared.ErrValidation)
	}
	item := sourcepackage.Package{TenantID: tenantID, EngagementID: engID, VersionID: idgen.RandomID{}.NewID(), Filename: sourcepackage.BaseFilename(filename), Size: size, SHA256: strings.ToLower(strings.TrimSpace(digest)), CreatedBy: strings.TrimSpace(actor), CreatedAt: at.UTC().Truncate(time.Microsecond), AssociatedBy: strings.TrimSpace(actor), AssociatedAt: at.UTC().Truncate(time.Microsecond)}
	item.Locator = versionLocator(tenantID, engID, item.VersionID)
	item.ObjectKey = item.Locator + "/archive" + sourcepackage.ArchiveExtension(item.Filename)
	if err := validateStoredVersion(item); err != nil {
		return sourcepackage.Package{}, err
	}
	if size > s.maxBytes {
		return sourcepackage.Package{}, fmt.Errorf("%w: uploaded source exceeds configured limit", shared.ErrValidation)
	}
	if old, err := s.Get(ctx, tenantID, engID); err == nil {
		if samePackageContent(old, item) {
			return old, nil
		}
		return sourcepackage.Package{}, shared.ErrConflict
	} else if !errors.Is(err, shared.ErrNotFound) {
		return sourcepackage.Package{}, err
	}
	hash := sha256.New()
	counter := &countingReader{reader: io.TeeReader(src, hash)}
	if err := s.objects.PutObject(ctx, item.ObjectKey, counter, size); err != nil {
		return item, fmt.Errorf("store uploaded source: %w", err)
	}
	var trailing [1]byte
	n, err := counter.Read(trailing[:])
	if counter.bytes != size || n != 0 || (err != nil && !errors.Is(err, io.EOF)) || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		_ = s.objects.DeleteObject(context.WithoutCancel(ctx), item.ObjectKey)
		return sourcepackage.Package{}, fmt.Errorf("%w: uploaded source content does not match size or SHA-256", shared.ErrValidation)
	}
	stored, _, err := s.repository.Create(ctx, item)
	if err != nil {
		// A failed COMMIT can still be durable. Only discard this unique staging
		// object when a different immutable binding demonstrably won the race.
		if errors.Is(err, shared.ErrConflict) && !stored.VersionID.IsZero() && stored.VersionID != item.VersionID {
			_ = s.objects.DeleteObject(context.WithoutCancel(ctx), item.ObjectKey)
			if samePackageContent(stored, item) {
				return stored, nil
			}
		}
		return item, fmt.Errorf("persist uploaded source metadata: %w", err)
	}
	return stored, nil
}

// DiscardUnpublished is only for compensation after the enclosing transaction.
// A version owns one unguessable object key; reuse cannot create a new reference
// once its original binding is absent. Unknown transaction outcomes retain bytes.
func (s *Store) DiscardUnpublished(ctx context.Context, item sourcepackage.Package) error {
	if s == nil || s.repository == nil || s.objects == nil {
		return shared.ErrValidation
	}
	if item.VersionID.IsZero() || !item.ReusedFromVersionID.IsZero() {
		return nil
	}
	if err := validateStoredVersion(item); err != nil {
		return err
	}
	if item.ObjectKey != item.Locator+"/archive"+sourcepackage.ArchiveExtension(item.Filename) {
		return nil // Verified legacy promotion does not own the original v1 object.
	}
	unreferenced, err := s.repository.ObjectUnreferenced(ctx, item.TenantID, item.ObjectKey)
	if err != nil || !unreferenced {
		return err
	}
	return s.objects.DeleteObject(ctx, item.ObjectKey)
}

func samePackageContent(left, right sourcepackage.Package) bool {
	return left.TenantID == right.TenantID && left.EngagementID == right.EngagementID && left.Filename == right.Filename && left.Size == right.Size && left.SHA256 == right.SHA256
}

func (s *Store) getVersioned(ctx context.Context, tenantID, engID shared.ID) (sourcepackage.Package, error) {
	item, err := s.repository.Get(ctx, tenantID, engID)
	if err == nil {
		return item, validateStoredVersion(item)
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return sourcepackage.Package{}, err
	}
	// Upgrade only a verifiable v1 archive. A digest in engagement scope alone
	// cannot restore missing in-memory bytes or prove legacy upload attribution.
	legacy, err := s.readManifest(ctx, locatorFor(tenantID, engID))
	if err != nil {
		return sourcepackage.Package{}, err
	}
	if err := s.verifyObject(ctx, legacy.Package, legacy.ObjectKey); err != nil {
		return sourcepackage.Package{}, err
	}
	item = legacy.Package
	item.VersionID = idgen.RandomID{}.NewID()
	item.CreatedAt = item.CreatedAt.UTC().Truncate(time.Microsecond)
	item.AssociatedBy, item.AssociatedAt = item.CreatedBy, item.CreatedAt
	item.Locator = versionLocator(tenantID, engID, item.VersionID)
	item.ObjectKey = legacy.ObjectKey
	stored, _, err := s.repository.Create(ctx, item)
	if errors.Is(err, shared.ErrConflict) {
		if winner, getErr := s.repository.Get(ctx, tenantID, engID); getErr == nil && samePackageContent(winner, item) {
			return winner, nil
		}
	}
	return stored, err
}

func (s *Store) GetByVersion(ctx context.Context, tenantID, engID, versionID shared.ID) (sourcepackage.Package, error) {
	item, err := s.Get(ctx, tenantID, engID)
	if err == nil && (versionID.IsZero() || item.VersionID != versionID) {
		return sourcepackage.Package{}, shared.ErrNotFound
	}
	return item, err
}

func (s *Store) Reuse(ctx context.Context, tenantID, parentEngID, childEngID, expectedVersionID shared.ID, actor string, at time.Time) (sourcepackage.Package, error) {
	if s == nil || s.repository == nil || tenantID.IsZero() || parentEngID.IsZero() || childEngID.IsZero() || parentEngID == childEngID || expectedVersionID.IsZero() {
		return sourcepackage.Package{}, fmt.Errorf("%w: source reuse ownership and expected version are required", shared.ErrValidation)
	}
	parent, err := s.GetByVersion(ctx, tenantID, parentEngID, expectedVersionID)
	if err != nil {
		return sourcepackage.Package{}, err
	}
	if err := s.verifyObject(ctx, parent, parent.ObjectKey); err != nil {
		return sourcepackage.Package{}, err
	}
	if existing, err := s.repository.Get(ctx, tenantID, childEngID); err == nil {
		if existing.ReusedFromVersionID == parent.VersionID {
			return existing, nil
		}
		return sourcepackage.Package{}, shared.ErrConflict
	} else if !errors.Is(err, shared.ErrNotFound) {
		return sourcepackage.Package{}, err
	}
	child := parent
	child.EngagementID, child.VersionID = childEngID, idgen.RandomID{}.NewID()
	child.ReusedFromVersionID = parent.VersionID
	child.AssociatedBy, child.AssociatedAt = strings.TrimSpace(actor), at.UTC().Truncate(time.Microsecond)
	child.Locator = versionLocator(tenantID, childEngID, child.VersionID)
	if err := validateStoredVersion(child); err != nil {
		return sourcepackage.Package{}, err
	}
	stored, _, err := s.repository.Create(ctx, child)
	if errors.Is(err, shared.ErrConflict) && stored.ReusedFromVersionID == parent.VersionID {
		return stored, nil
	}
	return stored, err
}

func (s *Store) verifyObject(ctx context.Context, item sourcepackage.Package, key string) error {
	reader, err := s.objects.OpenObject(ctx, key)
	if err != nil {
		return fmt.Errorf("uploaded source archive is unavailable: %w", err)
	}
	defer func() { _ = reader.Close() }()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(reader, item.Size+1))
	if err != nil {
		return fmt.Errorf("verify source archive: %w", err)
	}
	if n != item.Size || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		return fmt.Errorf("%w: uploaded source failed integrity verification", shared.ErrValidation)
	}
	return nil
}
