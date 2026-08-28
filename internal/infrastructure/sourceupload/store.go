package sourceupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const metadataLimit = int64(64 << 10)

var locatorPattern = regexp.MustCompile(`^engagement-sources/v1/[0-9a-f]{64}/[0-9a-f]{64}$`)

type Store struct {
	objects  ports.ObjectStore
	maxBytes int64
}

type manifest struct {
	Package   sourcepackage.Package `json:"package"`
	ObjectKey string                `json:"object_key"`
}

func NewStore(objects ports.ObjectStore, maxBytes int64) *Store {
	if maxBytes <= 0 || maxBytes > sourcepackage.MaxArchiveBytes {
		maxBytes = sourcepackage.MaxArchiveBytes
	}
	return &Store{objects: objects, maxBytes: maxBytes}
}

var _ ports.EngagementSourceStore = (*Store)(nil)

func (s *Store) Save(ctx context.Context, tenantID, engagementID shared.ID, filename, actor string, createdAt time.Time, size int64, sha256hex string, src io.Reader) (sourcepackage.Package, error) {
	if s == nil || s.objects == nil {
		return sourcepackage.Package{}, fmt.Errorf("%w: engagement source uploads are not configured", shared.ErrValidation)
	}
	filename = sourcepackage.BaseFilename(filename)
	item := sourcepackage.Package{
		TenantID: tenantID, EngagementID: engagementID, Filename: filename, Size: size,
		SHA256: strings.ToLower(strings.TrimSpace(sha256hex)), CreatedBy: strings.TrimSpace(actor), CreatedAt: createdAt.UTC(),
	}
	if err := item.Validate(); err != nil {
		return sourcepackage.Package{}, err
	}
	if size > s.maxBytes {
		return sourcepackage.Package{}, fmt.Errorf("%w: uploaded source exceeds %d bytes", shared.ErrValidation, s.maxBytes)
	}
	locator := locatorFor(tenantID, engagementID)
	if existing, err := s.getByLocator(ctx, locator); err == nil {
		if existing.SHA256 == item.SHA256 && existing.Size == item.Size && existing.Filename == item.Filename {
			return existing, nil
		}
		return sourcepackage.Package{}, fmt.Errorf("%w: engagement already has a different uploaded source", shared.ErrConflict)
	} else if !errors.Is(err, shared.ErrNotFound) {
		return sourcepackage.Package{}, err
	}

	archiveKey := locator + "/archive" + sourcepackage.ArchiveExtension(filename)
	hash := sha256.New()
	counter := &countingReader{reader: io.TeeReader(src, hash)}
	if err := s.objects.PutObject(ctx, archiveKey, counter, size); err != nil {
		return sourcepackage.Package{}, fmt.Errorf("store uploaded source: %w", err)
	}
	var trailing [1]byte
	trailingBytes, trailingErr := counter.Read(trailing[:])
	if counter.bytes != size || trailingBytes != 0 || (trailingErr != nil && !errors.Is(trailingErr, io.EOF)) || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		_ = s.objects.DeleteObject(context.WithoutCancel(ctx), archiveKey)
		return sourcepackage.Package{}, fmt.Errorf("%w: uploaded source content does not match its declared size or SHA-256", shared.ErrValidation)
	}
	item.Locator = locator
	data, err := json.Marshal(manifest{Package: item, ObjectKey: archiveKey})
	if err != nil {
		_ = s.objects.DeleteObject(context.WithoutCancel(ctx), archiveKey)
		return sourcepackage.Package{}, fmt.Errorf("marshal uploaded source metadata: %w", err)
	}
	if err := s.objects.PutObject(ctx, metadataKey(locator), bytes.NewReader(data), int64(len(data))); err != nil {
		_ = s.objects.DeleteObject(context.WithoutCancel(ctx), archiveKey)
		return sourcepackage.Package{}, fmt.Errorf("store uploaded source metadata: %w", err)
	}
	return item, nil
}

func (s *Store) Get(ctx context.Context, tenantID, engagementID shared.ID) (sourcepackage.Package, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return sourcepackage.Package{}, fmt.Errorf("%w: source package tenant and engagement are required", shared.ErrValidation)
	}
	item, err := s.getByLocator(ctx, locatorFor(tenantID, engagementID))
	if err != nil {
		return sourcepackage.Package{}, err
	}
	if item.TenantID != tenantID || item.EngagementID != engagementID {
		return sourcepackage.Package{}, fmt.Errorf("uploaded source ownership mismatch: %w", shared.ErrNotFound)
	}
	return item, nil
}

func (s *Store) Delete(ctx context.Context, tenantID, engagementID shared.ID) error {
	locator := locatorFor(tenantID, engagementID)
	stored, err := s.readManifest(ctx, locator)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return err
	}
	if err == nil {
		if deleteErr := s.objects.DeleteObject(ctx, stored.ObjectKey); deleteErr != nil {
			return deleteErr
		}
	}
	return s.objects.DeleteObject(ctx, metadataKey(locator))
}

func (s *Store) Materialize(ctx context.Context, locator string) (string, sourcepackage.Package, func() error, error) {
	stored, err := s.readManifest(ctx, locator)
	if err != nil {
		return "", sourcepackage.Package{}, nil, err
	}
	if stored.Package.Size > s.maxBytes {
		return "", sourcepackage.Package{}, nil, fmt.Errorf("%w: uploaded source exceeds %d bytes", shared.ErrValidation, s.maxBytes)
	}
	reader, err := s.objects.OpenObject(ctx, stored.ObjectKey)
	if err != nil {
		return "", sourcepackage.Package{}, nil, fmt.Errorf("open uploaded source: %w", err)
	}
	defer func() { _ = reader.Close() }()

	tmp, err := os.CreateTemp("", "synapse-upload-*"+sourcepackage.ArchiveExtension(stored.Package.Filename))
	if err != nil {
		return "", sourcepackage.Package{}, nil, fmt.Errorf("materialize uploaded source: %w", err)
	}
	path := tmp.Name()
	cleanup := func() error { return os.Remove(path) }
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(reader, stored.Package.Size+1))
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil || written != stored.Package.Size || hex.EncodeToString(hash.Sum(nil)) != stored.Package.SHA256 {
		_ = cleanup()
		if copyErr != nil {
			return "", sourcepackage.Package{}, nil, fmt.Errorf("materialize uploaded source: %w", copyErr)
		}
		if closeErr != nil {
			return "", sourcepackage.Package{}, nil, fmt.Errorf("materialize uploaded source: %w", closeErr)
		}
		return "", sourcepackage.Package{}, nil, fmt.Errorf("%w: uploaded source failed integrity verification", shared.ErrValidation)
	}
	return path, stored.Package, cleanup, nil
}

func (s *Store) getByLocator(ctx context.Context, locator string) (sourcepackage.Package, error) {
	stored, err := s.readManifest(ctx, locator)
	if err != nil {
		return sourcepackage.Package{}, err
	}
	return stored.Package, nil
}

func (s *Store) readManifest(ctx context.Context, locator string) (manifest, error) {
	if s == nil || s.objects == nil || !locatorPattern.MatchString(locator) {
		return manifest{}, fmt.Errorf("%w: uploaded source locator is invalid", shared.ErrValidation)
	}
	reader, err := s.objects.OpenObject(ctx, metadataKey(locator))
	if err != nil {
		return manifest{}, err
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(io.LimitReader(reader, metadataLimit+1))
	if err != nil {
		return manifest{}, fmt.Errorf("read uploaded source metadata: %w", err)
	}
	if int64(len(data)) > metadataLimit {
		return manifest{}, fmt.Errorf("%w: uploaded source metadata is oversized", shared.ErrValidation)
	}
	var stored manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return manifest{}, fmt.Errorf("decode uploaded source metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return manifest{}, fmt.Errorf("%w: uploaded source metadata has trailing content", shared.ErrValidation)
	}
	stored.Package.Locator = locator
	if err := stored.Package.Validate(); err != nil {
		return manifest{}, err
	}
	if locator != locatorFor(stored.Package.TenantID, stored.Package.EngagementID) {
		return manifest{}, fmt.Errorf("%w: uploaded source locator ownership is invalid", shared.ErrValidation)
	}
	expectedKey := locator + "/archive" + sourcepackage.ArchiveExtension(stored.Package.Filename)
	if stored.ObjectKey != expectedKey {
		return manifest{}, fmt.Errorf("%w: uploaded source object key is invalid", shared.ErrValidation)
	}
	return stored, nil
}

type countingReader struct {
	reader io.Reader
	bytes  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.bytes += int64(n)
	return n, err
}

func locatorFor(tenantID, engagementID shared.ID) string {
	tenantHash := sha256.Sum256([]byte(tenantID.String()))
	engagementHash := sha256.Sum256([]byte(engagementID.String()))
	return "engagement-sources/v1/" + hex.EncodeToString(tenantHash[:]) + "/" + hex.EncodeToString(engagementHash[:])
}

func metadataKey(locator string) string { return locator + "/metadata.json" }
