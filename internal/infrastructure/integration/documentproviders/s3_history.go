package documentproviders

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"golang.org/x/sync/errgroup"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Governed commands serialize a publication's writes. The lower admission limit
// also reserves one current-object budget for writes already racing a preflight.
// Reads of live objects never depend on the history count.
func (a *s3Adapter) checkWriteHistory(ctx context.Context, marker string) error {
	versions, err := a.allVersions(ctx, marker)
	if err != nil {
		return err
	}
	if len(versions) >= s3WriteHistoryLimit {
		return docError(http.StatusOK, "publication_history_full", false)
	}
	return nil
}

func (a *s3Adapter) allVersions(ctx context.Context, marker string) ([]s3Object, error) {
	prefix := a.publicationPrefix(marker)
	versions := make([]s3Object, 0, s3MaxObjects)
	for item := range a.client.ListObjectsIter(ctx, a.bucket, minio.ListObjectsOptions{
		Prefix: prefix, Recursive: true, WithVersions: true, MaxKeys: s3MaxObjects,
	}) {
		if item.Err != nil {
			return nil, s3Err(item.Err, false)
		}
		if len(versions) >= s3MaxHistoryVersions {
			return nil, docError(http.StatusOK, "publication_history_too_large", false)
		}
		if item.VersionID == "" {
			return nil, docError(http.StatusOK, "versioning_required", false)
		}
		versions = append(versions, s3Object{
			key: item.Key, versionID: item.VersionID, deleteMarker: item.IsDeleteMarker,
			latest: item.IsLatest,
		})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return versions, nil
}

// verifyPurgeSnapshot proves every data version, including versions hidden by
// delete markers, before the first deletion. Delete markers have no object
// metadata and are removed only after the verified data versions they hide.
func (a *s3Adapter) verifyPurgeSnapshot(ctx context.Context, marker string, versions []s3Object) error {
	locked := false
	state, _, _, _, err := a.client.GetObjectLockConfig(ctx, a.bucket)
	if err != nil {
		switch minio.ToErrorResponse(err).Code {
		case "ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration":
		default:
			return s3Err(err, false)
		}
	} else if state != "Enabled" {
		return docError(http.StatusOK, "object_lock_unverifiable", false)
	} else {
		locked = true
	}
	// Bound read-only proof work below the transport's eight-connection limit.
	// Every proof finishes before a delete can be dispatched.
	proofs, proofCtx := errgroup.WithContext(ctx)
	proofs.SetLimit(4)
	shells := make([]bool, len(versions))
	for i, version := range versions {
		proofs.Go(func() error {
			shell, err := a.verifyPurgeVersion(proofCtx, marker, version, locked)
			shells[i] = shell
			return err
		})
	}
	if err := proofs.Wait(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, shell := range shells {
		if shell {
			return nil
		}
	}
	return restrictionLostError(http.StatusOK, "remote_identity_changed")
}

func (a *s3Adapter) verifyPurgeVersion(ctx context.Context, marker string, version s3Object, locked bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	name, inside := strings.CutPrefix(version.key, a.publicationPrefix(marker))
	if !inside || name == "" || strings.Contains(name, "/") ||
		(name != s3ShellName && name != s3BodyName && !validAttachmentName(name)) {
		return false, docError(http.StatusOK, "unmanaged_child", false)
	}
	if version.deleteMarker {
		return false, nil
	}
	stat, err := a.client.StatObject(ctx, a.bucket, version.key, minio.StatObjectOptions{VersionID: version.versionID})
	if err != nil {
		return false, s3Err(err, false)
	}
	stamp := s3Marker(stat.UserMetadata)
	if stamp == "" {
		return false, docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	if stat.VersionID != version.versionID || stamp != marker {
		return false, docError(http.StatusOK, "unmanaged_child", false)
	}
	shell := name == s3ShellName
	if shell && stat.Size != 0 {
		return false, restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	if locked {
		if err := a.verifyVersionUnlocked(ctx, version); err != nil {
			return false, err
		}
	}
	return shell, nil
}

func s3LockAbsent(err error) bool {
	switch minio.ToErrorResponse(err).Code {
	case "NoSuchObjectLockConfiguration", "ObjectLockConfigurationNotFoundError", "NoSuchObjectLockRetention":
		return true
	}
	return false
}

func (a *s3Adapter) verifyVersionUnlocked(ctx context.Context, version s3Object) error {
	hold, err := a.client.GetObjectLegalHold(ctx, a.bucket, version.key, minio.GetObjectLegalHoldOptions{VersionID: version.versionID})
	if err != nil && !s3LockAbsent(err) {
		return s3Err(err, false)
	}
	if err == nil {
		if hold == nil || (*hold != minio.LegalHoldDisabled && *hold != minio.LegalHoldEnabled) {
			return docError(http.StatusOK, "object_lock_unverifiable", false)
		}
		if *hold == minio.LegalHoldEnabled {
			return docError(http.StatusOK, "object_lock_retained", false)
		}
	}
	mode, until, err := a.client.GetObjectRetention(ctx, a.bucket, version.key, version.versionID)
	if err != nil && !s3LockAbsent(err) {
		return s3Err(err, false)
	}
	if err == nil {
		if mode == nil || until == nil || (*mode != minio.Governance && *mode != minio.Compliance) {
			return docError(http.StatusOK, "object_lock_unverifiable", false)
		}
		if until.After(time.Now().UTC()) {
			return docError(http.StatusOK, "object_lock_retained", false)
		}
	}
	return nil
}

// PurgeDocument deletes only an inspected snapshot. Concurrent additions are
// left untouched and make the final confirmation ambiguous. The neutral shell
// is kept until last so an interrupted purge retains its ownership anchor.
func (a *s3Adapter) PurgeDocument(ctx context.Context, page string, guard func(context.Context) error) error {
	if !validMarker(page) || guard == nil {
		return shared.ErrValidation
	}
	versions, err := a.allVersions(ctx, page)
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return nil
	}
	if err = a.verifyPurgeSnapshot(ctx, page, versions); err != nil {
		return err
	}
	weight := func(v s3Object) int {
		if strings.TrimPrefix(v.key, a.publicationPrefix(page)) == s3ShellName {
			return 3
		}
		if v.deleteMarker {
			return 2
		}
		if v.latest {
			return 1
		}
		return 0
	}
	sort.SliceStable(versions, func(i, j int) bool { return weight(versions[i]) < weight(versions[j]) })
	dispatched := false
	for _, version := range versions {
		if err = ctx.Err(); err == nil {
			err = guard(ctx)
		}
		if err != nil {
			if dispatched {
				return partialEffectAmbiguity(err, "purge_incomplete")
			}
			return err
		}
		dispatched = true
		if err = a.client.RemoveObject(ctx, a.bucket, version.key, minio.RemoveObjectOptions{VersionID: version.versionID}); err != nil {
			return partialEffectAmbiguity(s3Err(err, true), "purge_incomplete")
		}
	}
	remaining, err := a.allVersions(ctx, page)
	if err != nil {
		return partialEffectAmbiguity(err, "purge_incomplete")
	}
	if len(remaining) != 0 {
		return partialEffectAmbiguity(docError(http.StatusOK, "purge_incomplete", true), "purge_incomplete")
	}
	return nil
}
