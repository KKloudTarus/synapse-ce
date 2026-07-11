package acquire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// readImageInfo recovers container-image metadata from a pulled OCI image layout
// (crane writes one to layoutDir). It reads the manifest + image config to build
// the ordered layer stack (diff_id + build command per non-empty layer) so the
// scan can attribute packages to layers and estimate the base image (Epic D).
//
// Best-effort: any malformed/missing file returns nil rather than failing the
// acquisition – layer attribution is an enhancement, not a scan precondition.
// It only reads files already on disk under layoutDir (no network, no exec).
func readImageInfo(layoutDir, ref string) *sbom.ImageInfo {
	manifest, ok := readManifest(layoutDir)
	if !ok || manifest.Config.Digest == "" {
		return nil
	}
	cfg, ok := readBlobJSON[ociConfig](layoutDir, manifest.Config.Digest)
	if !ok {
		return nil
	}
	info := &sbom.ImageInfo{
		// Redact any embedded registry credentials (user:pass@host): ImageInfo is stored in the
		// serialized ScanResult, so the reference must never carry a secret into persisted data.
		Reference:    redactCreds(strings.TrimSpace(ref)),
		Digest:       manifest.selfDigest, // the manifest digest (what `docker images --digests` shows)
		OS:           cfg.OS,
		Architecture: cfg.Architecture,
		Layers:       buildLayers(cfg),
	}
	return info
}

// buildLayers zips the image's rootfs.diff_ids (one per filesystem layer, in
// order) with the non-empty history entries (which carry the build command).
// Non-empty history entries map 1:1 to diff_ids in order; empty_layer entries
// (ENV/CMD/LABEL …) produce no filesystem layer and are skipped. If history is
// absent or inconsistent, layers are still listed from diff_ids alone.
func buildLayers(cfg ociConfig) []sbom.ImageLayer {
	diffIDs := cfg.RootFS.DiffIDs
	layers := make([]sbom.ImageLayer, 0, len(diffIDs))
	di := 0
	for _, h := range cfg.History {
		if h.EmptyLayer {
			continue // metadata-only history entry: no diff_id to pair
		}
		if di >= len(diffIDs) {
			break // more non-empty history than diff_ids – stop pairing, stay consistent
		}
		layers = append(layers, sbom.ImageLayer{
			Index:     di,
			DiffID:    diffIDs[di],
			CreatedBy: strings.TrimSpace(h.CreatedBy),
			Created:   strings.TrimSpace(h.Created),
		})
		di++
	}
	// Any diff_ids not covered by history (no/partial history): list them with no command.
	for ; di < len(diffIDs); di++ {
		layers = append(layers, sbom.ImageLayer{Index: di, DiffID: diffIDs[di]})
	}
	return layers
}

// --- OCI layout structures (minimal subset) ---

type ociIndex struct {
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Platform  struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	} `json:"manifests"`
}

type ociManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	// Layers are the filesystem layers in application order (each a tar, usually gzipped). Used to
	// materialize the assembled rootfs (extractOCIRootFS); readImageInfo itself does not read them. Only the
	// digest is needed (the layer compression is sniffed by magic, not trusted from the media type).
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
	selfDigest string // the manifest's own digest (from the index), not in the JSON
}

type ociConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	RootFS       struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

// readManifest reads index.json and follows the (single, linux/amd64-preferred)
// manifest descriptor to the image manifest blob.
func readManifest(layoutDir string) (ociManifest, bool) {
	idx, ok := readJSON[ociIndex](filepath.Join(layoutDir, "index.json"))
	if !ok || len(idx.Manifests) == 0 {
		return ociManifest{}, false
	}
	// Prefer a linux/amd64 image manifest (crane pulled that platform); else the first.
	pick := idx.Manifests[0]
	for _, m := range idx.Manifests {
		if m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
			pick = m
			break
		}
	}
	man, ok := readBlobJSON[ociManifest](layoutDir, pick.Digest)
	if !ok {
		return ociManifest{}, false
	}
	man.selfDigest = pick.Digest
	return man, true
}

// blobPath maps a "sha256:<hex>" digest to its on-disk path <layoutDir>/blobs/<algo>/<hex>, validating the
// digest is a bare algorithm:hex pair (no separators) so it cannot escape the blobs directory (no traversal).
func blobPath(layoutDir, digest string) (string, bool) {
	algo, hex, found := strings.Cut(digest, ":")
	if !found || algo == "" || hex == "" || strings.ContainsAny(hex, "/\\.") || strings.ContainsAny(algo, "/\\.") {
		return "", false
	}
	return filepath.Join(layoutDir, "blobs", algo, hex), true
}

// readBlobJSON reads + decodes the OCI blob addressed by a "sha256:<hex>" digest
// from <layoutDir>/blobs/sha256/<hex>. The digest is validated (see blobPath) so it
// cannot escape the blobs directory (no path traversal).
func readBlobJSON[T any](layoutDir, digest string) (T, bool) {
	var zero T
	p, ok := blobPath(layoutDir, digest)
	if !ok {
		return zero, false
	}
	return readJSON[T](p)
}

// readJSON reads + decodes a JSON file, bounded to a sane size. Best-effort: any
// error yields (zero, false). Image configs are small (KBs); cap defensively.
func readJSON[T any](path string) (T, bool) {
	var v T
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 8<<20 {
		return v, false
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return v, false
	}
	return v, true
}
