package scabench

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

const (
	// TrustedInputBindingSpecSchemaVersion describes the catalog-to-materialized-input mapping.
	TrustedInputBindingSpecSchemaVersion = "synapse-sca-trusted-input-binding-spec-v1"
	// TrustedInputArchiveSchemaVersion describes a materialized trusted-input archive.
	TrustedInputArchiveSchemaVersion = "synapse-sca-trusted-input-archive-v1"

	// MaxTrustedInputArchiveEntries is well above the current scanner database layouts while bounding
	// archive-manifest processing if a prepared root is accidentally pointed at a broader filesystem.
	MaxTrustedInputArchiveEntries = 10_000
	// MaxTrustedInputArchiveDepth permits the current database and capability-source layouts without
	// accepting arbitrarily deep paths that complicate safe restoration.
	MaxTrustedInputArchiveDepth = 32
	// MaxTrustedInputArchiveFileBytes permits the current database objects while keeping a corrupt or
	// misdirected materialization from consuming unbounded archive storage.
	MaxTrustedInputArchiveFileBytes int64 = 3 << 30
	// MaxTrustedInputArchiveBytes bounds the complete prepared benchmark input set.
	MaxTrustedInputArchiveBytes int64 = 8 << 30
	// MaxTrustedInputArchiveManifestBytes bounds each JSON archive or binding-spec document.
	MaxTrustedInputArchiveManifestBytes int64 = 1 << 20
)

// TrustedInputPinKind describes how a catalog pin is materialized under a trusted input root.
type TrustedInputPinKind string

const (
	TrustedInputPinFile TrustedInputPinKind = "file"
	TrustedInputPinTree TrustedInputPinKind = "tree"
)

// TrustedInputInventoryKind describes an archive inventory member.
type TrustedInputInventoryKind string

const (
	TrustedInputInventoryDirectory TrustedInputInventoryKind = "directory"
	TrustedInputInventoryFile      TrustedInputInventoryKind = "file"
)

// TrustedInputPinBinding binds one origin-bearing catalog pin to exactly one materialized input.
// PinDigest is the catalog pin identity; ObjectDigest in the inventory is deliberately distinct.
type TrustedInputPinBinding struct {
	Reference string              `json:"reference"`
	Locator   string              `json:"locator"`
	Kind      TrustedInputPinKind `json:"kind"`
	PinDigest string              `json:"pin_digest"`
}

// TrustedInputBindingSpec is maintained with a frozen corpus. It identifies where every upstream
// origin pin appears after preparation without redefining ArtifactPin or raw-origin archive semantics.
type TrustedInputBindingSpec struct {
	SchemaVersion   string                   `json:"schema_version"`
	CatalogRevision string                   `json:"catalog_revision"`
	CatalogDigest   string                   `json:"catalog_digest"`
	Bindings        []TrustedInputPinBinding `json:"bindings"`
}

// TrustedInputInventoryEntry captures one directory or regular file below a materialized root.
// Directories record only their safe permission bits; files additionally carry their stored object
// identity and exact length.
type TrustedInputInventoryEntry struct {
	Locator      string                    `json:"locator"`
	Kind         TrustedInputInventoryKind `json:"kind"`
	ObjectDigest string                    `json:"object_digest,omitempty"`
	Bytes        int64                     `json:"bytes,omitempty"`
	Mode         uint32                    `json:"mode"`
}

// TrustedInputArchive is a separately versioned archive of an already-prepared trusted input root.
// RootManifestDigest covers the canonical archive identity but never changes a catalog pin digest.
type TrustedInputArchive struct {
	SchemaVersion      string                       `json:"schema_version"`
	CatalogRevision    string                       `json:"catalog_revision"`
	CatalogDigest      string                       `json:"catalog_digest"`
	BindingSpecVersion string                       `json:"binding_spec_version"`
	Bindings           []TrustedInputPinBinding     `json:"bindings"`
	Inventory          []TrustedInputInventoryEntry `json:"inventory"`
	RootManifestDigest string                       `json:"root_manifest_digest"`
}

// DecodeTrustedInputBindingSpec strictly decodes a bounded binding specification. Full catalog
// coverage is checked by TrustedInputBindingSpec.Validate because it needs the frozen catalog.
func DecodeTrustedInputBindingSpec(reader io.Reader) (TrustedInputBindingSpec, error) {
	var spec TrustedInputBindingSpec
	if err := decodeTrustedInputArchiveDocument(reader, &spec); err != nil {
		return TrustedInputBindingSpec{}, fmt.Errorf("decode trusted input binding spec: %w", err)
	}
	if err := spec.validateShape(); err != nil {
		return TrustedInputBindingSpec{}, err
	}
	return spec, nil
}

// DecodeTrustedInputArchive strictly decodes and validates a bounded materialized-input archive.
func DecodeTrustedInputArchive(reader io.Reader) (TrustedInputArchive, error) {
	var archive TrustedInputArchive
	if err := decodeTrustedInputArchiveDocument(reader, &archive); err != nil {
		return TrustedInputArchive{}, fmt.Errorf("decode trusted input archive: %w", err)
	}
	if err := archive.Validate(); err != nil {
		return TrustedInputArchive{}, err
	}
	return archive, nil
}

// EncodeTrustedInputArchive validates and bounds a manifest before it leaves a collector.
func EncodeTrustedInputArchive(archive TrustedInputArchive) ([]byte, error) {
	if err := archive.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(archive)
	if err != nil {
		return nil, fmt.Errorf("encode trusted input archive: %w", err)
	}
	if int64(len(data)) > MaxTrustedInputArchiveManifestBytes {
		return nil, fmt.Errorf("trusted input archive document exceeds %d bytes", MaxTrustedInputArchiveManifestBytes)
	}
	return data, nil
}

func decodeTrustedInputArchiveDocument(reader io.Reader, destination any) error {
	if reader == nil {
		return errors.New("trusted input archive document is required")
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxTrustedInputArchiveManifestBytes+1))
	if err != nil {
		return fmt.Errorf("read trusted input archive document: %w", err)
	}
	if int64(len(data)) > MaxTrustedInputArchiveManifestBytes {
		return fmt.Errorf("trusted input archive document exceeds %d bytes", MaxTrustedInputArchiveManifestBytes)
	}
	return strictDecode(bytes.NewReader(data), destination)
}

// Validate confirms that the specification covers, and only covers, every origin-bearing catalog pin.
func (spec TrustedInputBindingSpec) Validate(catalog Catalog) error {
	if err := catalog.Validate(); err != nil {
		return err
	}
	if err := spec.validateShape(); err != nil {
		return err
	}
	if spec.CatalogRevision != catalog.Revision {
		return fmt.Errorf("trusted input binding spec revision %q does not match catalog revision %q", spec.CatalogRevision, catalog.Revision)
	}
	catalogDigest, err := DigestCatalog(catalog)
	if err != nil {
		return fmt.Errorf("digest catalog for trusted input binding spec: %w", err)
	}
	if spec.CatalogDigest != catalogDigest {
		return fmt.Errorf("trusted input binding spec catalog digest %s does not match catalog digest %s", spec.CatalogDigest, catalogDigest)
	}

	originPins := make(map[string]ArtifactPin, len(catalog.Pins))
	for _, pin := range catalog.Pins {
		if strings.TrimSpace(pin.Origin) != "" {
			originPins[pin.Reference] = pin
		}
	}
	seenReferences := make(map[string]struct{}, len(spec.Bindings))
	seenLocators := make(map[string]struct{}, len(spec.Bindings))
	for i, binding := range spec.Bindings {
		if err := validateTrustedInputBinding(binding); err != nil {
			return fmt.Errorf("trusted input binding %d: %w", i, err)
		}
		if _, exists := seenReferences[binding.Reference]; exists {
			return fmt.Errorf("trusted input binding reference %q is duplicated", binding.Reference)
		}
		seenReferences[binding.Reference] = struct{}{}
		if _, exists := seenLocators[binding.Locator]; exists {
			return fmt.Errorf("trusted input binding locator %q is duplicated", binding.Locator)
		}
		seenLocators[binding.Locator] = struct{}{}
		pin, exists := originPins[binding.Reference]
		if !exists {
			return fmt.Errorf("trusted input binding %q is orphaned from the catalog's origin pins", binding.Reference)
		}
		if binding.PinDigest != pin.Digest {
			return fmt.Errorf("trusted input binding %q pin digest %s does not match catalog pin digest %s", binding.Reference, binding.PinDigest, pin.Digest)
		}
	}
	missing := make([]string, 0)
	for reference := range originPins {
		if _, exists := seenReferences[reference]; !exists {
			missing = append(missing, reference)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("trusted input binding spec is missing %d origin pin binding(s): %s", len(missing), strings.Join(missing, ", "))
	}
	return nil
}

func (spec TrustedInputBindingSpec) validateShape() error {
	if spec.SchemaVersion != TrustedInputBindingSpecSchemaVersion {
		return fmt.Errorf("unsupported trusted input binding spec schema %q", spec.SchemaVersion)
	}
	if strings.TrimSpace(spec.CatalogRevision) == "" {
		return errors.New("trusted input binding spec catalog revision is required")
	}
	if !validSHA256Digest(spec.CatalogDigest) {
		return errors.New("trusted input binding spec catalog digest must be an immutable sha256 digest")
	}
	if len(spec.Bindings) == 0 {
		return errors.New("trusted input binding spec bindings are required")
	}
	if len(spec.Bindings) > MaxTrustedInputArchiveEntries {
		return fmt.Errorf("trusted input binding spec exceeds %d bindings", MaxTrustedInputArchiveEntries)
	}
	for i := 1; i < len(spec.Bindings); i++ {
		if spec.Bindings[i-1].Reference >= spec.Bindings[i].Reference {
			return errors.New("trusted input binding spec bindings must be sorted by reference")
		}
	}
	return nil
}

// NewTrustedInputArchive creates the canonical archive identity after a collector has enumerated a
// prepared input root. The collector remains responsible for filesystem verification and CAS storage.
func NewTrustedInputArchive(catalog Catalog, spec TrustedInputBindingSpec, inventory []TrustedInputInventoryEntry) (TrustedInputArchive, error) {
	if err := spec.Validate(catalog); err != nil {
		return TrustedInputArchive{}, err
	}
	archive := TrustedInputArchive{
		SchemaVersion:      TrustedInputArchiveSchemaVersion,
		CatalogRevision:    catalog.Revision,
		CatalogDigest:      spec.CatalogDigest,
		BindingSpecVersion: spec.SchemaVersion,
		Bindings:           append([]TrustedInputPinBinding(nil), spec.Bindings...),
		Inventory:          append([]TrustedInputInventoryEntry(nil), inventory...),
	}
	if err := archive.validateShape(); err != nil {
		return TrustedInputArchive{}, err
	}
	rootDigest, err := DigestTrustedInputArchiveRootManifest(archive)
	if err != nil {
		return TrustedInputArchive{}, err
	}
	archive.RootManifestDigest = rootDigest
	if err := archive.Validate(); err != nil {
		return TrustedInputArchive{}, err
	}
	if _, err := EncodeTrustedInputArchive(archive); err != nil {
		return TrustedInputArchive{}, err
	}
	return archive, nil
}

// Validate checks the archive's self-contained identity and inventory integrity.
func (archive TrustedInputArchive) Validate() error {
	if err := archive.validateShape(); err != nil {
		return err
	}
	if !validSHA256Digest(archive.RootManifestDigest) {
		return errors.New("trusted input archive root manifest digest must be an immutable sha256 digest")
	}
	rootDigest, err := DigestTrustedInputArchiveRootManifest(archive)
	if err != nil {
		return err
	}
	if archive.RootManifestDigest != rootDigest {
		return fmt.Errorf("trusted input archive root manifest digest %s does not match canonical digest %s", archive.RootManifestDigest, rootDigest)
	}
	return nil
}

// ValidateForCatalog verifies that an archive and its externally supplied binding specification name
// the same frozen catalog and the same explicit pin-to-locator bindings.
func (archive TrustedInputArchive) ValidateForCatalog(catalog Catalog, spec TrustedInputBindingSpec) error {
	if err := spec.Validate(catalog); err != nil {
		return err
	}
	if err := archive.Validate(); err != nil {
		return err
	}
	if archive.CatalogRevision != spec.CatalogRevision || archive.CatalogDigest != spec.CatalogDigest {
		return errors.New("trusted input archive does not bind the supplied catalog identity")
	}
	if archive.BindingSpecVersion != spec.SchemaVersion {
		return fmt.Errorf("trusted input archive binding spec version %q does not match supplied version %q", archive.BindingSpecVersion, spec.SchemaVersion)
	}
	if len(archive.Bindings) != len(spec.Bindings) {
		return errors.New("trusted input archive bindings do not match the supplied binding spec")
	}
	for i := range spec.Bindings {
		if archive.Bindings[i] != spec.Bindings[i] {
			return errors.New("trusted input archive bindings do not match the supplied binding spec")
		}
	}
	return nil
}

func (archive TrustedInputArchive) validateShape() error {
	if archive.SchemaVersion != TrustedInputArchiveSchemaVersion {
		return fmt.Errorf("unsupported trusted input archive schema %q", archive.SchemaVersion)
	}
	if strings.TrimSpace(archive.CatalogRevision) == "" {
		return errors.New("trusted input archive catalog revision is required")
	}
	if !validSHA256Digest(archive.CatalogDigest) {
		return errors.New("trusted input archive catalog digest must be an immutable sha256 digest")
	}
	if archive.BindingSpecVersion != TrustedInputBindingSpecSchemaVersion {
		return fmt.Errorf("unsupported trusted input archive binding spec version %q", archive.BindingSpecVersion)
	}
	if len(archive.Bindings) == 0 {
		return errors.New("trusted input archive bindings are required")
	}
	if len(archive.Inventory) == 0 {
		return errors.New("trusted input archive inventory is required")
	}
	if len(archive.Bindings) > MaxTrustedInputArchiveEntries || len(archive.Inventory) > MaxTrustedInputArchiveEntries {
		return fmt.Errorf("trusted input archive exceeds %d inventory members", MaxTrustedInputArchiveEntries)
	}

	entries := make(map[string]TrustedInputInventoryEntry, len(archive.Inventory))
	var totalBytes int64
	for i, entry := range archive.Inventory {
		if err := validateTrustedInputInventoryEntry(entry); err != nil {
			return fmt.Errorf("trusted input archive inventory entry %d: %w", i, err)
		}
		if i > 0 && archive.Inventory[i-1].Locator >= entry.Locator {
			return errors.New("trusted input archive inventory must be sorted by locator")
		}
		if _, exists := entries[entry.Locator]; exists {
			return fmt.Errorf("trusted input archive inventory locator %q is duplicated", entry.Locator)
		}
		entries[entry.Locator] = entry
		if entry.Kind == TrustedInputInventoryFile {
			if entry.Bytes > MaxTrustedInputArchiveBytes-totalBytes {
				return fmt.Errorf("trusted input archive inventory exceeds %d bytes", MaxTrustedInputArchiveBytes)
			}
			totalBytes += entry.Bytes
		}
	}
	for _, entry := range archive.Inventory {
		for parent := trustedInputParentLocator(entry.Locator); parent != ""; parent = trustedInputParentLocator(parent) {
			parentEntry, exists := entries[parent]
			if !exists || parentEntry.Kind != TrustedInputInventoryDirectory {
				return fmt.Errorf("trusted input archive directory %q required by %q is absent or not a directory", parent, entry.Locator)
			}
		}
	}

	seenReferences := make(map[string]struct{}, len(archive.Bindings))
	seenLocators := make(map[string]struct{}, len(archive.Bindings))
	for i, binding := range archive.Bindings {
		if err := validateTrustedInputBinding(binding); err != nil {
			return fmt.Errorf("trusted input archive binding %d: %w", i, err)
		}
		if i > 0 && archive.Bindings[i-1].Reference >= binding.Reference {
			return errors.New("trusted input archive bindings must be sorted by reference")
		}
		if _, exists := seenReferences[binding.Reference]; exists {
			return fmt.Errorf("trusted input archive binding reference %q is duplicated", binding.Reference)
		}
		seenReferences[binding.Reference] = struct{}{}
		if _, exists := seenLocators[binding.Locator]; exists {
			return fmt.Errorf("trusted input archive binding locator %q is duplicated", binding.Locator)
		}
		seenLocators[binding.Locator] = struct{}{}
		entry, exists := entries[binding.Locator]
		if !exists {
			return fmt.Errorf("trusted input archive binding %q locator %q is absent from inventory", binding.Reference, binding.Locator)
		}
		if (binding.Kind == TrustedInputPinFile && entry.Kind != TrustedInputInventoryFile) || (binding.Kind == TrustedInputPinTree && entry.Kind != TrustedInputInventoryDirectory) {
			return fmt.Errorf("trusted input archive binding %q kind does not match inventory locator %q", binding.Reference, binding.Locator)
		}
	}
	return nil
}

// DigestTrustedInputArchiveRootManifest calculates the canonical archive identity excluding the digest
// field itself. It is intentionally separate from catalog pin digests and blob-object digests.
func DigestTrustedInputArchiveRootManifest(archive TrustedInputArchive) (string, error) {
	if err := archive.validateShape(); err != nil {
		return "", err
	}
	manifest := struct {
		SchemaVersion      string                       `json:"schema_version"`
		CatalogRevision    string                       `json:"catalog_revision"`
		CatalogDigest      string                       `json:"catalog_digest"`
		BindingSpecVersion string                       `json:"binding_spec_version"`
		Bindings           []TrustedInputPinBinding     `json:"bindings"`
		Inventory          []TrustedInputInventoryEntry `json:"inventory"`
	}{
		SchemaVersion:      archive.SchemaVersion,
		CatalogRevision:    archive.CatalogRevision,
		CatalogDigest:      archive.CatalogDigest,
		BindingSpecVersion: archive.BindingSpecVersion,
		Bindings:           archive.Bindings,
		Inventory:          archive.Inventory,
	}
	encoded, err := CanonicalJSON(manifest)
	if err != nil {
		return "", fmt.Errorf("encode trusted input root manifest: %w", err)
	}
	return SHA256Digest(encoded), nil
}

func validateTrustedInputBinding(binding TrustedInputPinBinding) error {
	if strings.TrimSpace(binding.Reference) == "" || containsControlCharacter(binding.Reference) {
		return errors.New("reference is required and must not contain control characters")
	}
	if !validTrustedInputLocator(binding.Locator) {
		return fmt.Errorf("locator %q must be a safe root-relative path", binding.Locator)
	}
	if binding.Kind != TrustedInputPinFile && binding.Kind != TrustedInputPinTree {
		return fmt.Errorf("kind %q must be file or tree", binding.Kind)
	}
	if !validSHA256Digest(binding.PinDigest) {
		return errors.New("pin digest must be an immutable sha256 digest")
	}
	return nil
}

func validateTrustedInputInventoryEntry(entry TrustedInputInventoryEntry) error {
	if !validTrustedInputLocator(entry.Locator) {
		return fmt.Errorf("locator %q must be a safe root-relative path", entry.Locator)
	}
	if trustedInputLocatorDepth(entry.Locator) > MaxTrustedInputArchiveDepth {
		return fmt.Errorf("locator %q exceeds maximum depth %d", entry.Locator, MaxTrustedInputArchiveDepth)
	}
	if !validTrustedInputMode(entry.Mode) {
		return fmt.Errorf("locator %q has unsafe mode %o", entry.Locator, entry.Mode)
	}
	switch entry.Kind {
	case TrustedInputInventoryDirectory:
		if entry.ObjectDigest != "" || entry.Bytes != 0 {
			return fmt.Errorf("directory locator %q must not carry an object digest or byte length", entry.Locator)
		}
	case TrustedInputInventoryFile:
		if !validSHA256Digest(entry.ObjectDigest) {
			return fmt.Errorf("file locator %q object digest must be an immutable sha256 digest", entry.Locator)
		}
		if entry.Bytes < 0 || entry.Bytes > MaxTrustedInputArchiveFileBytes {
			return fmt.Errorf("file locator %q byte length must be between zero and %d", entry.Locator, MaxTrustedInputArchiveFileBytes)
		}
	default:
		return fmt.Errorf("locator %q has unsupported inventory kind %q", entry.Locator, entry.Kind)
	}
	return nil
}

func validTrustedInputLocator(locator string) bool {
	if locator == "" || len(locator) > 1024 || strings.HasPrefix(locator, "/") || strings.Contains(locator, "\\") || containsControlCharacter(locator) {
		return false
	}
	if path.Clean(locator) != locator {
		return false
	}
	for _, part := range strings.Split(locator, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validTrustedInputMode(mode uint32) bool {
	return mode&^uint32(0o777) == 0
}

func trustedInputLocatorDepth(locator string) int {
	return strings.Count(locator, "/") + 1
}

func trustedInputParentLocator(locator string) string {
	parent := path.Dir(locator)
	if parent == "." {
		return ""
	}
	return parent
}
