package scabench

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ArchivedPin records that a catalog pin's exact bytes were preserved, not merely digested.
//
// ArtifactPin proves two captures used the same bytes and says where those bytes came from. It
// cannot prove the bytes are still obtainable. Vendors republish these feeds in place: Red Hat
// regenerates a CSAF VEX document under the same CVE filename, and the SUSE OVAL, Debian OVAL, and
// OSV snapshots change size between fetches of the same advertised build. Once a document is
// regenerated the originally pinned bytes are gone from the origin, so a later capture on fresh
// infrastructure cannot reproduce the pinned digest and legitimately fails every floor.
//
// An archive entry closes that gap by binding the pin reference to bytes held in content-addressed
// storage under the pin's own digest. Recapture then verifies against retained evidence instead of
// against whatever the vendor serves today.
type ArchivedPin struct {
	// Reference is the catalog pin this entry preserves, matched exactly.
	Reference string `json:"reference"`
	// Digest is the archived content's lowercase sha256, identical to the pin's digest. Storage is
	// keyed by this value, so an entry that disagrees with its pin is a corrupt archive rather than a
	// second version of the artifact.
	Digest string `json:"digest"`
	// Bytes is the exact archived length, checked alongside the digest so a truncated read fails
	// loudly rather than hashing to something unexpected.
	Bytes int64 `json:"bytes"`
	// CapturedAt is the RFC3339 UTC instant the bytes were retrieved from the origin. A pin records
	// no time, so without this an archive cannot say how stale its evidence is.
	CapturedAt string `json:"captured_at"`
}

// PinArchive is the manifest of archived pin bytes for one catalog revision.
type PinArchive struct {
	SchemaVersion string        `json:"schema_version"`
	// CatalogRevision binds the archive to the catalog whose pins it preserves, so an archive cannot
	// be silently paired with a different corpus.
	CatalogRevision string        `json:"catalog_revision"`
	Entries         []ArchivedPin `json:"entries"`
}

// PinArchiveSchemaVersion is the only accepted archive schema.
const PinArchiveSchemaVersion = "synapse-sca-benchmark-pin-archive-v1"

// Validate rejects an archive that could not be used as evidence.
func (a PinArchive) Validate() error {
	if a.SchemaVersion != PinArchiveSchemaVersion {
		return fmt.Errorf("pin archive schema version %q is not supported", a.SchemaVersion)
	}
	if strings.TrimSpace(a.CatalogRevision) == "" {
		return errors.New("pin archive catalog revision is required")
	}
	if len(a.Entries) == 0 {
		return errors.New("pin archive requires at least one entry")
	}
	seen := make(map[string]struct{}, len(a.Entries))
	for _, entry := range a.Entries {
		if err := entry.validate(); err != nil {
			return err
		}
		if _, exists := seen[entry.Reference]; exists {
			return fmt.Errorf("pin archive entry %q is duplicated", entry.Reference)
		}
		seen[entry.Reference] = struct{}{}
	}
	return nil
}

func (p ArchivedPin) validate() error {
	if strings.TrimSpace(p.Reference) == "" {
		return errors.New("archived pin reference is required")
	}
	if !validSHA256Digest(p.Digest) {
		return fmt.Errorf("archived pin %q requires an immutable sha256 digest", p.Reference)
	}
	if p.Bytes <= 0 {
		return fmt.Errorf("archived pin %q requires a positive byte length", p.Reference)
	}
	captured, err := time.Parse(time.RFC3339, p.CapturedAt)
	if err != nil {
		return fmt.Errorf("archived pin %q requires an RFC3339 capture time", p.Reference)
	}
	// A local-offset timestamp would make two archives of the same bytes order differently depending
	// on where they were produced, so the instant is required to be expressed in UTC.
	if captured.Location() != time.UTC {
		return fmt.Errorf("archived pin %q capture time must be UTC", p.Reference)
	}
	return nil
}

// ArchivablePins returns the catalog pins whose bytes are fetchable and therefore archivable, in
// deterministic reference order.
//
// A pin without an origin is locally produced — the owned benchmark binary, a scanner profile, the
// environment attestation — and is reproduced by building or by the runner rather than retrieved, so
// there is nothing upstream to preserve. Archiving those would grow the store without protecting
// anything that can drift.
func ArchivablePins(catalog Catalog) []ArtifactPin {
	archivable := make([]ArtifactPin, 0, len(catalog.Pins))
	for _, pin := range catalog.Pins {
		if strings.TrimSpace(pin.Origin) == "" {
			continue
		}
		archivable = append(archivable, pin)
	}
	sort.Slice(archivable, func(i, j int) bool { return archivable[i].Reference < archivable[j].Reference })
	return archivable
}

// ValidateArchiveCoverage reports whether an archive preserves every drift-prone pin in a catalog.
//
// Coverage is required rather than advisory because a partially archived corpus gives the most
// misleading result available: a recapture reproduces the archived pins, fails only on the
// unarchived ones, and reads as though the archive did not work. Naming the missing references
// instead makes an incomplete archive actionable.
func ValidateArchiveCoverage(catalog Catalog, archive PinArchive) error {
	if err := archive.Validate(); err != nil {
		return err
	}
	if archive.CatalogRevision != catalog.Revision {
		return fmt.Errorf("pin archive revision %q does not match catalog revision %q", archive.CatalogRevision, catalog.Revision)
	}
	archived := make(map[string]ArchivedPin, len(archive.Entries))
	for _, entry := range archive.Entries {
		archived[entry.Reference] = entry
	}
	pins := make(map[string]ArtifactPin, len(catalog.Pins))
	for _, pin := range catalog.Pins {
		pins[pin.Reference] = pin
	}
	// An entry for a pin the catalog no longer carries means the archive outlived its corpus. Left
	// unreported it would satisfy coverage while preserving bytes nothing verifies against.
	for _, entry := range archive.Entries {
		pin, exists := pins[entry.Reference]
		if !exists {
			return fmt.Errorf("pin archive entry %q is not a catalog pin", entry.Reference)
		}
		if entry.Digest != pin.Digest {
			return fmt.Errorf("pin archive entry %q digest %s does not match catalog pin digest %s", entry.Reference, entry.Digest, pin.Digest)
		}
	}
	missing := make([]string, 0)
	for _, pin := range ArchivablePins(catalog) {
		if _, exists := archived[pin.Reference]; !exists {
			missing = append(missing, pin.Reference)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("pin archive is missing %d fetchable pin(s): %s", len(missing), strings.Join(missing, ", "))
	}
	return nil
}
