package ownadvisory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SecdbDirFeed is an AdvisoryFeed over a local directory of apk secdb JSON files (Alpine's
// secdb.alpinelinux.org/<rel>/<repo>.json, Wolfi's packages.wolfi.dev/os/security.json, or the Chainguard
// equivalent): the offline ingestion path for apk-family security advisories. Each file is parsed via
// ParseSecdb over the same hardened walkAdvisoryFiles core as the OVAL and OSV feeds. Like the other dir feeds
// it drops INERT advisories (ones that resolved to no fixed package) into the skip total.
type SecdbDirFeed struct {
	dir string
}

// NewSecdbDirFeed returns a feed over the given directory of apk secdb files.
func NewSecdbDirFeed(dir string) *SecdbDirFeed { return &SecdbDirFeed{dir: dir} }

var _ ports.AdvisoryFeed = (*SecdbDirFeed)(nil)

// Each walks the directory, parses every secdb JSON file via ParseSecdb, and invokes fn for each advisory that
// resolved to at least one fixed package. It returns the total skipped and a fatal error.
func (f *SecdbDirFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	inert := 0
	fileSkipped, err := walkAdvisoryFiles(ctx, f.dir, hasJSONSuffix, maxOVALFileBytes, ParseSecdb, func(adv advisory.Advisory) error {
		if len(adv.Affected) == 0 {
			inert++
			return nil
		}
		return fn(adv)
	})
	return fileSkipped + inert, err
}
