package ownadvisory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RockyOSVDirFeed is an AdvisoryFeed over a local directory of RESF/Apollo OSV list pages (the
// apollo.build.resf.org/api/v3/osv JSON): the offline ingestion path for Rocky Linux RLSA advisories, which
// are published as an {"advisories":[...]} OSV envelope keyed by RLSA with the CVEs in "upstream". Each file
// is parsed via ParseRockyOSV over the same hardened walkAdvisoryFiles core as the OVAL and OSV feeds. Like
// the other dir feeds it drops INERT advisories (ones that resolved to no fixed package) into the skip total.
type RockyOSVDirFeed struct {
	dir string
}

// NewRockyOSVDirFeed returns a feed over the given directory of Apollo OSV list pages.
func NewRockyOSVDirFeed(dir string) *RockyOSVDirFeed { return &RockyOSVDirFeed{dir: dir} }

var _ ports.AdvisoryFeed = (*RockyOSVDirFeed)(nil)

// Each walks the directory, parses every Apollo OSV list page via ParseRockyOSV, and invokes fn for each
// advisory that resolved to at least one fixed package. It returns the total skipped and a fatal error.
func (f *RockyOSVDirFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	inert := 0
	fileSkipped, err := walkAdvisoryFiles(ctx, f.dir, hasJSONSuffix, maxOVALFileBytes, ParseRockyOSV, func(adv advisory.Advisory) error {
		if len(adv.Affected) == 0 {
			inert++
			return nil
		}
		return fn(adv)
	})
	return fileSkipped + inert, err
}
