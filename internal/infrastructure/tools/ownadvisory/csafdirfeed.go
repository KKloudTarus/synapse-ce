package ownadvisory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CSAFDirFeed is an AdvisoryFeed over a local directory of OASIS CSAF 2.0 advisory JSON files: the
// offline ingestion path for vendor security advisories (RedHat/SUSE/Cisco-style). Each *.json is parsed
// via ParseCSAF (which yields MANY advisories per document) over the same hardened walkJSONAdvisories core
// as DirFeed.
//
// Beyond the file-level skipping the shared walk does, this feed also drops INERT advisories – ones whose
// products did not resolve to any owned (ecosystem, package) key (the CPE↔ecosystem gap; see cpe.go), so
// they carry no Affected block and could never match. They are counted into the returned skip total so the
// CLI can surface honest coverage (how much of a CSAF feed actually maps to a matchable ecosystem) rather
// than silently storing rows that never fire.
type CSAFDirFeed struct {
	dir string
}

// NewCSAFDirFeed returns a feed over the given directory of CSAF 2.0 JSON advisories.
func NewCSAFDirFeed(dir string) *CSAFDirFeed { return &CSAFDirFeed{dir: dir} }

var _ ports.AdvisoryFeed = (*CSAFDirFeed)(nil)

// Each walks the directory, parses every *.json CSAF document via ParseCSAF, and invokes fn for each
// advisory that resolved to at least one matchable package. It returns the total skipped (unparseable/
// oversized/unreadable FILES + inert advisories with no resolvable package) and a fatal error.
func (f *CSAFDirFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	inert := 0
	fileSkipped, err := walkJSONAdvisories(ctx, f.dir, ParseCSAF, func(adv advisory.Advisory) error {
		if len(adv.Affected) == 0 {
			inert++ // no product mapped to a comparable ecosystem – inert in the store, so don't persist it
			return nil
		}
		return fn(adv)
	})
	return fileSkipped + inert, err
}
