package ownadvisory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// OVALDirFeed is an AdvisoryFeed over a local directory of Canonical Ubuntu OVAL files
// (com.ubuntu.<codename>.cve.oval.xml or .xml.bz2): the offline ingestion path for vendor OS-package
// advisories. Each file is one release's whole CVE set, parsed via ParseUbuntuOVAL over the same hardened
// walkAdvisoryFiles core as the JSON feeds (regular-file-only, size- and count-capped, abort-vs-skip).
//
// Like CSAFDirFeed it drops INERT advisories – ones that resolved to no fixed (ecosystem, package) key –
// counting them into the skip total so the CLI reports honest coverage instead of storing rows that could
// never match.
type OVALDirFeed struct {
	dir string
}

// NewOVALDirFeed returns a feed over the given directory of Ubuntu OVAL files.
func NewOVALDirFeed(dir string) *OVALDirFeed { return &OVALDirFeed{dir: dir} }

var _ ports.AdvisoryFeed = (*OVALDirFeed)(nil)

// Each walks the directory, parses every OVAL file via ParseUbuntuOVAL, and invokes fn for each advisory
// that resolved to at least one fixed package. It returns the total skipped (unparseable/oversized/
// unreadable FILES + inert advisories) and a fatal error.
func (f *OVALDirFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	inert := 0
	fileSkipped, err := walkAdvisoryFiles(ctx, f.dir, hasOVALSuffix, maxOVALFileBytes, ParseUbuntuOVAL, func(adv advisory.Advisory) error {
		if len(adv.Affected) == 0 {
			inert++
			return nil
		}
		return fn(adv)
	})
	return fileSkipped + inert, err
}
