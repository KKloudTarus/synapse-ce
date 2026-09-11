package ownadvisory

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// UpdateInfoDirFeed is an AdvisoryFeed over a local directory of yum/dnf updateinfo errata files
// (repodata updateinfo.xml, plain or .gz/.bz2): the offline ingestion path for Amazon Linux ALAS security
// advisories, which are published only as updateinfo (no OVAL). Each file is parsed via ParseUpdateInfo over
// the same hardened walkAdvisoryFiles core as the OVAL and JSON feeds (regular-file-only, size- and
// count-capped, abort-vs-skip). Like the other dir feeds it drops INERT advisories (ones that resolved to no
// fixed package) into the skip total so the CLI reports honest coverage.
type UpdateInfoDirFeed struct {
	dir string
}

// NewUpdateInfoDirFeed returns a feed over the given directory of updateinfo errata files.
func NewUpdateInfoDirFeed(dir string) *UpdateInfoDirFeed { return &UpdateInfoDirFeed{dir: dir} }

var _ ports.AdvisoryFeed = (*UpdateInfoDirFeed)(nil)

// hasUpdateInfoSuffix accepts the plain and compressed updateinfo XML file names.
func hasUpdateInfoSuffix(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".xml") || strings.HasSuffix(n, ".xml.gz") || strings.HasSuffix(n, ".xml.bz2")
}

// Each walks the directory, parses every updateinfo file via ParseUpdateInfo, and invokes fn for each
// advisory that resolved to at least one fixed package. It returns the total skipped (unparseable/oversized/
// unreadable FILES + inert advisories) and a fatal error.
func (f *UpdateInfoDirFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	inert := 0
	fileSkipped, err := walkAdvisoryFiles(ctx, f.dir, hasUpdateInfoSuffix, maxOVALFileBytes, ParseUpdateInfo, func(adv advisory.Advisory) error {
		if len(adv.Affected) == 0 {
			inert++
			return nil
		}
		return fn(adv)
	})
	return fileSkipped + inert, err
}
