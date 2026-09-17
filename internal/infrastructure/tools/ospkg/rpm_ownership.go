package ospkg

import (
	"context"
	"path/filepath"
)

// RPMPackageFiles is one installed RPM package and the absolute file paths it owns (as recorded in the
// rpm header: DIRNAMES[DIRINDEXES[i]]+BASENAMES[i]). Files is empty for a metapackage that installs no files.
type RPMPackageFiles struct {
	Name    string
	Version string // EVR (epoch:version-release when an epoch is present)
	Arch    string
	Files   []string
}

// RPMOwnership reads the rpm database under rootfsDir and returns the file list each installed package owns,
// for a file->package ownership join. It reuses the same hardened, bounded, recover-wrapped container walkers
// as the SBOM cataloger (no shell, direct DB read), trying each backend in turn: the sqlite rpmdb
// (RHEL9+/Fedora/UBI9) first, then the BerkeleyDB rpmdb (RHEL<=8/CentOS/UBI8/Amazon Linux 2), then the ndb
// backend (openSUSE/SLE). The first backend that yields any valid package header wins, so a single-backend
// rootfs is read from whichever DB it has and a rootfs whose /var/lib/rpm symlinks to /usr/lib/sysimage/rpm is
// never double-counted. Only packages that own at least one file are returned. An error (context cancellation)
// from any backend is surfaced; an absent/malformed DB contributes nothing.
func RPMOwnership(ctx context.Context, rootfsDir string) ([]RPMPackageFiles, error) {
	// collect drains one container's header blobs. saw is true once any blob parses as a valid header
	// (even a metapackage owning no files), which is what selects the backend; out carries only the
	// file-owning packages, since a package owning no files can never own a loaded object.
	collect := func(walk func(func([]byte)) error) (out []RPMPackageFiles, saw bool, err error) {
		bytesUsed := 0 // running total of retained path bytes, so a hostile DB cannot accumulate unbounded memory
		err = walk(func(blob []byte) {
			name, evr, arch, files, ok := safeParseRPMHeaderFiles(blob)
			if !ok {
				return
			}
			saw = true
			if len(files) == 0 || bytesUsed >= maxRPMOwnershipBytes {
				return
			}
			for _, f := range files {
				bytesUsed += len(f)
			}
			out = append(out, RPMPackageFiles{Name: name, Version: evr, Arch: arch, Files: files})
		})
		return out, saw, err
	}

	out, saw, err := collect(func(v func([]byte)) error { return rpmSQLiteBlobs(ctx, rootfsDir, v) })
	if err != nil || saw {
		return out, err
	}
	out, saw, err = collect(func(v func([]byte)) error {
		return rpmBDBBlobs(ctx, filepath.Join(rootfsDir, rpmBDBPath), v)
	})
	if err != nil || saw {
		return out, err
	}
	for _, p := range []string{rpmNDBPath, rpmNDBSysimagePath} {
		out, saw, err = collect(func(v func([]byte)) error {
			return rpmNDBBlobs(ctx, filepath.Join(rootfsDir, p), v)
		})
		if err != nil || saw {
			return out, err
		}
	}
	return nil, nil
}
