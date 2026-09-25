package ospkg

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
)

//go:embed testdata/centos7-base-header-allowlist.json
var centOS7BaseManifestJSON []byte

type centOS7BaseManifest struct {
	Repository   string `json:"repository"`
	RepomdSHA256 string `json:"repomd_sha256"`
	Packages     []struct {
		Name                  string `json:"name"`
		EVR                   string `json:"evr"`
		Arch                  string `json:"arch"`
		RPMPath               string `json:"rpm_path"`
		RPMSHA256             string `json:"rpm_sha256"`
		ImmutableHeaderSHA256 string `json:"immutable_header_sha256"`
	} `json:"packages"`
}

type centOS7BaseIdentity struct {
	name, evr, arch string
}

// A signer proves that CentOS produced a package, not that it came from the
// RHEL-derived base repository. These digests were generated from full RPMs
// whose checksums match the signed CentOS Vault 7.9.2009 base repository.
// Unknown signed RPMs remain unsupported until their provenance is reviewed
// and the manifest is regenerated.
var centOS7BaseHeaders = parseCentOS7BaseManifest(centOS7BaseManifestJSON)

func parseCentOS7BaseManifest(data []byte) map[[sha256.Size]byte]centOS7BaseIdentity {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest centOS7BaseManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil
	}
	if manifest.Repository != "https://vault.centos.org/7.9.2009/os/x86_64/" || !validSHA256Hex(manifest.RepomdSHA256) || len(manifest.Packages) == 0 {
		return nil
	}
	allowed := make(map[[sha256.Size]byte]centOS7BaseIdentity, len(manifest.Packages))
	for _, pkg := range manifest.Packages {
		if pkg.Name == "" || pkg.EVR == "" || pkg.Arch == "" || !strings.HasPrefix(pkg.RPMPath, "Packages/") ||
			strings.Contains(pkg.RPMPath, "..") || !validSHA256Hex(pkg.RPMSHA256) || !validSHA256Hex(pkg.ImmutableHeaderSHA256) {
			return nil
		}
		decoded, _ := hex.DecodeString(pkg.ImmutableHeaderSHA256)
		var headerSHA [sha256.Size]byte
		copy(headerSHA[:], decoded)
		if _, duplicate := allowed[headerSHA]; duplicate {
			return nil
		}
		allowed[headerSHA] = centOS7BaseIdentity{name: pkg.Name, evr: pkg.EVR, arch: pkg.Arch}
	}
	return allowed
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func centOS7BaseHeaderAllowed(original []byte, name, evr, arch string) bool {
	entry, found := centOS7BaseHeaders[sha256.Sum256(original)]
	return found && entry.name == name && entry.evr == evr && entry.arch == arch
}
