# Release provenance and artifact verification

Synapse release verification has three separate layers. None substitutes for another:

| Layer | Proves | Does not prove |
|---|---|---|
| SHA-256 entries in `release-evidence.json` | The downloaded bytes are the complete asset set recorded for the release | Who published the manifest |
| Detached GPG signature | The manifest was signed by the published Synapse package key | Which workflow or source revision produced it |
| GitHub artifact attestation | GitHub observed the trusted workflow attest this manifest at the stated source identity | That the source was vulnerability-free |

The release workflow generates `release-evidence.json` without a timestamp. Given the same repository,
tag, source revision, and asset bytes, it is byte-for-byte deterministic. Entries are sorted and include
every primary archive/package, detached signature, SBOM, and checksum file. The manifest does not list
itself or its detached signature, avoiding a recursive digest.

The workflow refuses to sign when its GitHub workflow identity, checked-out commit, and tag commit do
not agree. A manually dispatched signing run must therefore be launched from the release tag rather
than from a moving branch. On retry, previously generated signatures, SBOMs, checksums, and evidence
manifest are removed from the runner and regenerated from the primary goreleaser assets.

## Verify a release

Start from a trusted checkout of the expected tag and import the public package key from
`packaging/keys/synapse-packages.gpg`. Download all assets into an otherwise empty directory:

```bash
tag=v1.2.3
repo=KKloudTarus/synapse-ce
revision="$(git rev-list -n 1 "${tag}^{commit}")"

mkdir release-assets
gh release download "${tag}" --repo "${repo}" --dir release-assets
gpg --import packaging/keys/synapse-packages.gpg
gpg --verify release-assets/release-evidence.json.sig release-assets/release-evidence.json
```

Next verify the expected identity, every recorded digest and size, and the absence of unlisted assets:

```bash
go run ./cmd/synapse-release-evidence verify \
  --dir release-assets \
  --repository "${repo}" \
  --revision "${revision}" \
  --release "${tag}"
```

Verification is fail-closed. It rejects unknown JSON fields, non-canonical encoding, path traversal,
symlinks and non-regular files, duplicate or unsorted entries, a wrong repository/tag/revision, changed
or missing files, and any extra asset not recorded by the manifest. Build the verifier from the trusted
tag checkout; do not substitute a verifier downloaded from the unverified release.

Finally verify GitHub's signed provenance for the manifest. Pinning the repository, signing workflow,
source digest, and tag ref is stronger than accepting any attestation from the organization:

```bash
gh attestation verify release-assets/release-evidence.json \
  --repo "${repo}" \
  --signer-workflow "github.com/${repo}/.github/workflows/release-sign.yml" \
  --source-digest "${revision}" \
  --source-ref "refs/tags/${tag}"
```

All three commands must pass before promotion. A checksum match alone proves consistency with a
manifest, not publisher authenticity. A valid publisher signature does not prove runtime safety or
the absence of vulnerabilities; release scanning and deployment policy remain independent gates.

## Generate a manifest locally

Release engineering can reproduce the deterministic manifest before a tag is published:

```bash
go run ./cmd/synapse-release-evidence generate \
  --dir release-assets \
  --repository KKloudTarus/synapse-ce \
  --revision "$(git rev-parse HEAD)" \
  --release v1.2.3
```

Generation refuses to overwrite an existing manifest. Use a fresh asset directory when reproducing
evidence; this keeps stale output from being mistaken for current release evidence.
