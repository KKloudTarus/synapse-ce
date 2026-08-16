# Synapse release verification keys

Two public keys are committed here so operators can verify the artifacts that currently use them:

- **`synapse-packages.gpg`** — the project GPG public key. The current release workflow uses it to
  create detached signatures for release checksums and archives. Native RPM/deb repository signing is
  not wired yet; `packaging/nfpm.yaml` deliberately fails rather than claiming signed packages.
- **`synapse-agent-update.ed25519.pub`** — the hex-encoded Ed25519 public key used by the fleet-agent
  update verifier before swapping a binary (`internal/infrastructure/fleetupdate`).

The matching private keys live only in repository secrets and maintainers' offline custody; they are
never stored in this repository.

## Published keys

| Key | Identity |
|---|---|
| `synapse-packages.gpg` | GPG Ed25519, sign-only, fingerprint `8F106FEC55FD76D73CC86D2B2EDFBC3AFAB786E1`, expires **2028-08-08** |
| `synapse-agent-update.ed25519.pub` | `a718c942752776b59d91a6660e3734ad44dbda9ef00bc046d02d855bf824e23d` |

## Verify current release artifacts

Download an artifact, `checksums.txt`, and their detached signatures from the same GitHub release.
Import the public key, verify the checksum signature, then verify the artifact checksum:

```sh
gpg --import packaging/keys/synapse-packages.gpg
gpg --verify checksums.txt.sig checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Windows release archives are **not** Authenticode-signed. The release workflow rejects top-level
MSI/EXE package publication until a trusted code-signing certificate and signing path exist; Windows
amd64 ZIP archives remain checksum- and detached-signature-verifiable like other release archives.

## Rotation

The signing keys expire in 2028. To rotate earlier — or after any suspected exposure — publish the
revocation certificate, generate a replacement, replace the `SYNAPSE_GPG_*` and
`SYNAPSE_UPDATE_SIGNING_KEY` repository secrets, and commit the new public halves here.

Note the asymmetry: a rotated **package** key only affects new installs, but a rotated **update** key is
rejected by every already-deployed agent until the new public key reaches it. Ship the new public key
in an agent release signed by the OLD key first.
