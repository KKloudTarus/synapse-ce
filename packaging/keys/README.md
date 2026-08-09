# Synapse release signing keys

Two distinct keys, published here so anyone can verify what they run (#412 req 4-5, 7):

- **`synapse-packages.gpg`** — the project GPG public key that signs the **rpm and deb packages**.
  Verify a package before install, e.g. `rpm --checksig synapse-agent-*.rpm` after importing this key,
  or `dpkg-sig --verify` for deb. The release pipeline fails if any package is unsigned.
- **`synapse-agent-update.ed25519.pub`** — the hex-encoded ed25519 public key the **agent** uses to
  verify a self-update artifact's detached signature before swapping any binary
  (`internal/infrastructure/fleetupdate`). Wire it into the agent as the release verifier key.

Windows artifacts (MSI/EXE) are Authenticode-signed with the project code-signing certificate; verify
with `signtool verify /pa` or the file's Digital Signatures tab.

## The published keys

Both public halves are committed here. Their private counterparts live only in the release secrets and
in the maintainer's offline copy; they are never in this repository.

| Key | Identity |
|---|---|
| `synapse-packages.gpg` | GPG ed25519, sign-only, fingerprint `8F106FEC55FD76D73CC86D2B2EDFBC3AFAB786E1`, expires **2028-08-08** |
| `synapse-agent-update.ed25519.pub` | `a718c942752776b59d91a6660e3734ad44dbda9ef00bc046d02d855bf824e23d` |

Verify a package before installing it:

```sh
gpg --import packaging/keys/synapse-packages.gpg
rpm --import packaging/keys/synapse-packages.gpg && rpm --checksig synapse-agent-*.rpm
gpg --verify synapse-agent_*.deb.sig synapse-agent_*.deb
```

## Windows Authenticode

Not yet available. Authenticode requires a code-signing certificate issued by a CA that Windows already
trusts; a self-signed certificate would still raise the SmartScreen warning that #412 requirement 4 was
written to eliminate, so it would look like progress while changing nothing.

**Until a real certificate exists the release pipeline refuses to publish a Windows artifact rather than
publishing an unsigned one.** That is the honest failure: no Windows package, rather than one users are
warned about.

## Rotation

The signing keys expire in 2028. To rotate earlier — or after any suspected exposure — publish the
revocation certificate, generate a replacement, replace the `SYNAPSE_GPG_*` and
`SYNAPSE_UPDATE_SIGNING_KEY` repository secrets, and commit the new public halves here.

Note the asymmetry: a rotated **package** key only affects new installs, but a rotated **update** key is
rejected by every already-deployed agent until the new public key reaches it. Ship the new public key
in an agent release signed by the OLD key first.
