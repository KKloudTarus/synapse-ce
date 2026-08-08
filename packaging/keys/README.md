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

> The actual key material is provisioned out of band and published at release time; it is intentionally
> not committed. This directory documents the contract and is where the published public keys land.
