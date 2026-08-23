# Fleet agent packaging, signing, updates and version skew (#412)

The Synapse fleet agents (`synapse-agent` for VMs, `synapse-cluster-agent` for Kubernetes) run on
hosts the project does not own. This document is the release-engineering contract: the support
matrix, signing keys, the self-update + rollback procedure, version-skew handling, and clean
uninstall/decommission.

> **Status.** Live, with one exception named below.
>
> **Verified on every pull request.** `agent-package-matrix.yml` builds the rpm and deb from
> `packaging/nfpm.yaml` and, per matrix row, installs it, asserts the unit / `0640` config / service
> account, runs the packaged binary against a real control plane to complete one enrol and heartbeat,
> uninstalls, and fails if anything is left outside `/var/lib/synapse-agent`. A separate job builds a
> package whose libc floor is above any runtime and asserts the install is refused with a readable
> message, leaving nothing behind. `release-gate-negative.yml` proves the release gates by breaking
> them: a missing scanner, an injected exit-swallow, an unsigned artifact and an empty artifact set
> each fail.
>
> **Signed.** rpm and deb are signed with the project GPG key (`packaging/keys/synapse-packages.gpg`);
> the agent self-update manifest is signed with the project ed25519 key, whose public half is compiled
> into the agent. `release-sign.yml` refuses to start when a signing key is absent, checks the signing
> key against the published public key, signs and verifies every artifact, emits an SBOM per artifact
> from this project's own engine, signs the checksum file, and attests provenance.
>
> **Windows is the exception, and it is refused rather than faked.** Authenticode needs a certificate
> from a CA that Windows already trusts; a self-signed one would still raise the SmartScreen warning
> that requirement 4 exists to remove.
>
> So the split is precise: the MSI is **built and verified** on every pull request — installed, the
> service started, one real enrol and heartbeat completed, then uninstalled — but the release pipeline
> **refuses to publish it** until a real certificate exists. Windows packaging is supported; Windows
> *publishing* is blocked on a purchase, not on code.
>
> **Update rollout is operator-controlled** (`/api/v1/agents/rollout`): a target reaches the canary
> groups only, promotion to every group is a second deliberate action, pausing needs a reason, and
> nothing is ever offered without a plan. See *Update channel* below.

## Support matrix

Anything outside this matrix is refused by the installer with a clear message rather than installed
and left to crash at first start (#412 req 1).

| Distribution | Min version | Arch | libc floor (glibc) | Service manager |
|---|---|---|---|---|
| Debian | 10 (buster) | amd64, arm64 | 2.28 | systemd |
| Ubuntu | 20.04 LTS | amd64, arm64 | 2.31 | systemd |
| RHEL / Rocky / Alma | 8 | amd64, arm64 | 2.28 | systemd |
| Amazon Linux | 2023 | amd64, arm64 | 2.34 | systemd |
| Windows Server | 2019 (build 17763) | amd64 | n/a | Windows Service (LocalService) |

The **libc floor is enforced twice** (#412 req 2): (1) as a package dependency — rpm
`Requires: glibc >= X`, deb `Depends: libc6 (>= X)` — so the package manager refuses an install below
it; and (2) by `packaging/scripts/preinstall.sh`, which re-checks the *runtime* glibc and aborts at
install time (leaving nothing behind) for the field case where the dependency is satisfiable but the
running glibc is older than the build target and the service would crash-loop at first start.

**The Windows floor is enforced twice as well, but split differently, and the reason is worth knowing
before anyone "tightens" it.** `msiexec.exe` reads the OS version through the compatibility shim, so on
every release after Windows 8.1 it sees version 6.3 **build 9600** — `WindowsBuild` does *not* carry the
real number. An MSI launch condition on the build therefore refuses Windows Server 2025 exactly as
readily as Windows 7 (observed: install failed with 1603 on a build-26100 runner). So:

1. the **MSI** conditions on `VersionNT >= 603`, which is the strongest claim MSI can make honestly —
   `VersionNT` *is* accurate below 8.1, so this does refuse Windows 7 and 8 at install time; and
2. the **agent** enforces build ≥ 17763 itself in `cmd/synapse-agent/osfloor_windows.go`, reading it
   through `RtlGetVersion`, which the shim does not touch, and refusing to start below it.

The second check is not belt-and-braces for its own sake: an agent that runs on an untested platform and
reports inventory anyway makes the fleet view show a host as covered when it is not, which is worse than
the host being absent from it.

## Native packages

`packaging/nfpm.yaml` produces **rpm + deb** from one spec; Windows ships an **MSI**; a plain archive
is produced by goreleaser. Each package installs a hardened systemd unit
(`packaging/systemd/synapse-agent.service` — non-root dedicated `synapse-agent` account, `NoNewPrivileges`,
`ProtectSystem=strict`, dropped capabilities, seccomp `@system-service`), a `0640 root:synapse-agent`
config, and a state directory `/var/lib/synapse-agent` (credential `0600`).

## Signing (#412 req 4-5)

- **rpm/deb** are signed with the project **GPG** key; its public key ships in `packaging/keys/`.
- **Windows** artifacts are **Authenticode**-signed.
- Every release publishes **checksums, an SBOM per artifact (generated by Synapse's own engine —
  dogfooding), a deterministic release-evidence manifest, and a provenance attestation**. See
  [Release provenance and artifact verification](release-provenance.md) for the fail-closed consumer
  procedure and trust boundaries.
- The pipeline **fails if any artifact is unsigned**; a deliberately-broken run asserting that failure
  is part of acceptance.

## Release scanning fails closed (#412 req 6)

`.github/workflows/release-scan-gate.yml` scans every artifact (and the image) with
`synapse-cli scan --fail-on high` and **fails the job if the scanner is missing, errors, or reports a
finding at/above the floor** — never a `|| true` that reports zero findings for a dead scanner. No
step in the release path may swallow a non-zero exit; `scripts/release/check-no-exit-swallow.sh`
greps the release workflows for that pattern and fails the build if found (runnable locally too).

## Self-update and automatic rollback (#412 req 7-8)

Implemented in `internal/infrastructure/fleetupdate`:

1. The heartbeat response can carry an available `target_version` + download URL + expected SHA-256 +
   detached signature (operator-controlled rollout — see version skew below; never an unconditional
   fleet-wide auto-update, #412 req 9).
2. The agent downloads over the authenticated channel, **verifies the checksum and the signature
   before replacing anything** (the ed25519 release key in `packaging/keys/`). A tampered checksum or
   signature is **refused with nothing installed** — the running version is untouched.
3. On a valid, newer plan it installs atomically (keeping a backup) and restarts under the service
   manager.
4. It then **health-gates**: if the new version does not report a successful heartbeat within the
   window, the agent **automatically rolls back** to the previous version and reports the failure with
   the `from → to` version pair.

Rollout is **operator-controlled**: a target version per agent group, a canary group, and a documented
pause — never an unconditional auto-update.

## Update rollout is operator-controlled (#412 req 9)

There is no unconditional fleet-wide auto-update. An offer requires an operator to have said three
things explicitly, and the API is shaped so that saying two of them is not enough.

| | |
|---|---|
| `GET /api/v1/agents/rollout` | read the plan — `PermView`, so on-call can see why the fleet is or is not updating |
| `PUT /api/v1/agents/rollout` | set the target version and the canary groups — `PermAdminister` |
| `POST /api/v1/agents/rollout/promote` | release the target to every group — `PermAdminister` |
| `POST /api/v1/agents/rollout/pause` | stop every offer; a reason is required |
| `POST /api/v1/agents/rollout/resume` | lift the pause without advancing the rollout |

These are operator routes under `/api/v1/agents`, **not** `/api/v1/fleet`. The latter is the untrusted
agent auth plane, which deliberately bypasses the human authenticator and the acceptable-use gate; an
operator control mounted there would be authenticated by agent credentials.

Rules the implementation enforces rather than documents:

- **Setting a target always resets promotion.** Otherwise a new version would inherit an operator's
  decision about a different one and reach the whole fleet at once.
- **A target with no canary group is refused.** It could only ever go to every host simultaneously.
- **Promotion of a paused rollout is refused**, not queued.
- **Downgrade is never offered.** A target older than the running version declines.
- **Group membership is operator-assigned, never self-declared.** An agent that could name its own
  group could pin itself to an older, vulnerable version.
- **No plan, no decider, or a store failure all decline**, each with a reason on the heartbeat, so a
  fleet that is not updating can explain itself.

The heartbeat response carries the decision:

```json
{ "proto": "...", "control_plane_version": "...", "min_supported_agent_version": "...",
  "update": { "available": true, "reason": "the agent is in a canary group for this target",
              "target_version": "1.4.0" } }
```

Every mutation is audited. "Who moved the fleet to 1.4.0, and when" is answerable from the record.

## Version skew (#412 req 10)

- The **control plane** advertises `min_supported_agent_version` (config
  `SYNAPSE_FLEET_MIN_AGENT_VERSION`) and its own `control_plane_version` on every heartbeat response,
  and **refuses work** (`426 Upgrade Required`) to an agent below the floor with an instruction to
  update. Fail-closed: an agent that cannot state a parseable version under an active floor is refused.
- The **agent** declares the minimum control-plane version it requires (`minControlPlaneVersion`) and,
  if the control plane is older, refuses to claim work rather than act against an incompatible
  transport contract; if it is itself below the advertised floor it logs a clear update instruction.

## Uninstall and decommission (#412 req 11)

`packaging/scripts/preremove.sh` stops and disables the service; the package manager removes package
files. The documented state directory `/var/lib/synapse-agent` is left for deliberate inspection (a
package *purge* removes it). Decommissioning the agent **identity** on the control plane
(`POST .../fleet/agents/{id}/revoke`) is a separate operator action so the fleet shows the agent
**decommissioned** rather than silently going stale.
