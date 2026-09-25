# Installation

[Documentation home](README.md) · Previous: [Introduction](introduction.md) · Next: [Quickstart](quickstart.md)

## Requirements

| Component | Notes |
| --- | --- |
| Go 1.26 | Pinned in `go.mod`. Builds cgo-free, so the container image is distroless. |
| Node 22 and pnpm | For the web dashboard. Use pnpm, not npm or yarn. |
| Syft | Optional. An opt-in second SBOM producer, used to cross-check the owned parsers. Not needed to scan: `SYNAPSE_SBOM_PRODUCER` defaults to `ownsbom`. |
| Grype | Optional. Adds an offline vulnerability database as an opt-in detection source beside the owned advisory store. |
| PostgreSQL | Optional for development, required for durable persistence, the fleet, scheduled provider work, and the owned advisory store. |
| S3 or MinIO | Optional. For evidence artifacts. |
| Docker | Optional. The easiest way to run the full stack on any OS. |
| Linux host | Required for the hardened sandbox, live recon, and egress scoping (bubblewrap, seccomp, cgroups, network namespaces). |
| Linux with eBPF | Required only for host-agent runtime detections. Needs root or equivalent capabilities. |
| Kubernetes access | Required only for `synapse-cluster-agent`. Runs in-cluster or with a kubeconfig. |

## Platform support

The API, SCA, project code quality, findings, and reports run on macOS, Linux, and Windows for
development. Several capabilities depend on Linux kernel features with no Windows or macOS equivalent:

| Capability | Requirement | Behavior elsewhere |
| --- | --- | --- |
| Execution sandbox | Linux with bubblewrap, seccomp, cgroups | Fails closed when requested; never runs unsandboxed |
| Live recon | Linux sandbox | Stays disabled |
| Egress scoping | Linux network namespaces | A run needing enforced egress is refused, not downgraded |
| Governed DAST probes | Linux, kernel-enforced egress allowlist | Probe refused |
| Host runtime detections | Linux with eBPF, root or capabilities | Detection engine stays off |

Requested-but-unavailable protection is always an error rather than a silent downgrade. The simplest way
to get full parity on any OS is the container, which is Linux inside.

## Install the external tools

A scan needs none of these. The SBOM comes from Synapse's own per-ecosystem parsers and the
vulnerability data from its own advisory store, so a stock install shells out to no third-party
scanner at all. Install them only for the opt-in cross-check:

```bash
make tools            # installs syft and grype into ./bin, checksum-verified
export PATH="$PWD/bin:$PATH"
```

Recon is different: live recon really does shell out, so its tools must be present and, because the
sandbox binds a curated read-only root, they must sit somewhere it can reach.

```bash
make tools RECON=1                              # subfinder, httpx, naabu via `go install`
sudo cp "$(go env GOPATH)/bin/"{subfinder,httpx,naabu} /usr/local/bin/
```

`go install` writes into `$(go env GOPATH)/bin`, which is usually under a home directory, and a
home directory is mode `0750` on current Ubuntu. The sandbox drops into a user namespace before it
binds anything, so it cannot traverse that path and the run fails with `bwrap: Can't find source
path …: Permission denied`. `/usr/local/bin` is inside the curated root. See
[troubleshooting](troubleshooting.md#a-recon-run-fails-with-ip-netns-attach--no-such-file-or-directory).

## Install Synapse

### From source

```bash
git clone https://github.com/KKloudTarus/synapse-ce.git
cd synapse-ce
make install          # Go modules + web dependencies
make build            # all binaries into ./bin
```

### With Docker

The full stack (API with tools bundled, PostgreSQL, object store, dashboard) builds and runs
with one command:

```bash
docker compose -f deploy/docker-compose.full.yml up --build
```

See [Deployment](deployment.md) for the image targets and a production checklist.

### With Kubernetes (Helm)

The chart in `deploy/helm/synapse` installs the control plane on any cluster. Its `execution.mode`
selects the shape: `controlPlaneOnly` (the offline scanner console, boots on managed EKS/GKE and
`kind`), `externalNative` (production control plane on Kubernetes with a native execution tier per
ADR 0008), and `inClusterBroker` (in-cluster execution via an opt-in privileged egress-broker
DaemonSet). Try it against a local `kind` cluster:

```bash
make kind-smoke       # deploy execution.mode=controlPlaneOnly and assert the control plane serves
```

The runtime database role must be `NOSUPERUSER NOBYPASSRLS`; Synapse refuses to serve on a superuser
role because it bypasses the row-level security that isolates tenants. See
[Deployment](deployment.md) for the mode matrix, the egress placements, and the production checklist.

## Verify

```bash
make build vet test
curl -s http://localhost:8080/healthz    # after the server is running
```

Next: [Quickstart](quickstart.md)
