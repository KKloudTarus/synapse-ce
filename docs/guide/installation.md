# Installation

[Documentation home](README.md) · Previous: [Introduction](introduction.md) · Next: [Quickstart](quickstart.md)

## Requirements

| Component | Notes |
| --- | --- |
| Go 1.26 | Pinned in `go.mod`. Builds cgo-free, so the container image is distroless. |
| Node 20 and pnpm 9 | For the web dashboard. Use pnpm, not npm or yarn. |
| Syft | Required for any scan. Generates the SBOM. |
| Grype | Optional. Adds the offline vulnerability database. Missing means detection degrades to the live source only. |
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

Synapse shells out to pinned tool binaries. Install them with the provided target:

```bash
make tools            # installs syft and grype into ./bin, checksum-verified
export PATH="$PWD/bin:$PATH"
```

Add recon tools on Linux with `make tools RECON=1`. The container image already bundles syft
and grype.

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

## Verify

```bash
make build vet test
curl -s http://localhost:8080/healthz    # after the server is running
```

Next: [Quickstart](quickstart.md)
