# Installation

[Documentation home](README.md) · Previous: [Introduction](introduction.md) · Next: [Quickstart](quickstart.md)

## Requirements

| Component | Notes |
| --- | --- |
| Go 1.26 | Pinned in `go.mod`. Builds cgo-free, so the container image is distroless. |
| Node and pnpm | For the web dashboard. Use pnpm, not npm or yarn. |
| Syft | Required for any scan. Generates the SBOM. |
| Grype | Optional. Adds the offline vulnerability database. Missing means detection degrades to the live source only. |
| PostgreSQL | Optional. For durable persistence. A blank DSN runs an in-memory dev store. |
| S3 or MinIO | Optional. For evidence artifacts. |
| Docker | Optional. The easiest way to run the full stack on any OS. |
| Linux host | Required only for the hardened sandbox, live recon, and egress scoping (bubblewrap, seccomp, cgroups, network namespaces). |

## Platform support

The API, SCA, findings, and reports run on macOS, Linux, and Windows for development. The
execution sandbox, live recon, and egress scoping use Linux kernel features that have no
Windows or macOS equivalent. On those platforms the features stay disabled and fail closed
rather than running unsandboxed. The simplest way to get full parity on any OS is to run the
container, which is Linux inside.

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
