# Synapse Documentation

**Verify Everything. Trust Nothing.**

A governed control plane for software composition analysis, recon, evidence, and reporting.

[Landing page](https://synapse.kkloudtarus.net/) · [GitHub](https://github.com/KKloudTarus/synapse-ce) · [License](https://github.com/KKloudTarus/synapse-ce/blob/main/LICENSE)

---

Welcome to the Synapse documentation. These guides cover everything from a first scan to a
production deployment. If you prefer a visual tour, the [landing page](https://synapse.kkloudtarus.net/)
has screenshots of the current build.

## Contents

| Guide | What it covers |
| --- | --- |
| [Introduction](introduction.md) | What Synapse is, the core ideas, and how a scan flows through it |
| [Installation](installation.md) | Requirements, external tools, and the ways to install |
| [Quickstart](quickstart.md) | From clone to a running dashboard, then a first scan |
| [Features](features.md) | Every capability, in depth |
| [Code Quality Rules](code-quality-rules.md) | Authoring guide for code-quality rule packs (schema, clean-room policy, per-language sources) |
| [Configuration](configuration.md) | The full environment-variable reference |
| [CLI](cli.md) | Using `synapse-cli` for scans in CI |
| [Architecture](architecture.md) | Clean architecture, layers, ports, and the binaries |
| [Deployment](deployment.md) | Docker, Compose, and a production checklist |
| [Security model](security.md) | The safety invariants and how they are enforced |

## Quick links

- Run the full stack: `docker compose -f deploy/docker-compose.full.yml up --build`
- Scan a project: `./bin/synapse-cli scan . --fail-on high`
- The only required setting: `SYNAPSE_API_TOKEN`

## A note on scope

Synapse is for authorized security testing. Every engagement enforces an explicit scope and a
legal authorization window, server-side, before any tool runs. Synapse validates that scope
data but cannot verify legal authorization. The operator is responsible for holding written
permission to test any target.
