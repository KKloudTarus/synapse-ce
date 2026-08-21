# Synapse documentation

**Verify Everything. Trust Nothing.**

Synapse is a governed control plane for supply-chain, code, cloud, offensive, and runtime security
assessments. These guides cover the first scan, production operations, governance, integrations, and the
architectural boundaries that keep execution auditable.

[Landing page](https://synapse.kkloudtarus.net/) · [GitHub](https://github.com/KKloudTarus/synapse-ce) · [License](https://github.com/KKloudTarus/synapse-ce/blob/main/LICENSE)

## Get started

| Guide | What it covers |
| --- | --- |
| [Introduction](introduction.md) | The product model, safety principles, and assessment flow |
| [Installation](installation.md) | Supported platforms, requirements, tools, and install paths |
| [Quickstart](quickstart.md) | Run the dashboard and complete a first supported scan |
| [Features](features.md) | Shipped capabilities and honest platform limits |

## Assessment workflows

| Guide | What it covers |
| --- | --- |
| [Project code quality](project-code-quality.md) | Projects, analyses, issues, hotspots, profiles, gates, and source views |
| [Governed assessments](governed-assessment-workflows.md) | Engagement scope, evidence, imported artifacts, threat models, work orders, purple coverage, and write-ups |
| [Vulnerability intelligence](vulnerability-intelligence.md) | Sources, synchronization, reconciliation, risk changes, rollout, and recovery |
| [Cloud posture](cloud-posture.md) | Read-only AWS, Azure, and Google Cloud inventory, checks, and credential boundaries |
| [Fleet and runtime defense](fleet-blue-team.md) | Agent identity, inventory, detections, coverage, work, rollout, and decommissioning |
| [AI triage review](ai-triage-review.md) | Propose/verify/review flow, evidence requirements, independence, and promotion |
| [Remediation SLA governance](sla-governance.md) | Risk scoring, immutable deadlines, lifecycle transitions, and reassessment |

## Operate and integrate

| Guide | What it covers |
| --- | --- |
| [Configuration](configuration.md) | Environment variables, defaults, dependencies, and production requirements |
| [Deployment](deployment.md) | Containers, services, agents, Linux-only capabilities, and production checks |
| [Backup, restore, and upgrade recovery](backup-restore-upgrade.md) | Quiesced paired backups, restore verification, active-write characterization, and safe upgrades |
| [CLI](cli.md) | Scanning, code-quality gates, advisory maintenance, imports, and exit contracts |
| [MCP integration](mcp-integration.md) | Read/propose-only tool access scoped to one engagement |
| [Fleet agent packaging](fleet-agent-packaging.md) | Package, identity, rollout, upgrade, and uninstall contracts |
| [AI triage evaluation](ai-triage-evaluation.md) | Offline datasets, comparison gates, promotion, rollback, and drift detection |
| [Operations drill evidence](operations-drill-evidence.md) | Versioned, redacted evidence for backup, restore, and rollback-on-copy drills |
| [Code quality rule authoring](code-quality-rules.md) | Clean-room rule packs, schemas, references, and golden coverage |

## Architecture and policy

| Guide | What it covers |
| --- | --- |
| [Architecture](architecture.md) | Clean-architecture layers, runtime topology, ports, and binaries |
| [Security model](security.md) | The safety invariants and their enforcement boundaries |
| [Telemetry store ADR](repository/telemetry-store-adr.md) | Why fleet telemetry is isolated behind a dedicated store port |
| [CSPM helper ADR](repository/cspm-helper-adr.md) | Why cloud SDKs and credentials live in an authorized sandbox helper |
| [Promotion rules](repository/promotion-rules.md) | Deterministic cross-pillar priority proposals and uncertainty handling |
| [Offensive policy](repository/offensive-policy.md) | Enforced technique classifications, approval, cleanup, and kill switch |

## Quick links

- Full local stack: `docker compose -f deploy/docker-compose.full.yml up --build`
- Native development: `SYNAPSE_API_TOKEN="$(openssl rand -hex 32)" make dev`
- CI scan: `./bin/synapse-cli scan . --fail-on high`
- Only required development setting: `SYNAPSE_API_TOKEN`

## Authorized use

Synapse is for authorized security testing. Every engagement enforces an explicit scope and legal
authorization window server-side before execution. Synapse validates those controls but cannot verify that
an operator holds legal permission. Keep written authorization for every target.
