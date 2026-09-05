# Deployment

[Documentation home](README.md) · Previous: [Architecture](architecture.md) · Next: [Security model](security.md)

Synapse ships as a set of Go binaries plus a web dashboard. The provided Compose stack is the quickest local-development deployment. It is not the recommended production topology: it publishes development service ports and runs the API sandbox-off.

## Full stack with Docker Compose

The `deploy/docker-compose.full.yml` stack runs everything: PostgreSQL, an S3-compatible object
store, the API server with Syft and Grype bundled, and the web dashboard.

The stack requires explicit database credentials and complete runtime/migration DSNs. There are no defaults for them, and that is the point: a database password committed to a public repository is a password every reader of the repository has. Generate them once. From the repository root:

```bash
umask 077
DB_ADMIN_PASSWORD="$(openssl rand -hex 16)"
DB_APP_PASSWORD="$(openssl rand -hex 16)"
BLOB_PASSWORD="$(openssl rand -hex 16)"
cat > deploy/.env.local <<EOF
DB_ADMIN_PASSWORD=$DB_ADMIN_PASSWORD
DB_APP_PASSWORD=$DB_APP_PASSWORD
BLOB_PASSWORD=$BLOB_PASSWORD
SYNAPSE_API_TOKEN=$(openssl rand -hex 32)
SYNAPSE_DB_DSN=postgres://synapse_app:$DB_APP_PASSWORD@postgres:5432/synapse?sslmode=disable
SYNAPSE_DB_MIGRATION_DSN=postgres://synapse_admin:$DB_ADMIN_PASSWORD@postgres:5432/synapse?sslmode=disable
EOF

docker compose --env-file deploy/.env.local \
  -f deploy/docker-compose.full.yml up -d --build --wait
```

Then check both surfaces:

```bash
curl localhost:8080/readyz                                  # {"status":"ready",...}
curl -s -o /dev/null -w '%{http_code}\n' localhost:5173/    # 200
```

`--env-file` is intentional: Compose does not infer `deploy/.env.local` merely because the Compose file lives in `deploy/`. Keep the file out of version control; `.gitignore` already covers `.env.local`. Hex passwords are URL-safe; percent-encode reserved characters in any complete DSN you write by hand. PostgreSQL stores its initial credentials in the `pgdata` volume; changing the env file does not rewrite an existing role password. Keep the original credentials, rotate them in PostgreSQL, or reset disposable local state with `down -v`.

The two database roles are not interchangeable. `synapse_admin` owns the schema, runs migrations, and grants the runtime role its table privileges. `synapse_app` is `NOSUPERUSER NOBYPASSRLS` and is the only role the API will serve under: `SYNAPSE_DB_DSN` pointed at a superuser stops startup with `rls: runtime DB role cannot enforce isolation: role is SUPERUSER`, because row level security is silently a no-op for a role that bypasses it.

The two Compose files declare distinct project names, `synapse-dev` for `deploy/docker-compose.yml` and `synapse-full` for `deploy/docker-compose.full.yml`. Without them Compose derives the project name from the `deploy/` directory, both stacks share the volume `deploy_pgdata`, and the second one to run inherits the first one's superuser and fails with `password authentication failed`. Each stack now owns `synapse-dev_pgdata` or `synapse-full_pgdata`, so they can be started and stopped independently. They still both publish 5432, so run one at a time.

Treat this profile as local development only. Its ports bind beyond loopback by default, MinIO has administrative access to the evidence bucket, and `SYNAPSE_SANDBOX_ENABLED=false` means source-acquisition and tool processes lack Synapse's required production containment. Restrict it with host firewall rules and use only trusted fixture targets. A production deployment must enable the fail-closed Linux sandbox, keep data services private, terminate TLS, and follow the checklist below.

| Service | Port | Purpose |
| --- | --- | --- |
| `synapse-api` | 8080 | HTTP API |
| `web` | 5173 | Web dashboard |
| `postgres` | 5432 | Database |
| `minio` | 9000, 9001 | Object store and console |

Init containers (`postgres-init`, `minio-init`, `project-source-artifacts-init`) prepare the database,
bucket, and source-artifact volume before the API starts.

`web` serves the built dashboard from nginx (`deploy/Dockerfile.web` target `compose`) and reverse-proxies `/api`, `/healthz`, and `/readyz` to `synapse-api`, which is the routing a Kubernetes ingress performs in production. Editing `web/` therefore does not hot-reload here; run `make dev` for that.

## Beyond a single API

The Compose stack is the smallest useful deployment. Three components run separately in a real
installation:

**`synapse-worker`** is required for durable recon, scheduled vulnerability-intelligence work, CSPM runs,
and fleet dispatch. It is lease-based, so enable `SYNAPSE_LEADER_ENABLED` and run it alongside the API
rather than inside it.

**Fleet agents** run on the hosts being defended, not on the control plane. `synapse-agent` needs Linux
with eBPF for runtime detections; `synapse-cluster-agent` runs in-cluster or with a kubeconfig. Both enroll
with a one-time token and then authenticate with a client certificate. See
[Fleet and runtime defense](fleet-blue-team.md) and
[Fleet agent packaging](fleet-agent-packaging.md).

**Sandboxed helpers** (`synapse-callgraph`, `synapse-ast`, `synapse-cspm`, `synapse-dast-helper`) are
executed by the server as pinned binaries. They need to be present on the host or image, and in production
should be referenced by absolute path with hashes pinned in `SYNAPSE_TOOL_HASHES`.

The stack reads its settings from environment variables with dev defaults. Change them for
anything but local development. Put real values in a `.env` file next to the Compose file, or
export them in your shell.

## Image targets

`deploy/Dockerfile` has three buildable targets. `build` and `ast-build` are internal compile stages
and are not meant to be built directly.

- **production**: the hardened runtime the Helm chart deploys. Debian trixie with bubblewrap, tini,
  git, every server-side binary, and pinned Syft and Grype. Use this one for a real deployment.
- **api**: a distroless image carrying `synapse-api`, `synapse-cli`, `synapse-dast-helper`, Syft, and
  Grype. Smallest and most locked-down; it has no shell and no bubblewrap, so sandboxed execution
  fails closed there.
- **full**: the local-development image `deploy/docker-compose.full.yml` builds. Debian bookworm with
  a JDK 17, Maven, and a Gradle distribution on top of the API and CLI binaries, so
  `synapse-cli scan --mode full` can resolve JVM dependency trees from source.

```bash
docker build -t synapse-api:latest --target api -f deploy/Dockerfile .
docker build -t synapse:full --target full -f deploy/Dockerfile .
docker build -t synapse:production --target production -f deploy/Dockerfile .
```

The build is cgo-free, so the distroless image works with a pure-Go SQLite driver and no
system libraries. The one exception is `synapse-ast`, which is tree-sitter-linked and is therefore
compiled in a separate Debian stage against glibc for the `production` image.

### The `full` image is large

`full` measures roughly 940 MB against roughly 320 MB for `api`. The JVM toolchain is the
difference, and it is load-bearing: JVM software composition analysis shells out to `mvn` and
`gradle` to resolve transitive dependency trees, so removing the toolchain removes that capability.
When you do not need JVM-from-source SCA, build `--target api` and get the same HTTP server in a
third of the size.

That toolchain layer caches independently of your Go code. In the `full` stage the
`RUN apt-get install ... && curl gradle` line is the first instruction after
`FROM debian:bookworm-slim`, and the compiled binaries arrive afterwards through
`COPY --from=build`. BuildKit keys that `RUN` on the base image and the command text alone, so a
change under `cmd/` or `internal/` rebuilds only the Go compile stage. A measured rebuild after
editing `cmd/synapse-api/main.go`:

```
#16 [build 6/6] RUN CGO_ENABLED=0 go build ...          DONE 70.5s
#17 [full 2/7]  RUN apt-get update && apt-get install   CACHED
```

Keep it that way. Moving `COPY --from=build` above the toolchain `RUN`, or inserting an `ARG` or a
`COPY` of repository content before it, would put every JVM install back on the critical path of
every rebuild.

Only the first build pays for the toolchain, about a minute of apt plus the Gradle download from
`services.gradle.org`. If your Docker daemon has restricted egress, that download fails with
`curl` exit 35 and the layer never caches; `docker build --network=host` runs the build in the
daemon's network namespace and gets past it.

## Production EKS control plane and EC2 execution tier

The production reference topology keeps `synapse-api`, web, and the ordered migration Job on Amazon EKS.
Run at least two ready API replicas behind a TLS-terminating ingress. PostgreSQL and S3-compatible evidence
storage are private, externally operated dependencies rather than Helm-managed StatefulSets.

Production untrusted-tool execution does **not** run in an EKS Pod. Set the API execution posture to
`dispatch-only`, disable the chart worker with `worker.enabled=false`, and run native non-root
`synapse-worker` services in dedicated private EC2 worker subnets. [ADR 0008](../adr/0008-native-ec2-execution-tier.md)
supersedes only ADR 0005's worker-placement decision; ADR 0005 still governs the control plane and migration
order.

Set `SYNAPSE_DB_AUTO_MIGRATE=false`. The Helm pre-install/pre-upgrade migration Job uses the owner identity
and must complete before API rollout. Back up PostgreSQL and the evidence object store as a quiesced pair and
use forward-only schema migration as specified by [ADR 0007](../adr/0007-paired-backup-and-forward-only-upgrades.md).

## Kubernetes control plane

The chart is at [`deploy/helm/synapse`](https://github.com/KKloudTarus/synapse-ce/blob/main/deploy/helm/synapse/README.md).
It renders two or more APIs, web, and a migration hook while referring only to pre-existing Secrets. Production
values must disable the in-cluster worker, use digest-qualified images, set `SYNAPSE_SANDBOX_ENABLED=true` as a
fail-closed configuration invariant, and expose neither metrics nor the machine grant listener through browser
Ingress.

The grant authority is a separate machine-only API listener behind a private TLS-terminating NLB. Configure its
dedicated frontend security group, dedicated NLB subnets and fixed private addresses, ACM certificate, and
`networkPolicySourceCIDRs`. The frontend security group accepts only the native-worker security group. The pod
NetworkPolicy accepts only the dedicated NLB-subnet CIDRs on the authority backend port. Put the certificate
hostname in private Route 53 and never reuse the browser API token for this listener.

Run static validation before installation:

```bash
helm lint --strict deploy/helm/synapse -f deploy/helm/synapse/tests/production-values.yaml
helm template synapse deploy/helm/synapse -f deploy/helm/synapse/tests/production-values.yaml --kube-version 1.29.0
(cd deploy/helm/synapse && sh testdata/render_test.sh)
```

## Native worker image and rollout

`deploy/aws/staging` defines dedicated private worker subnets, an EC2 Image Builder recipe, encrypted Launch
Template, SSM-only instance role, and an Auto Scaling Group with rolling replacement and automatic rollback.
Supply governed values through ignored operator inputs: a pinned AL2023 parent image ARN, versioned RPM object
key and SHA-256 digest, worker runtime-secret ARN, private authority DNS/certificate inputs, and desired capacity.
Do not put secret payloads, AWS credentials, machine tokens, or private signing seeds in Terraform inputs or
state.

The AMI build verifies the RPM and systemd units, then runs `/opt/synapse/synapse-sandbox-check -mode=startup
-strict` as the `synapse-worker` service identity with delegated cgroup v2 and an empty capability set. Do not
route claims to an image that fails this check. The worker service has no sudo or capabilities; only the separate
root broker has the narrowly bounded namespace/firewall capabilities required by its typed protocol.

Before a rollout:

1. Run `bash packaging/tests/static.sh`, Terraform formatting/validation/static checks, and inspect a saved plan.
2. Build the AMI and record the parent AMI, resulting AMI, kernel, release, worker RPM, helper/tool, seccomp, and
   grant-public-key digests.
3. Start one disposable instance, use SSM to inspect `systemctl status` and the strict conformance result, and
   verify the broker replay journal is root-owned mode `0600` on a root-owned state directory.
4. Prove worker-to-private-NLB TLS using the certificate hostname, and prove other VPC identities cannot connect.
5. Prove the authority Pod observes only dedicated NLB-subnet sources and that browser Ingress has no authority
   route.
6. Start an ASG instance refresh. Verify a terminated worker loses its queue lease, cannot finalize through its
   stale fence, its entire tool process tree is gone, the instance is replaced, and the replacement passes strict
   conformance before claiming work. Let automatic rollback retain the previous Launch Template/AMI if a health
   check fails.

Use SSM Session Manager and `journalctl -u synapse-worker -u synapse-egress-broker`; do not add SSH ingress or a
key pair. Broker startup recovers stale namespace state before listening. Failed setup consumes its signed grant,
and replay after worker or broker restart is refused.

## Secret, key, DNS, and certificate rotation

- Rotate the dedicated worker authority bearer token independently from `SYNAPSE_API_TOKEN`. Update the governed
  worker runtime secret, roll the ASG, verify all new instances, then retire the old authority token.
- Rotate the Ed25519 grant key by adding the new public key to the AMI/broker configuration, deploying the new
  API signing seed, waiting longer than the five-minute maximum grant lifetime, and then removing the old public
  key in a second worker rollout. The private seed never enters worker secrets or Terraform state.
- Renew the ACM certificate before expiry while retaining the same private hostname, verify NLB TLS from a worker,
  and only then remove the old certificate. For a hostname change, publish and verify the private Route 53 alias
  before updating the worker authority URL.
- Rotate database, object-store, vault, and evidence credentials according to their own dual-read/dual-write
  procedures; do not bundle them into the broker environment. The broker receives only its grant public key.

## Supported network execution posture

Recon has an authoritative signed-grant issuer. Production refuses CSPM and networked SCA/acquisition until their
issuer branches can reload authoritative aggregate state and independently derive exact egress. Production API
composition omits DAST execution workflows, so authenticated DAST and verifier probes cannot start. Do not bypass
these refusals with host networking, a local privileged egress applier, a worker-supplied policy, or a broadly
reachable proxy.

## Production checklist

Required, by variable name. Any `SYNAPSE_ENV` value other than `development`, `dev`, `local`, `test`, or
`ci` is treated as production and activates the fail-closed gates:

| Variable | Requirement |
| --- | --- |
| `SYNAPSE_ENV` | Left at its production value, so the strict gates stay on |
| `SYNAPSE_API_TOKEN` | A strong random value; the server refuses to start without it |
| `SYNAPSE_DB_DSN` | Managed PostgreSQL with TLS |
| `SYNAPSE_VAULT_MASTER_KEY` | Credential-vault master key. Without it, stored secrets do not survive a restart |
| `SYNAPSE_EVIDENCE_SIGNING_SEED` | Ed25519 seed giving the evidence and audit chain a stable key ID |
| `SYNAPSE_MEASURE_CURSOR_SECRET` | HMAC key signing measure pagination cursors |
| `SYNAPSE_SANDBOX_ENABLED` | `true` on a Linux host. If set and bubblewrap is missing, startup fails closed |
| `SYNAPSE_BLOB_ENDPOINT` | Object store for evidence artifacts |

Recommended hardening:

- Give migrations a separate owner-level identity with `SYNAPSE_DB_MIGRATION_DSN`, keeping the runtime DSN
  least-privileged.
- Pin tool hashes with `SYNAPSE_TOOL_HASHES` so the sandbox refuses an unexpected binary. Empty means
  trust-on-first-use.
- Set `SYNAPSE_TSA_URL` to anchor the evidence chain externally, making it tamper-proof rather than only
  tamper-evident.
- Enable `SYNAPSE_LEADER_ENABLED` when running more than one API or worker, so scheduled dispatch runs
  exactly once.
- Terminate TLS at your load balancer or reverse proxy in front of the API.
- Back up the database and the evidence object store together; a report depends on both.

`GET /healthz` and `GET /readyz` are unauthenticated by design. Every other API route requires the bearer token.

## Migration rollout

In production, set `SYNAPSE_DB_AUTO_MIGRATE=false` and run `synapse-migrate` with the owner
credential before deploying API, worker, or MCP binaries. Design migrations as backward-compatible,
phased changes: expand first, deploy consumers second, then remove obsolete schema only after all
older consumers are gone. This migrate-first sequence permits an older API to remain serving a
forward schema only when every additional database migration is applied and has a version strictly
above that binary's embedded maximum. Missing, down, or divergent required migrations remain
unready.

The distinction is intentional: an API with a stale schema stays running but reports `503` from
`/readyz`, allowing the orchestrator to remove it from traffic. `synapse-worker` and `synapse-mcp`
have no equivalent HTTP readiness endpoint, so they refuse startup until migrations are ready.

## Metrics and access logging

`SYNAPSE_METRICS_ENABLED` (default `false`) exposes Prometheus metrics — HTTP RED
(rate/errors/duration), aggregate durable-job queue depth, and SCA scan outcomes — on a
SEPARATE listener bound by `SYNAPSE_METRICS_ADDR` (default `127.0.0.1:9090`). That
listener is intentionally uninstrumented and never bearer-protected: keep it loopback-only
or on a private scrape network, and never put it behind the same public path as the API.
See [Configuration](configuration.md#observability) for metric names and the label/privacy
policy.

`SYNAPSE_ACCESS_LOG_ENABLED` (default `true`) emits one structured `http access` log event
per request with only bounded, non-sensitive fields (method, matched route, status,
latency, request id, and — once authenticated — the resolved principal id). It never logs
raw paths, query strings, headers, bodies, tenant ids, remote addresses, user agents, or
secrets.

## Liveness and readiness probes

`GET /healthz` is a constant liveness probe: `200` means the process and HTTP listener are alive. It
does not inspect dependencies. `GET /readyz` runs the configured PostgreSQL, migration, and evidence
object-store checks concurrently with a short timeout. It returns `200` only when every check passes,
or `503` with per-check pass/fail states; dependency errors and credentials are never exposed.

In in-memory development mode no external checks are configured, so readiness follows process health.
The full Compose stack uses `/readyz` for its service health condition. Kubernetes should keep the two
signals separate:

```bash
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/readyz
```

```yaml
livenessProbe:
  httpGet: {path: /healthz, port: 8080}
readinessProbe:
  httpGet: {path: /readyz, port: 8080}
```

Next: [Security model](security.md)
