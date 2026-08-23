# ADR 0008 — Native EC2 execution tier

**Status:** Accepted · **Date:** 2026-08-22 · **Deciders:** Issues #589 and #591

## Context

[ADR 0005](0005-production-helm-eks-topology.md) selected EKS for the production control plane and placed
execution workers in a separate Deployment. Standard EKS nodes did not provide a reliable positive path for
the exact nested Bubblewrap namespace, mount, seccomp, and cgroup boundary without granting unacceptable
container privileges. Production must not compensate with `privileged: true`, broad `SYS_ADMIN`, unrestricted
sudo, host namespaces, or an unsandboxed fallback.

The API also needs an authorization boundary that a compromised worker cannot forge. Network access for an
untrusted process must be derived again from live control-plane state and bound to the exact Bubblewrap process
and network namespace before that process starts.

## Decision

ADR 0005 remains authoritative for the API, web, migration, database, object-store, and ingress topology. This
ADR supersedes only its execution-worker placement decision:

- Keep `synapse-api`, web, and the ordered migration Job on EKS. Production APIs run in `dispatch-only` posture
  and cannot instantiate local untrusted-tool runners.
- Run native, non-root `synapse-worker` processes under systemd in a private EC2 Auto Scaling Group. Instances
  have no public IP, SSH key, or inbound application port; operators use SSM. The launch image is produced by
  EC2 Image Builder from a governed parent AMI and installs a digest-pinned worker RPM.
- `synapse-worker.service` has an empty capability set, `NoNewPrivileges=true`, and delegated cgroup v2. Its
  `ExecStartPre` invokes the same strict sandbox runner used by tools. A failed exact-runner check prevents queue
  claims.
- A separate root-owned broker may administer only per-run network namespaces and firewall rules. It exposes a
  typed Unix-socket protocol with no command or argv fields, authenticates the worker and Bubblewrap process,
  and retains the authenticated namespace file descriptor. Its bounding set includes `SYS_PTRACE` and
  `DAC_READ_SEARCH` only for read-only cross-UID procfs inspection of the executable, namespaces, and inherited
  block pipe; `KILL` remains absent and pidfd liveness is poll-based. The worker receives no `NET_ADMIN`,
  `SYS_ADMIN`, sudo, or direct firewall command access.
- Networked execution requires a short-lived Ed25519 grant from a separate machine-only API listener. The issuer
  reloads authoritative tenant, execution, engagement, authorization-window, scope, rules-of-engagement, and tool
  state; independently derives canonical IPv4 CIDR/port rules; and signs tenant, execution kind/id, broker run,
  namespace slot, Bubblewrap PID, exact rules, and expiry. The broker holds only the public verification key.
- The broker fsyncs an append-only replay journal before privileged mutation. A failed setup burns its grant;
  malformed, insecure, or uncertain journal state blocks startup. Broker restart removes stale namespace state
  before accepting requests.
- The authority uses a dedicated internal TLS NLB. Its frontend security group accepts TCP/443 only from the
  native-worker security group; its egress reaches only the EKS backend port. Dedicated NLB subnet CIDRs form
  the pod NetworkPolicy source boundary. The listener is never exposed by browser Ingress and applies an
  authenticated request limit in addition to upstream NLB and security-group controls.
- Only execution kinds with a trusted issuer branch may request network access. Recon is supported. Production
  CSPM, networked SCA/acquisition, authenticated DAST, and DAST verifier execution fail at startup or composition
  until each has an authoritative aggregate and independent policy-derivation branch. An execution-kind string
  carried by a worker is not authorization.

## Consequences

- Production Helm values disable the in-cluster worker. Development may retain it, but it is not production
  evidence for the exact runner.
- Releases must publish the worker package digest, AMI/kernel/release/tool/seccomp-policy digests, grant public
  key, and strict conformance result. Instance refresh rolls forward only after image tests pass and may
  automatically roll back.
- Operations require coordinated rotation of the worker machine token, grant signing key pair, private TLS
  certificate, DNS alias, and worker runtime secret. The signing seed remains only in the trusted control plane.
- Production acceptance must terminate a worker during execution and prove lease fencing, process-tree cleanup,
  ASG replacement, broker recovery, replay refusal, and a subsequent healthy run.
- This topology adds an EC2 and systemd operational surface, but keeps privileged namespace administration out of
  the worker and keeps untrusted execution out of the API and Kubernetes Pods.
