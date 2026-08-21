# Security model

[Documentation home](README.md) · Previous: [Deployment](deployment.md)

Synapse is a security tool, so its own safety model matters. These invariants are enforced in
code, not in prompts or documentation.

## Safety invariants

1. **Execute tools via argv arrays.** Tools are run with argument arrays, never a shell string.
   No target, agent, or user input is concatenated into a command. This closes the door on
   command injection through a scan target.
2. **Enforce scope and the authorization window in the execution layer.** Both are checked
   server-side, before any tool runs. This is a real chokepoint, not a single skippable hook.
3. **Secrets never enter logs, the transcript, or source.** A credential vault holds them, and
   server-side placeholder substitution keeps them out of everything a tool or a model sees.
   A shared redactor is a second line of defense on any output path.
4. **AI orchestration is a typed Go state machine.** The model proposes structured tool calls.
   Go validates and executes them. Control flow is not driven by prompts.
5. **Reports are templated from stored data.** No model sits in the report path. Analysis
   claims promote only through the judgment lifecycle, and gated capabilities need a distinct
   verifier's sealed verdict. Evidence is hash-chained. A mismatch blocks the report.
6. **The audit log is append-only.** Every action is attributable to a person or an agent id.

## Fail-closed posture

When a required capability is missing, Synapse refuses rather than degrading silently.

- No `SYNAPSE_API_TOKEN` means the server does not start. There is no anonymous access.
- The sandbox requested but bubblewrap unavailable means startup fails, rather than running
  tools unsandboxed.
- A production environment without the vault key or signing seed fails to start.
- A verification error on the evidence chain blocks the report.

## Access control

Per-action role-based access control runs through a single authorization chokepoint. Roles are
admin, consultant, reviewer, and read-only. Separation of duties means a machine identity can
never verify or accept its own claim. Tenant isolation is enforced at the service layer, so a
caller cannot read another tenant's engagement even if a route wrapper is bypassed.

## Browser OIDC access

Browser OIDC uses a backend-for-frontend model. The server accepts an identity only for an exact approved
issuer and subject pair, assigns it to the deployment's fixed tenant, and maps it only to the existing
allowlisted roles: `admin`, `consultant`, `reviewer`, and `read-only`. It stores the authenticated browser
state in an opaque, replica-safe server-side session and requires a session-bound CSRF token for every
state-changing request. Existing bearer-token machine authentication is unchanged. See
[ADR 0006](https://github.com/KKloudTarus/synapse-ce/blob/main/docs/adr/0006-oidc-bff-trust-model.md).

## Authorization is your responsibility

Synapse validates scope data but cannot verify legal authorization. The operator is responsible
for holding written permission to test any target. Use it only against systems you are
explicitly authorized to test.

## Offensive actions

Anything Synapse executes **against a target** is additionally governed by the offensive governance
policy in [`docs/redteam/offensive-policy.md`](https://github.com/KKloudTarus/synapse-ce/blob/main/docs/redteam/offensive-policy.md).
It is not published on this site because it is a repository artifact that CI verifies against the
machine-readable register the code enforces — the two must change together, so the reviewed text lives
next to the register rather than in the docs build.

What it settles, and what the three controls above do not:

- The categories Synapse **will not** execute at all: denial of service, destructive actions,
  exfiltration beyond a bounded proof sample, unauthorised persistence, out-of-scope lateral movement
  and third-party impact.
- Per-technique risk classification, and which class needs automatic, single or **dual** human approval.
- The rules-of-engagement fields an engagement must carry first. A missing field is a refusal.
- The kill switch: `POST /api/v1/redteam/halt` cancels all in-flight offensive work, audited with the
  operator and reason. Its stated bound covers the control plane; a technique already running on a host
  stops within one further agent poll interval.

**A technique with no register entry is refused.** The register is an allowlist.

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use GitHub's private
vulnerability reporting on the repository (Security tab, Report a vulnerability). See
[SECURITY.md](https://github.com/KKloudTarus/synapse-ce/blob/main/SECURITY.md) for details.
