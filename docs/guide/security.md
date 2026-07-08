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

## Authorization is your responsibility

Synapse validates scope data but cannot verify legal authorization. The operator is responsible
for holding written permission to test any target. Use it only against systems you are
explicitly authorized to test.

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use GitHub's private
vulnerability reporting on the repository (Security tab, Report a vulnerability). See
[SECURITY.md](https://github.com/KKloudTarus/synapse-ce/blob/main/SECURITY.md) for details.
