# Security Policy

## Reporting a vulnerability

We take the security of Synapse seriously. If you believe you have found a security
vulnerability, please report it responsibly.

**Please do not open a public issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:

- Go to the **Security** tab of this repository → **Report a vulnerability**.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept if possible).
- Affected version / commit.
- Any suggested remediation.

We will acknowledge your report as quickly as we can, keep you informed of progress, and
credit you in the release notes once a fix ships (unless you prefer to remain anonymous).

## Scope

In scope:

- The Synapse server, CLI, worker, and web dashboard in this repository.
- The execution sandbox, scope/authorization enforcement, credential handling, evidence
  chain-of-custody, and authorization/RBAC chokepoint.

Out of scope:

- Vulnerabilities in third-party tools Synapse shells out to (report those upstream).
- Findings that require a misconfigured deployment contrary to the documented guidance
  (for example, running with the sandbox disabled on a non-Linux host, or exposing the API
  without a token).

## Using Synapse safely

Synapse is a security-testing tool. It must only be used against systems you are explicitly
authorized to test. It enforces an engagement **scope** and a **legal authorization window**
server-side before any tool runs, but it cannot verify your legal authorization – the
operator is responsible for holding written permission.

Hardening highlights operators should preserve:

- Always set `SYNAPSE_API_TOKEN`; the server refuses anonymous access.
- Run the execution sandbox and live recon on a Linux host; they **fail closed** without
  the required kernel features rather than running unsandboxed.
- Keep secrets in the credential vault; never place them in logs or source.
- Never disable the append-only audit/evidence guarantees in production.
