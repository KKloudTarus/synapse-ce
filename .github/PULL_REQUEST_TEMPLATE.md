## Summary

<!-- What does this change and why? -->

## Changes

<!-- Bullet the key changes. -->

## Checklist

- [ ] `make build vet test typecheck` passes
- [ ] `cd web && pnpm build` passes (if the dashboard changed)
- [ ] Tests added/updated for new behavior
- [ ] Preserves the safety invariants (argv exec, server-side scope enforcement, secrets
      out of logs, deterministic reports, append-only evidence) – see CONTRIBUTING.md

### Documentation

Drift guards run in `make test`, so these usually fail loudly rather than silently. Confirm anyway:

- [ ] New or changed `SYNAPSE_*` variables are in `docs/guide/configuration.md`, and
      security-relevant ones state the risk of a careless value
- [ ] New or changed CLI flags, subcommands, and exit codes are in `docs/guide/cli.md`
- [ ] New HTTP routes are described in `api/openapi.yaml` (do not grow
      `api/testdata/openapi-coverage-debt.txt`)
- [ ] New guides are in `mkdocs.yml` nav, so the site actually publishes them
- [ ] Claims match shipped behavior: no unbuilt artifact, unimplemented setting, or
      ingest-only format described as an export
- [ ] Screenshots retaken if the documented UI changed, with no tokens, keys, or real
      customer data captured
