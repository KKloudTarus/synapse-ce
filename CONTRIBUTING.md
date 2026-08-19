# Contributing to Synapse

Thanks for your interest in improving Synapse! This document explains how to get set up and
what we expect from contributions.

## Maintainers & review

Synapse is stewarded by its founding team. Pull requests are reviewed strictly against the
architecture rules and safety invariants below; expect a maintainer to ask for changes until
they hold.

- **Founder:** [@nghiadaulau](https://github.com/nghiadaulau) · **Co-founder:** [@nnatuan03](https://github.com/nnatuan03)
- **Lead maintainer:** [@pho-veteran](https://github.com/pho-veteran) — primary reviewer/merger
- Engineers, designer, and AI-engineer contributors are credited in the [README](README.md#team--contributors).

## Getting started

1. Fork the repository and create a feature branch off `main`.
2. Install prerequisites: Go 1.26, Node + pnpm, and the external scan tools (`make tools`).
3. Build and test:

   ```bash
   make build
   make test
   make vet
   make typecheck        # go vet + web tsc --noEmit
   cd web && pnpm build  # verify the dashboard builds
   ```

## Architecture rules (please read before large changes)

Synapse follows clean architecture with a strict, inward-only dependency rule:

```
domain  ←  usecase  ←  adapter / infrastructure
```

- `internal/domain/*` imports only `domain` + the standard library – no frameworks, DB, or
  tools. The sole sanctioned exception is the pure-Go `golang.org/x/net/idna` package used for
  standards-based canonical domain identity; this does not permit other third-party domain dependencies.
- `internal/usecase/*` imports `domain` and `usecase/ports` (interfaces) – never a concrete
  adapter or infrastructure package.
- All external I/O (database, tools, storage, sandbox) goes through **ports** in
  `internal/usecase/ports`.
- `cmd/*` is the composition root – dependency injection only, no business logic.

## Safety invariants (non-negotiable)

Synapse is a security tool. Changes must preserve these:

1. **Execute tools via `argv` arrays – never a shell string.** No user/target input is ever
   concatenated into a command.
2. **Enforce scope + the authorization window in the execution layer**, server-side, before
   any tool runs.
3. **Secrets never enter logs, transcripts, or source.** Use the credential vault + server-side
   placeholder substitution.
4. **Reports are templated from stored data** – deterministic, reproducible.
5. **Evidence and audit logs are append-only** and hash-chained; a broken chain blocks the
   report.
6. **Tenant-scoped tables carry `tenant_id` + Postgres RLS** (`synapse_enable_tenant_rls`) and are
   reached through a `WithTenant` transaction; global reference data (e.g. `advisories`) is the
   deliberate exception. Cross-tenant access must be rejected by the hostile harness.

If a change would weaken any of these, please open an issue to discuss first.

## Database migrations

Migrations are numbered SQL files in `migrations/`, embedded and **auto-applied at startup via
goose**. Two rules avoid the duplicate-version startup crash goose raises on collisions:

- **Append a new numbered file — never edit or renumber a shipped migration.** Take the next
  free number after the current maximum on `main` at PR time; if two PRs race for the same number,
  the later one rebases and renumbers. goose keys on the leading integer, so a duplicate is a
  hard startup panic, not a git merge conflict (the filenames differ), and a clean merge will not
  catch it.
- **Use backward-compatible, phased schema changes.** Production rollouts migrate first, then
  deploy application binaries. During that overlap an older API may serve only a database whose
  additional migration versions are applied and strictly newer than its embedded maximum; it must
  not depend on columns or constraints removed by the migration.
- **Add a Postgres integration test** (`migration_00NN_test.go`) that calls `postgres.Migrate`,
  so a broken or duplicate version is caught locally.

## Coding conventions

**Go:**
- Wrap errors with `%w` and context: `fmt.Errorf("generate sbom: %w", err)`.
- `context.Context` is the first parameter of any I/O method and is honored.
- Each adapter declares a compile-time port assertion: `var _ ports.X = (*Impl)(nil)`.
- `New...` constructors validate and return `(*T, error)`. Keep the domain pure.
- No `panic` in library code, no global mutable state. Tests are table-driven `_test.go`.
- Run `gofmt` (`make format`) before committing.

**Frontend (`web/`):**
- Use **pnpm**, never npm/yarn.
- Style via the design-system tokens in `web/src/index.css` – no raw hex in components.
- Icons: `lucide-react`. Always handle loading/empty/error states.

## Pull requests

- Keep PRs focused; describe the change and its rationale.
- Include tests for new behavior. Security- or execution-sensitive changes should also pass the
  hostile harness (`TestHostileHarness` in `internal/adapter/httpapi/harness_test.go`); persistence
  changes should include real-Postgres integration tests run with `SYNAPSE_TEST_DB_DSN` set.
- Ensure `make build vet test typecheck` and `cd web && pnpm build` pass.
- Use clear, conventional commit messages (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`).
- For a user-visible change, add an entry under the `Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
