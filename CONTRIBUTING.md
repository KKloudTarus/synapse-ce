# Contributing to Synapse

Thanks for your interest in improving Synapse! This document explains how to get set up and
what we expect from contributions.

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

If a change would weaken any of these, please open an issue to discuss first.

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
- Include tests for new behavior.
- Ensure `make build vet test typecheck` and `cd web && pnpm build` pass.
- Use clear, conventional commit messages (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`).
- For a user-visible change, add an entry under the `Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
