# Python Tier-2 Reachability and Interprocedural Taint

Status: implementation plan; work in progress on `feat/python-tier2-taint`.

This document is the source of truth for the multi-pass implementation. It records the target
architecture, safety invariants, package boundaries, pass ordering, test strategy, and completion
criteria so that work can resume without re-deriving design decisions from individual commits.

## Outcome

Extend the shipped Python Tier-1 import signal with two deterministic, source-only capabilities:

1. **Tier-2 semantic reachability**: prove that an application entrypoint reaches an affected Python
   symbol through a statically resolved call path.
2. **Interprocedural taint**: prove a bounded source-to-sink value-flow path across assignments,
   arguments, returns, and selected attribute flows, with injection-class-aware sanitizers.

The implementation never imports or executes target Python. The existing sandboxed `synapse-ast`
tree-sitter sidecar extracts a versioned semantic-facts document. Pure Go domain and use-case code
validates, resolves, and queries those facts.

The feature is a conservative evidence producer, not a whole-program Python type checker. Uncertainty
must reduce coverage; it must never be converted into a false `not_reachable` or a false clean taint
result.

## Existing seams to preserve

- `internal/usecase/pyreach` owns shipped Tier-1 distribution-to-import analysis.
- `internal/usecase/reachproof` owns deterministic reachability judgments and tier supersession.
- `internal/domain/callgraph` owns language-neutral call-path queries.
- `internal/domain/taint` owns deterministic taint-path queries; its current call-graph assembly is a
  coarse Go MVP and remains compatible while precise value-flow is added.
- `internal/infrastructure/tools/astwalk` is the only process that links tree-sitter grammars.
- `internal/infrastructure/tools/ast` is the CGO-free adapter that invokes `synapse-ast`.
- `cmd/*` remains composition only.

## Non-negotiable invariants

### Coverage honesty

- A negative Tier-2 result is publishable only when all call-resolution facts needed for the queried
  path are complete.
- Parse errors, truncation, unreadable files, unresolved dynamic calls, wildcard imports, dynamic import
  mechanisms, `eval`/`exec`, unsupported decorators that replace callables, and budget exhaustion are
  explicit coverage gaps.
- A coverage gap causes Tier-2 to mint nothing. The shipped Tier-1 judgment remains authoritative.
- A reachable path may still be reported from a partial graph when every edge in its witness is directly
  resolved. Partial coverage can prove presence, never absence.
- An advisory without usable affected Python symbols remains at Tier-1. Distribution names must not be
  invented as callable symbols.

### Target safety

- Never run Python, import a target module, invoke a package manager, or execute build hooks.
- Parse inside the existing read-only, sandboxable AST sidecar.
- Follow no symlinks and reuse the bounded source walk.
- Bound files, bytes, nodes, symbols, call candidates, graph edges, value-flow edges, witness length, and
  serialized output.
- Wire output contains normalized relative paths and symbol/value identities, never source bodies,
  environment values, credentials, or absolute host paths.

### Determinism and evidence

- Version every sidecar wire document.
- Sort files, symbols, edges, coverage gaps, and catalog entries before serialization/querying.
- Stable identities are derived from normalized module, qualified symbol, location, and value slot—not
  traversal or map iteration order.
- Tier-2 reachability carries the shortest entrypoint-to-symbol witness.
- Taint findings remain `CapSAST` propose-only and require a distinct verifier. The deterministic engine
  must not self-confirm them.
- Evidence records only bounded symbol/location witnesses and explicit coverage metadata.

### Architecture

The dependency direction remains:

```text
domain <- usecase <- adapter / infrastructure <- cmd
```

- Tree-sitter nodes never escape `internal/infrastructure/tools/astwalk`.
- Domain packages import only the standard library and other domain packages.
- Sidecar execution is accessed through a narrow use-case port.
- External I/O stays in infrastructure.

## Semantic model

### Versioned facts document

The sidecar emits a language-specific but tool-independent document:

```text
PythonFactsDocument
  schema_version
  files[]
  modules[]
  symbols[]
  imports[]
  calls[]
  values[]
  flows[]
  entrypoint_hints[]
  coverage_gaps[]
  truncated
```

Initial symbol kinds:

- module
- class
- function
- method
- lambda (stable synthetic identity)

Initial call shapes:

- direct local/module call: `run()`
- imported symbol call: `from x import run; run()`
- module member call: `import x; x.run()`
- constructor and statically known instance method call
- `self`/`cls` method call
- selected decorator-derived framework entrypoint

Calls that cannot be resolved have an explicit reason and location. They are not silently discarded.

### Symbol identity

Canonical callable identity:

```text
python:<module>:<qualified-name>
```

Examples:

```text
python:app.api:create_user
python:app.service:UserService.save
python:django.db.models.query:QuerySet.raw
```

The `python:` prefix prevents collision with Go/JVM identities in shared graphs. Module names are derived
from the source root and Python package layout. `__init__.py` names its containing package. Paths remain a
separate evidence attribute and are never used as a replacement for a semantic identity.

### Coverage model

Coverage is first-class rather than a boolean hidden in error handling:

```text
Coverage
  complete
  gaps[] {kind, file, line, symbol, detail}
  files_seen
  files_parsed
  nodes_seen
  truncated
```

Gap details use closed, bounded reason codes. Human-readable text is produced by trusted Go code rather
than copied from source or parser diagnostics.

### Value-flow model

The precise taint path uses value slots rather than treating call edges as data flow:

- function parameter
- local binding
- return slot
- call argument
- call result
- selected object attribute
- literal/constant clean origin

Initial flow operations:

- assignment and annotated assignment
- tuple/list destructuring when arity is statically known
- return
- positional and keyword argument binding
- constructor result to statically known instance binding
- selected attribute read/write on a statically known receiver
- conservative propagation through string formatting, concatenation, containers, and comprehensions

Each sanitizer is scoped to one or more taint classes. HTML escaping cannot sanitize SQL injection;
path containment cannot sanitize SSRF.

## Package and file plan

The exact file split may evolve, but ownership must remain stable.

```text
internal/domain/pythonprogram/
  facts.go                 validated semantic facts and coverage
  identity.go              canonical modules/symbols/value slots
  graph.go                 resolved call graph and path queries
  resolver.go              pure name/scope/import resolution
  valueflow.go             precise value-flow IR

internal/domain/taint/
  typed_catalog.go         language + taint-class-aware roles
  value_graph.go           value-slot source/sink/sanitizer queries

internal/usecase/ports/
  python_analysis.go       PythonFactsProvider port and wire-independent request/result

internal/usecase/pyreach/
  tier2.go                 facts -> resolved graph -> reachability.Analysis
  symbols.go               affected-symbol normalization/matching

internal/usecase/pytaint/
  coordinator.go           facts/value flow -> propose-only CapSAST judgments
  evidence.go              bounded, normalized witness metadata

internal/infrastructure/tools/astwalk/
  python_facts.go          shared wire model helpers
  python_facts_cgo.go      tree-sitter extraction
  python_facts_nocgo.go    ErrUnavailable stub

internal/infrastructure/tools/ast/
  python.go                sidecar provider adapter

internal/infrastructure/rulecatalog/
  python_taint.go          first-party rule metadata

cmd/synapse-ast/
  main.go                  `python-facts <root>` dispatch only
```

Do not add all of these files merely to match the plan. Prefer small cohesive files once behavior exists.

## Implementation passes

All passes land on one feature branch. Each pass ends in a reviewable conventional commit and records
its validation evidence below. The final upstream submission is one PR containing the commit series.

### Pass 0 — Baseline and contract reconnaissance

- [x] Start from current `main` on a dedicated feature branch.
- [x] Record architecture, safety invariants, and pass plan.
- [x] Capture baseline focused tests for pyreach, reachproof, taint, astwalk, and AST provider.
- [x] Record baseline full build/test status and environmental skips.

Exit: the branch is reproducible and no existing behavior is unintentionally redefined.

### Pass 1 — Semantic-facts wire and extraction

- [x] Add the schema-versioned document and closed coverage-gap codes.
- [x] Add `python-facts` to `synapse-ast` and its CGO-free unavailable behavior.
- [x] Extract deterministic modules, classes, functions, methods, imports, aliases, calls, assignments,
  parameters, returns, attributes, decorators, and locations.
- [x] Detect dynamic constructs and parser errors as gaps.
- [x] Add hostile bounds, sorting, golden fixtures, malformed-source tests, and determinism tests.
- [x] Add the narrow provider port and CGO-free adapter.

Exit: a sandboxed sidecar can emit stable, bounded facts without executing Python.

### Pass 2 — Pure resolver and call graph

- [ ] Validate all sidecar facts at the trust boundary.
- [ ] Resolve lexical scopes, imports/aliases, relative imports, local functions, classes, `self`/`cls`,
  constructors, and conservative inheritance.
- [ ] Model unresolved calls and ambiguity explicitly.
- [ ] Derive framework entrypoints for Django, Flask, FastAPI, ASGI/WSGI, CLI, and conventional `main`.
- [ ] Produce the shared callgraph graph plus Python coverage metadata.
- [ ] Add shortest-path, recursion, ambiguity, shadowing, inheritance, and dynamic-dispatch tests.

Exit: pure Go resolution can prove positive paths and distinguish complete negatives from unknowns.

### Pass 3 — Tier-2 reachability integration

- [ ] Normalize Python affected symbols without guessing when advisory symbol data is absent.
- [ ] Add a Tier-2 analyzer alongside existing Tier-1 pyreach.
- [ ] Reuse reachproof supersession so Tier-2 replaces Tier-1 append-only.
- [ ] On complete negative coverage, mint Tier-2 `not_reachable`; on gaps, keep Tier-1.
- [ ] Seal bounded call-path and entrypoint evidence.
- [ ] Wire configuration and API/CLI/worker composition roots.
- [ ] Add SCA-to-judgment-to-OpenVEX end-to-end tests.

Exit: Python findings with affected symbols receive honest Tier-2 judgments.

### Pass 4 — Interprocedural value-flow engine

- [ ] Build value slots and intra-function flows from facts.
- [ ] Bind positional/keyword arguments and return values across resolved calls.
- [ ] Add bounded function summaries, recursion/fixpoint handling, and deterministic convergence.
- [ ] Add typed source, sink, propagator, and sanitizer roles.
- [ ] Preserve the existing coarse Go taint behavior and tests.
- [ ] Add witness paths carrying relative file:line evidence.
- [ ] Add tests for sibling calls, sanitizer class separation, return propagation, keyword arguments,
  methods, recursion, and unsupported shapes.

Exit: value flow—not mere call adjacency—drives Python taint candidates.

### Pass 5 — Framework catalog and proposed findings

- [ ] Add Flask, Django, and FastAPI request sources.
- [ ] Add SQLAlchemy/Django DB/raw SQL sinks.
- [ ] Add subprocess/OS command, path, SSRF, template/XSS, deserialization, and redirect sinks.
- [ ] Add class-specific sanitizers and safe API shapes.
- [ ] Create complete first-party catalog metadata and golden compliant/noncompliant examples.
- [ ] Propose `CapSAST` judgments only; never self-confirm.
- [ ] Add deduplication and bounded audit evidence.

Exit: the supported framework matrix produces reviewable, evidence-backed proposed findings.

### Pass 6 — Product integration and hardening

- [ ] Expose coverage summaries without treating unsupported code as clean.
- [ ] Add SARIF/finding metadata needed to display source-to-sink witnesses.
- [ ] Document flags, tiers, limitations, and operational sidecar requirements.
- [ ] Add changelog entry.
- [ ] Add architecture dependency tests and hostile harness cases.
- [ ] Add corpus benchmarks with explicit precision/recall and coverage metrics.
- [ ] Run build, vet, tests, lint/typecheck, web build, CGO-on sidecar tests, and CGO-off compilation.

Exit: all public behavior, safety boundaries, and release gates are documented and green.

### Pass 7 — Final branch review and one upstream PR

- [ ] Rebase/merge current upstream `main` and resolve migration/config drift.
- [ ] Review diff for secrets, shell execution, absolute paths, unbounded data, architecture violations,
  accidental generated artifacts, and unrelated changes.
- [ ] Ensure commits remain logically reviewable while the PR is one unit.
- [ ] Push `feat/python-tier2-taint` to the fork.
- [ ] Open one PR to `KKloudTarus/synapse-ce:main` with architecture, threat model, coverage semantics,
  test evidence, limitations, and rollout plan.

Exit: one complete upstream PR is open from the fork branch.

## Test matrix

### Unit

- Fact validation and identity normalization.
- Module/import/scope/call resolution.
- Coverage-gap propagation.
- Call-path determinism.
- Value-flow propagation and sanitizer-class separation.
- Catalog integrity and stable rule keys.

### Golden parser fixtures

- Plain modules and packages.
- Relative imports and aliases.
- Nested functions, lambdas, classes, inheritance, async functions.
- Flask/Django/FastAPI routes and dependency injection.
- Syntax errors and partially valid files.
- Dynamic imports, wildcard imports, `eval`, `exec`, monkey patching, and decorators.
- Oversized/deep/hostile syntax trees.

### Integration

- Sidecar provider round trip with CGO.
- CGO-free sidecar returns unavailable rather than a false empty graph.
- Sandbox receives a read-only target and argv-only invocation.
- Tier-1 remains when Tier-2 has a gap.
- Tier-2 supersedes Tier-1 append-only when proof is complete.
- Proposed taint judgment cannot self-confirm.

### End to end

- PyPI finding with affected symbol -> reached framework route -> Tier-2 reachable witness.
- PyPI finding with affected symbol -> complete graph with no path -> Tier-2 not reachable.
- Same project with dynamic behavior -> no Tier-2 negative; Tier-1 stands.
- Request source -> interprocedural SQL/command/SSRF sink -> proposed SAST judgment + bounded evidence.
- Correct class-specific sanitizer -> no candidate for that class, without suppressing another class.

## Validation log

Append one row at the end of every implementation pass.

| Pass | Commit | Focused tests | Full gates | Notes |
| --- | --- | --- | --- | --- |
| 0 | `20b77fc` | Focused seam tests pass | `go build ./cmd/...` passes; `go test ./...` has four pre-existing Windows/baseline test failures | Plan created from `bf7dad4`. Failures: private-file ACL in `cmd/synapse-fptriage-release`, owner-controlled replay directory in `internal/infrastructure/egressbroker`, and two telemetry failure-matrix assertions in `test/e2e`. |
| 1 | `feat:python-semantic-facts` | Domain, provider, CGO-free astwalk/ports tests pass | `go build ./cmd/...` and `CGO_ENABLED=0 go build ./cmd/synapse-ast` pass | CGO golden fixtures were added but cannot execute on this workstation because no C compiler is installed; CI must run them with CGO enabled. Coverage-aware walking reports skipped Python candidates instead of silently permitting a negative proof. |

## Definition of done

The feature is complete only when all of the following hold:

- Tier-2 positive and negative semantics are coverage-honest and tested end to end.
- Unsupported/dynamic Python never creates a false negative.
- Taint uses interprocedural value flow with class-aware sanitizers.
- Target Python is never executed.
- All sidecar input/output is bounded, deterministic, and free of source/secrets/absolute paths.
- Existing Go taint, Python Tier-1, JS reachability, JVM reachability, and judgment behavior remain green.
- CGO-on and CGO-off builds behave as documented.
- Full repository gates pass, aside from explicitly documented environment-only skips.
- Documentation and changelog describe shipped behavior and limitations.
- The fork branch is pushed and one upstream PR contains the complete reviewed commit series.
