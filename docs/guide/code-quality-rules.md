# Code Quality Rules — authoring guide

[Documentation home](README.md) · Previous: [Features](features.md) · Next: [Configuration](configuration.md)

This guide is for contributors adding or reviewing **code-quality rules**. Synapse's code-quality
engine (see the [Features](features.md) guide) turns parsed source into `Kind=quality` /
`Kind=reliability` findings and the A–E ratings. Each language ships a built-in **"Synapse way"**
quality profile — **generated automatically from the catalog rules for that language** (every rule whose
`Language` matches, at its default severity). This page defines how those rules are modelled, how they
are authored, and the authoritative sources each language draws on.

Tracking epic: [Code Quality as a product](https://github.com/KKloudTarus/synapse-ce/issues/174) ·
language rule-pack tracker: [#185](https://github.com/KKloudTarus/synapse-ce/issues/185).

## Clean-room policy (non-negotiable)

We author **100% of our rule content ourselves**. We survey prior art — the public rule taxonomies of
mature analyzers, and each language's own linters — to understand *structure and coverage*, never to
copy. Specifically:

- **Do** derive rules from a language's **authoritative, openly-published** sources: official style
  guides, the language team's own tooling (`go vet`, Clippy, Roslyn analyzers, …), [CWE](https://cwe.mitre.org/),
  [OWASP](https://owasp.org/), [SEI CERT](https://wiki.sei.cmu.edu/confluence/display/seccode) secure-coding
  standards, and [ISO/IEC 25010](https://www.iso.org/standard/78176.html) software-quality attributes.
- **Do** write our own rule title, description, rationale, remediation, and code examples, and our own
  detection (AST query, structured parser check, token/line pattern, or metric threshold).
- **Do not** copy any third-party rule's text, description, examples, or detection code, and **do not**
  attribute our rules to a specific commercial product. Cite the *concept's* origin (a CWE id, a
  style-guide section, a linter category) — not another tool's rule prose.

When a rule maps to a well-known weakness, cite the **CWE** (e.g. `CWE-89` for SQL injection). When it
maps to a language idiom, cite the **style-guide section** or the **linter category** it belongs to.

## Taxonomy

Every rule carries a **type**, an impacted **software quality**, and a **severity**.

**Type** (what kind of problem):

| Type | Meaning |
| --- | --- |
| `bug` | Code that is or will be wrong at runtime (a defect). |
| `vulnerability` | A security weakness that is exploitable as written. |
| `code_smell` | Maintainability issue — correct today, costly to change. |
| `security_hotspot` | Security-sensitive code that **needs human review** (not asserted exploitable). |

**Software quality** (which rating it moves — from ISO/IEC 25010; a rule may touch more than one):
**Security**, **Reliability**, **Maintainability**. This is how a rule feeds the A–E ratings — every
new rule declares the quality it impacts so the rating engine stays honest.

**Severity** (Synapse's own scale — do not fork it): `critical` · `high` · `medium` · `low` · `info`.

`security_hotspot` findings flow through the **review workflow** (To review → Acknowledged / Fixed /
Safe), not the exploitability gate — see the hotspots issue
[#179](https://github.com/KKloudTarus/synapse-ce/issues/179).

## Depth: parity targets + rule categories

A serious code-quality profile carries **hundreds** of rules per major language, not a dozen. Our
built-in profiles target real parity with mature analyzers. A flat list of 300+ rules is unmaintainable,
so every language pack is planned as a set of **rule categories (families)**, each with a target count
that sums to the language's parity target. Contributors claim a *category* within a language and fill it
out; reviewers check the family is complete, not just that "some rules exist".

**Standard rule families** (apply across languages; a language issue distributes its target across these):

| Family | Covers | Typical types |
| --- | --- | --- |
| `bugs` | logic/correctness defects (wrong comparisons, off-by-one, always-true conditions, unreachable code) | bug |
| `err` | exception & error handling (swallowed errors, over-broad catch, error in finally) | bug, code_smell |
| `res` | resource & memory management (unclosed handles, leaks, use-after-free, double-free) | bug |
| `conc` | concurrency / async (races, deadlock shapes, unawaited promises, goroutine leaks) | bug |
| `inj` | injection & untrusted input (SQLi, command, path traversal, XXE, deserialization, SSRF, XSS) | vulnerability |
| `crypto` | cryptography & secrets (weak hash/cipher, hardcoded keys, bad randomness, TLS misconfig) | vulnerability, security_hotspot |
| `authz` | authentication / session / access control | vulnerability, security_hotspot |
| `hotspot` | security-sensitive code to **review** (not asserted exploitable) | security_hotspot |
| `api` | library/contract misuse (deprecated/dangerous API, wrong arguments, misused stdlib) | bug, code_smell |
| `types` | type & null safety (null deref, unchecked casts, narrowing, `any`) | bug, code_smell |
| `perf` | performance anti-patterns (allocation in loops, needless copies) | code_smell |
| `maint` | maintainability: cyclomatic/cognitive complexity, size, duplication, dead/redundant code, naming, comments, docs, modernization, test smells | code_smell |

Each language issue carries a **category-count table** (family → target) whose total is the language's
parity target. Ship a family at a time; each rule still needs metadata + a compliant/non-compliant golden
test (see the workflow below).

## Rule schema

Rules are catalogued as first-class entities (see [#182](https://github.com/KKloudTarus/synapse-ce/issues/182)):

```
Rule {
  Key            // stable, opaque. Namespace by analyzer domain. Existing IDs never renamed.
  Name           // short human title
  Language       // explicit user-facing language ("Go", "Python", etc.). Never parsed from Key.
  Type           // bug | vulnerability | code_smell | security_hotspot
  Qualities[]    // security | reliability | maintainability
  DefaultSeverity// critical | high | medium | low | info
  Tags[]         // free-form discovery tags
  CWE[] / OWASP[]// when security-relevant
  Description    // what it flags (our own words)
  Rationale      // why it matters (cite the concept origin + a source link)
  Remediation    // how to fix
  CompliantExample    // compliant code example
  NoncompliantExample // non-compliant code example
  RemediationEffort // minutes, for the tech-debt measure
  Detection      // ast | parse | pattern | metric
}
```

## Detection & the parser

Detection is one of: an **AST query** (via the sandboxed `synapse-ast` sidecar, tree-sitter), a
**structured parser check**, a **token/line pattern**, or a **metric threshold** (complexity, size,
duplication). Prefer AST rules where a grammar exists.

The sidecar parses, via bundled tree-sitter grammars, **Python, JavaScript, Java, Go, C, C++, C#, Rust,
Ruby, PHP, Scala, Swift, Kotlin, CSS, and HTML** (registered in `internal/infrastructure/tools/astwalk`;
each grammar's function/complexity node types are verified by `parse_langs_cgo_test.go`). go-enry
supplies line counts for many more. A language whose grammar is registered is ready for AST rule
authoring — only **VB.NET** still lacks a bundled grammar (author its rules as token/line patterns, or
reuse the C# .NET rule *concepts*). Structured-config languages (Docker, CloudFormation, Terraform,
Kubernetes, Azure Resource Manager) use the misconfig analyzer, and XML/Secrets/Text use token/parse —
none needs a grammar. The matrix below records each language's parser status.

## Authoring workflow

1. Pick the language's authoritative sources (matrix below) and enumerate rule *ideas* by category:
   correctness/bugs, security, maintainability/smells, and style-with-substance.
2. For each rule, write the schema fields **from scratch**, with a concrete **source link** in the
   rationale, and a compliant + non-compliant example.
3. Implement detection (AST query preferred) and add a **golden test** per rule: a fixture that must
   flag and one that must not.
4. Catalogue the rule ([#182](https://github.com/KKloudTarus/synapse-ce/issues/182)) with its
   `Language` set. That is all that is required to ship it: the built-in **"Synapse way (<language>)"**
   profile is generated from the catalog, so a correctly-`Language`-tagged rule is automatically active
   in that language's default profile ([#183](https://github.com/KKloudTarus/synapse-ce/issues/183)),
   browsable in the Rules explorer, and gate-eligible ([#184](https://github.com/KKloudTarus/synapse-ce/issues/184)).

## Built-in profiles, custom profiles & the gate

How a rule flows from the catalogue to an enforced gate result (the shipped
[#182](https://github.com/KKloudTarus/synapse-ce/issues/182)/[#183](https://github.com/KKloudTarus/synapse-ce/issues/183)/[#184](https://github.com/KKloudTarus/synapse-ce/issues/184)
plumbing):

- **Built-in profile (generated, immutable).** For each language, `qualityprofile.BuiltIn` activates
  every catalog rule for that `Language` at its default severity, under the key `synapse-way-<slug>`. It
  is never stored and never edited — it always reflects the current catalogue.
- **Custom profile (copy, editable).** A user copies a built-in into a tenant-scoped custom profile,
  then **deactivates** rules or **overrides** severities. Deactivating/overriding is `PermOperate`-gated
  and audited; it never touches SCA advisory findings (a profile can only affect first-party catalog
  rules, so it can't suppress a dependency vulnerability).
- **Assignment.** A profile is assigned per language per project. At analysis time the assigned profiles
  are resolved into one overlay that drops deactivated rules and applies severity overrides before the
  findings are classified, rated, and gated — so **analyses honor the assigned profile**.
- **Gate.** Metrics feed the Quality Gate ([#184](https://github.com/KKloudTarus/synapse-ce/issues/184)):
  the whole-codebase and Clean-as-You-Code (`new_*`) counts, ratings, hotspots-reviewed, and the
  coverage/duplication metrics (`coverage`, `new_coverage`, `duplication_density`, `new_duplication`).

The acceptance invariant — *every shipped language has a non-empty built-in profile* — is enforced by a
test over the real catalogue (`internal/infrastructure/rulecatalog` → `qualityprofile.BuiltIn` per
language), so adding the first rule for a new language automatically gives it a "Synapse way" profile.

## Language source matrix

**Parity targets.** These are our own built-in-profile targets, set to match the depth of a mature
analyzer's default profile (not a token seed). Each language issue decomposes its target across the rule
families above. Ship families incrementally toward the target; every rule is clean-room + golden-tested.

| Language | Parity target (rules) | Notes |
| --- | --- | --- |
| Java | ~450 | broadest surface; concurrency + API misuse heavy |
| JavaScript/TypeScript | ~400 | one pack; shared JS rules + TS-only type rules |
| C# | ~300 | + VB.NET later shares much of the catalog |
| Python | ~300 | dynamic-language bug + API-misuse heavy |
| C++ | ~180 | memory/resource + object-lifetime heavy |
| C | ~120 | memory safety + CERT C core |
| Rust | ~80 | Clippy-category coverage + unsafe/security |
| Node.js | ~50 | server-side security subset (complements JS/TS) |
| Go | ~40 | correctness + concurrency + gosec-class security |
| PHP | ~180 | web-app security + typing |
| VB.NET | ~140 | shares most of the C# catalog |
| Kotlin | ~130 | JVM + Android; nullability + coroutines |
| Swift | ~120 | iOS/macOS; optionals + memory |
| Terraform | ~60 | multi-cloud (AWS/Azure/GCP) misconfig |
| HTML | ~50 | correctness + accessibility (WCAG) |
| Secrets | ~40 | credential detectors (extends the existing scanner) |
| Ruby | ~40 | Rails security (Brakeman-class) + style |
| Scala | ~40 | JVM + functional idioms |
| ARM | ~35 | cloud misconfig |
| CSS | ~30 | correctness + maintainability |
| Docker | ~30 | image hardening + hygiene |
| Kubernetes | ~30 | manifest hardening (Pod Security Standards) |
| CloudFormation | ~30 | cloud misconfig |
| XML | ~30 | XXE + schema/well-formedness |
| IPython Notebooks | +~15 | notebook-specific (reuses the Python pack over cells) |
| Text | ~8 | any-file: bidi-unicode, BOM, generic secrets |
| Flex | deferred | legacy ActionScript — low priority |

Every source below is openly published; cite the concept origin per rule.

| Language | Detection | Parser status | Authoritative sources |
| --- | --- | --- | --- |
| **Go** | AST + pattern | ready (tree-sitter) | [Effective Go](https://go.dev/doc/effective_go), [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments), [`go vet`](https://pkg.go.dev/cmd/vet), [Staticcheck checks](https://staticcheck.dev/docs/checks/), [gosec](https://github.com/securego/gosec), [CWE](https://cwe.mitre.org/) |
| **Python** | AST (today) | ready | [PEP 8](https://peps.python.org/pep-0008/), [Ruff rules](https://docs.astral.sh/ruff/rules/), [Pylint checks](https://pylint.readthedocs.io/en/stable/user_guide/messages/messages_overview.html), [Bandit plugins](https://bandit.readthedocs.io/en/latest/plugins/index.html), [CWE](https://cwe.mitre.org/) |
| **JavaScript/TypeScript** | AST (JS today) | needs TS grammar | [ESLint rules](https://eslint.org/docs/latest/rules/), [typescript-eslint rules](https://typescript-eslint.io/rules/), [MDN JS](https://developer.mozilla.org/en-US/docs/Web/JavaScript), [CWE](https://cwe.mitre.org/) |
| **Node.js** | AST (JS) + pattern | needs TS grammar for TS | [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html), [Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html), [Node.js security best practices](https://nodejs.org/en/learn/getting-started/security-best-practices), [NPM Security](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html), [CWE](https://cwe.mitre.org/) |
| **Java** | AST (today) | ready | [Google Java Style](https://google.github.io/styleguide/javaguide.html), [Error Prone bug patterns](https://errorprone.info/bugpatterns), [SpotBugs descriptions](https://spotbugs.readthedocs.io/en/stable/bugDescriptions.html), [SEI CERT Oracle (Java)](https://wiki.sei.cmu.edu/confluence/display/java), [CWE](https://cwe.mitre.org/) |
| **C#** | AST | ready (tree-sitter) | [.NET code-quality rules](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/), [StyleCop Analyzers](https://github.com/DotNetAnalyzers/StyleCopAnalyzers), [.NET secure coding](https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines), [CWE](https://cwe.mitre.org/) |
| **Rust** | AST | ready (tree-sitter) | [Clippy lints](https://rust-lang.github.io/rust-clippy/master/) ([book](https://doc.rust-lang.org/clippy/)), [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/), [RustSec advisories](https://rustsec.org/), [CWE](https://cwe.mitre.org/) |
| **C** | AST | ready (tree-sitter) | [SEI CERT C](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard), [clang-tidy checks](https://clang.llvm.org/extra/clang-tidy/checks/list.html), [Cppcheck](https://cppcheck.sourceforge.io/), [CWE](https://cwe.mitre.org/) |
| **C++** | AST | ready (tree-sitter) | [SEI CERT C++](https://cmu-sei.github.io/secure-coding-standards/sei-cert-cpp-coding-standard/), [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines), [clang-tidy checks](https://clang.llvm.org/extra/clang-tidy/checks/list.html), [CWE](https://cwe.mitre.org/) |
| **CSS** | AST/token | ready (tree-sitter) | [W3C CSS specs](https://www.w3.org/Style/CSS/specs.en.html), [MDN CSS](https://developer.mozilla.org/en-US/docs/Web/CSS), [Stylelint rules](https://stylelint.io/rules/) |
| **Docker** | config analyzer | ready (misconfig) | [Dockerfile best practices](https://docs.docker.com/build/building/best-practices/), [Hadolint rules](https://github.com/hadolint/hadolint#rules), [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker), [CWE](https://cwe.mitre.org/) |
| **CloudFormation** | config analyzer | ready (misconfig) | [AWS Well-Architected](https://aws.amazon.com/architecture/well-architected/), [cfn-lint rules](https://github.com/aws-cloudformation/cfn-lint/blob/main/docs/rules.md), [CIS AWS Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services), [CWE](https://cwe.mitre.org/) |
| **Azure Resource Manager** | config analyzer | ready (misconfig) | [ARM template best practices](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/best-practices), [arm-ttk](https://github.com/Azure/arm-ttk), [Azure Security Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/), [CWE](https://cwe.mitre.org/) |
| **Kotlin** | AST | ready (tree-sitter) | [Kotlin coding conventions](https://kotlinlang.org/docs/coding-conventions.html), [detekt rules](https://detekt.dev/docs/rules/comments), [ktlint standard rules](https://pinterest.github.io/ktlint/latest/rules/standard/), [CWE](https://cwe.mitre.org/) |
| **PHP** | AST | ready (tree-sitter) | [PSR standards](https://www.php-fig.org/psr/), [PHPStan](https://phpstan.org/), [Psalm](https://psalm.dev/docs/), [OWASP PHP](https://cheatsheetseries.owasp.org/), [CWE](https://cwe.mitre.org/) |
| **Ruby** | AST | ready (tree-sitter) | [Ruby Style Guide](https://rubystyle.guide/), [RuboCop cops](https://docs.rubocop.org/rubocop/cops.html), [Brakeman warnings](https://brakemanscanner.org/docs/warning_types/), [CWE](https://cwe.mitre.org/) |
| **Scala** | AST | ready (tree-sitter) | [Scala Style Guide](https://docs.scala-lang.org/style/), [Scalafix rules](https://scalacenter.github.io/scalafix/docs/rules/overview.html), [Scalastyle](http://www.scalastyle.org/rules-dev.html), [CWE](https://cwe.mitre.org/) |
| **Swift** | AST | ready (tree-sitter) | [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/), [SwiftLint rule directory](https://realm.github.io/SwiftLint/rule-directory.html), [CWE](https://cwe.mitre.org/) |
| **VB.NET** | token/pattern | no bundled grammar (pattern rules) | [.NET code-quality rules](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/) (shared with C#), [CWE](https://cwe.mitre.org/) |
| **Kubernetes** | config analyzer | ready (misconfig) | [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/), [KubeLinter checks](https://docs.kubelinter.io/#/generated/checks), [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes), [kubesec](https://kubesec.io/), [CWE](https://cwe.mitre.org/) |
| **Terraform** | config analyzer | ready (misconfig) | [Terraform style](https://developer.hashicorp.com/terraform/language/style), [Trivy IaC (ex-tfsec)](https://aquasecurity.github.io/trivy/latest/docs/coverage/iac/terraform/), [Checkov Terraform policies](https://www.checkov.io/5.Policy%20Index/terraform.html), [tflint](https://github.com/terraform-linters/tflint), AWS/Azure/GCP Well-Architected, [CWE](https://cwe.mitre.org/) |
| **HTML** | AST/token | ready (tree-sitter) | [HTMLHint rules](https://htmlhint.com/docs/user-guide/list-rules), [WCAG](https://www.w3.org/WAI/standards-guidelines/wcag/), [MDN HTML](https://developer.mozilla.org/en-US/docs/Web/HTML), [W3C validator](https://validator.w3.org/) |
| **XML** | token/parse | ready | [W3C XML](https://www.w3.org/TR/xml/), [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [CWE-611](https://cwe.mitre.org/data/definitions/611.html) |
| **IPython Notebooks** | reuses Python | ready (Python) | reuses the [Python](#) pack over notebook cells + notebook-specific ([nbqa](https://nbqa.readthedocs.io/), [Bandit](https://bandit.readthedocs.io/)) |
| **Secrets** | token/entropy | ready (secretscan) | extends the existing secret scanner; [gitleaks rules](https://github.com/gitleaks/gitleaks), [detect-secrets](https://github.com/Yelp/detect-secrets), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **Text** | token | ready | any-file checks: [bidi-unicode (Trojan Source)](https://trojansource.codes/), BOM, oversized files, generic secrets |

**Kubernetes** and **Terraform** give Synapse its **AWS / Azure / GCP** cloud-misconfig coverage
alongside CloudFormation + ARM. **Secrets** and **IPython Notebooks** extend existing engines (the secret
scanner and the Python pack) rather than adding a new parser. Deferred / low-priority: **Flex** (legacy
ActionScript). Further candidates: Shell, Dart, YAML-generic.

## Reviewing an existing pack

When reviewing a language pack, check each rule:

- **Correct** — does the detection actually match the described defect, with acceptable false-positive
  rate? Prefer AST over regex where precision matters.
- **Sourced** — does the rationale cite a concrete, openly-published source link?
- **Typed + rated** — right type, impacted software quality, and severity on Synapse's scale?
- **Tested** — a compliant + non-compliant golden fixture?
- **Original** — our own wording and detection (clean-room)?
