# Code Quality Rules — authoring guide

[Documentation home](README.md) · Previous: [Features](features.md) · Next: [Configuration](configuration.md)

This guide is for contributors adding or reviewing **code-quality rules**. Synapse's code-quality
engine (see the [Features](features.md) guide) turns parsed source into `Kind=quality` /
`Kind=reliability` findings and the A–E ratings. Each language ships a built-in **"Synapse way"**
quality profile — a curated set of rules. This page defines how those rules are modelled, how they are
authored, and the authoritative sources each language draws on.

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
  detection (AST query, token/line pattern, or metric threshold).
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

## Rule schema

Rules are catalogued as first-class entities (see [#182](https://github.com/KKloudTarus/synapse-ce/issues/182)):

```
Rule {
  Key            // stable, e.g. "go:unhandled-error"  (namespace by language)
  Name           // short human title
  Language       // "Go", "Python", …
  Type           // bug | vulnerability | code_smell | security_hotspot
  Qualities[]    // security | reliability | maintainability
  DefaultSeverity// critical | high | medium | low | info
  Tags[]         // free-form discovery tags
  CWE[] / OWASP[]// when security-relevant
  Description    // what it flags (our own words)
  Rationale      // why it matters (cite the concept origin + a source link)
  Remediation    // how to fix, with our own compliant + non-compliant example
  RemediationEffort // minutes, for the tech-debt measure
  Detection      // ast | pattern | metric
}
```

## Detection & the parser

Detection is one of: an **AST query** (via the sandboxed `synapse-ast` sidecar, tree-sitter), a
**token/line pattern**, or a **metric threshold** (complexity, size, duplication). Prefer AST rules
where a grammar exists.

The sidecar currently parses **Python, JavaScript, Java** for function-level metrics (via go-enry for
line counts of many more). Languages that need a new tree-sitter grammar (or a structured-config
analyzer) before AST rules are possible are noted in the matrix below.

## Authoring workflow

1. Pick the language's authoritative sources (matrix below) and enumerate rule *ideas* by category:
   correctness/bugs, security, maintainability/smells, and style-with-substance.
2. For each rule, write the schema fields **from scratch**, with a concrete **source link** in the
   rationale, and a compliant + non-compliant example.
3. Implement detection (AST query preferred) and add a **golden test** per rule: a fixture that must
   flag and one that must not.
4. Add the rule to the language's built-in "Synapse way" profile ([#183](https://github.com/KKloudTarus/synapse-ce/issues/183)).
5. Keep the rule catalogue browsable ([#182](https://github.com/KKloudTarus/synapse-ce/issues/182)) and
   gate-eligible ([#184](https://github.com/KKloudTarus/synapse-ce/issues/184)).

## Language source matrix

Rule-count targets are our own scope goals (seed → longer-term), informed by how much ground each
language covers in mature analyzers. Start with the seed set. Every source below is openly published.

| Language | Detection | Parser status | Authoritative sources |
| --- | --- | --- | --- |
| **Go** | AST + pattern | needs Go grammar | [Effective Go](https://go.dev/doc/effective_go), [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments), [`go vet`](https://pkg.go.dev/cmd/vet), [Staticcheck checks](https://staticcheck.dev/docs/checks/), [gosec](https://github.com/securego/gosec), [CWE](https://cwe.mitre.org/) |
| **Python** | AST (today) | ready | [PEP 8](https://peps.python.org/pep-0008/), [Ruff rules](https://docs.astral.sh/ruff/rules/), [Pylint checks](https://pylint.readthedocs.io/en/stable/user_guide/messages/messages_overview.html), [Bandit plugins](https://bandit.readthedocs.io/en/latest/plugins/index.html), [CWE](https://cwe.mitre.org/) |
| **JavaScript/TypeScript** | AST (JS today) | needs TS grammar | [ESLint rules](https://eslint.org/docs/latest/rules/), [typescript-eslint rules](https://typescript-eslint.io/rules/), [MDN JS](https://developer.mozilla.org/en-US/docs/Web/JavaScript), [CWE](https://cwe.mitre.org/) |
| **Node.js** | AST (JS) + pattern | needs TS grammar for TS | [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html), [Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html), [Node.js security best practices](https://nodejs.org/en/learn/getting-started/security-best-practices), [NPM Security](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html), [CWE](https://cwe.mitre.org/) |
| **Java** | AST (today) | ready | [Google Java Style](https://google.github.io/styleguide/javaguide.html), [Error Prone bug patterns](https://errorprone.info/bugpatterns), [SpotBugs descriptions](https://spotbugs.readthedocs.io/en/stable/bugDescriptions.html), [SEI CERT Oracle (Java)](https://wiki.sei.cmu.edu/confluence/display/java), [CWE](https://cwe.mitre.org/) |
| **C#** | AST | needs C# grammar | [.NET code-quality rules](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/), [StyleCop Analyzers](https://github.com/DotNetAnalyzers/StyleCopAnalyzers), [.NET secure coding](https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines), [CWE](https://cwe.mitre.org/) |
| **Rust** | AST | needs Rust grammar | [Clippy lints](https://rust-lang.github.io/rust-clippy/master/) ([book](https://doc.rust-lang.org/clippy/)), [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/), [RustSec advisories](https://rustsec.org/), [CWE](https://cwe.mitre.org/) |
| **C** | AST | needs C grammar | [SEI CERT C](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard), [clang-tidy checks](https://clang.llvm.org/extra/clang-tidy/checks/list.html), [Cppcheck](https://cppcheck.sourceforge.io/), [CWE](https://cwe.mitre.org/) |
| **C++** | AST | needs C++ grammar | [SEI CERT C++](https://cmu-sei.github.io/secure-coding-standards/sei-cert-cpp-coding-standard/), [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines), [clang-tidy checks](https://clang.llvm.org/extra/clang-tidy/checks/list.html), [CWE](https://cwe.mitre.org/) |
| **CSS** | AST/token | needs CSS grammar | [W3C CSS specs](https://www.w3.org/Style/CSS/specs.en.html), [MDN CSS](https://developer.mozilla.org/en-US/docs/Web/CSS), [Stylelint rules](https://stylelint.io/rules/) |
| **Docker** | config analyzer | ready (misconfig) | [Dockerfile best practices](https://docs.docker.com/build/building/best-practices/), [Hadolint rules](https://github.com/hadolint/hadolint#rules), [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker), [CWE](https://cwe.mitre.org/) |
| **CloudFormation** | config analyzer | ready (misconfig) | [AWS Well-Architected](https://aws.amazon.com/architecture/well-architected/), [cfn-lint rules](https://github.com/aws-cloudformation/cfn-lint/blob/main/docs/rules.md), [CIS AWS Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services), [CWE](https://cwe.mitre.org/) |
| **Azure Resource Manager** | config analyzer | ready (misconfig) | [ARM template best practices](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/best-practices), [arm-ttk](https://github.com/Azure/arm-ttk), [Azure Security Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/), [CWE](https://cwe.mitre.org/) |

Languages already partly covered elsewhere: **Kubernetes** and **Terraform** by the misconfig
analyzer; **Java** has AST metrics today. Candidates for later packs: HTML, Ruby, PHP, Kotlin, Scala,
Swift, Shell, YAML.

## Reviewing an existing pack

When reviewing a language pack, check each rule:

- **Correct** — does the detection actually match the described defect, with acceptable false-positive
  rate? Prefer AST over regex where precision matters.
- **Sourced** — does the rationale cite a concrete, openly-published source link?
- **Typed + rated** — right type, impacted software quality, and severity on Synapse's scale?
- **Tested** — a compliant + non-compliant golden fixture?
- **Original** — our own wording and detection (clean-room)?
