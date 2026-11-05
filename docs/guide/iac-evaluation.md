# Infrastructure-as-code evaluation

This page states what the owned IaC engine evaluates, what it deliberately leaves
unevaluated, and how each policy decision maps to a severity. A clean result inside the
contract means the configuration was read and found secure. A clean result outside it
means nothing was evaluated, and the scan says so rather than implying safety.

## Terraform: what is evaluated

Each `.tf` and `.tf.json` file is parsed with HCL, and every attribute expression is
evaluated against the module's values before any rule runs. The rules therefore read the
effective value, not the spelling: `cidr_blocks = var.ssh_ranges` and
`cidr_blocks = ["0.0.0.0/0"]` reach the open-CIDR predicate as the same list.

A module is a directory, which is the unit of variable scope. Values resolve from:

1. the module's own `variable "x" { default = ... }`,
2. `terraform.tfvars`, then `terraform.tfvars.json`, then each `*.auto.tfvars` and
   `*.auto.tfvars.json` in lexical order, each overriding the previous,
3. the inputs a parent `module` block binds, which override everything above.

An assignment at any of those levels that the evaluator refuses, or whose value is too large
to keep, binds the name UNKNOWN at that level rather than dropping it. Dropping it would let
the level below take over, so a variable file that overrides a `true` default with an
expression nobody evaluated would read back as `true`, and an attribute depending on it would
resolve to the value the operator overrode. Which way that lands is decided by the default:
one direction hides a real misconfiguration, the other invents one. An assignment that Terraform
itself rejects is different, and is left out, because it has no value at any level.

A `*.tfvars` file Terraform loads only when it is named with `-var-file` is not applied
silently. Each such file is evaluated as its own scenario: the WHOLE workspace is resolved
again under it, so the scenario's bindings travel down every module edge, and the findings
of every scenario are unioned, because each is a configuration an operator applies. At most
eight scenarios are evaluated across the workspace, and at most 64 candidate variable
files are read from one directory. A file dropped at either bound is reported as a coverage
gap so `--require-complete` rejects the run rather than passing work that was never done.
Both bounds report through the same counter, because a file skipped before it was read and
a file skipped after the budget filled are the same thing to the operator: a configuration
nobody evaluated.

Locals resolve by repeated substitution. A local that is declared but not resolved yet is
UNKNOWN rather than missing, so an expression reading it propagates uncertainty instead of
taking a `try` fallback that Terraform would not take. Module inputs propagate down the
tree, recorded per call site: one site refining its value across rounds is the same binding
becoming accurate, and only two different sites disagreeing leaves the input without a
single value. Both are bounded at eight rounds: a configuration that needs more is left
unresolved rather than iterated to a fixpoint.

Functions are a fixed, pure allowlist (`concat`, `slice`, `merge`, `jsonencode`,
`lookup`, and the other value transformations). None reads a file, a provider, the
network, or the Terraform state, so evaluating a target's configuration can have no effect
outside the scan.

`format`, `formatlist` and `indent` are absent: their width and count parameters let a
one-line configuration ask for an arbitrarily large string.

Every remaining function is wrapped so the projected size of its result is checked from the
arguments BEFORE it runs. The check has to come first: a predicate on the finished value
arrives after the allocation it exists to prevent, and wrapping the call in `length()` hides
the intermediate entirely. `join` is bounded by `separator x (n-1) + items`, because the
separator repeats between every pair; `split` and `jsonencode` carry their own expansion
factors; everything else cannot exceed the sum of its inputs. `join` is variadic, so the
projection spans every list it is given, not the first: two lists multiply the separator
across their combined element count exactly as one longer list would.

A refused call returns an UNKNOWN value rather than an error. The distinction decides what
`try(expr, fallback)` does with it. An error is a configuration failure, and Terraform
answers one with the fallback; a refusal is the scanner declining to do work, and answering
that with the fallback would print the scanner's own limit as a confident verdict about the
target. The unknown propagates instead, and the attribute is reported as unresolved.

Three further bounds apply. A single resolved variable, module input or local is capped at
64 KiB and is not stored above that. One expression may read at most 64 variable or local
references, so a template cannot chain an unbounded number of budget-sized operands.

A `for` expression and a template `for` directive are refused before evaluation. Their cost
is not a function of the arguments: the body runs once per element of a collection that is
itself computed, so nesting two of them squares the work and the per-call projection above
sees only the innermost call's small arguments. Terraform configurations that build values
this way are left unresolved and reported, which costs coverage on a construct that
appears in a minority of attributes and removes the only path from source text to unbounded
work.

Admission runs at one boundary that every evaluation passes through: resource and module
attributes, variable defaults, variable files, and policy documents, in native syntax and in
JSON. A `.tf.json` attribute needs its own inspection, because it carries no syntax tree:
the JSON library parses each string as a native template at evaluation time, so the kind of
the wrapper says nothing about what running it will do. Arrays and objects are walked to
their leaves, including an interpolated object key, and each leaf string is read back
verbatim and parsed as the template it is about to become. An expression whose shape this
walk does not recognise is refused rather than admitted.

A `.tf.json` attribute that does not resolve is rendered with its name and an unresolved
marker rather than omitted. Omitting it would state something different from what the
scanner knows: a rule that asks whether `encrypted` is set would read the gap as an
operator who left encryption at the default, which is a finding about the target rather
than about an expression nobody evaluated.

## Terraform: what stays unknown

Everything else is unknown: a `data` source other than `aws_iam_policy_document`, another
resource's attribute, `count`/`each`/`path`, an undeclared variable, a module whose source
is not a local directory, and a variable a parent binds differently at two call sites.

An unknown attribute keeps its source text, so a rule can match only what was literally
written. Unknown values are never guessed, so evaluation can turn a missed finding into a
reported one and can never invent one from a value Terraform would not produce.

Each unresolved attribute is reported on the scan report as `file:line: attribute`. Treat
those lines as not evaluated, not as evaluated and clean.

A file that does not parse is scanned as plain text with the literal rules, exactly as
before HCL parsing was introduced. A syntax error degrades detection; it never removes it.

## AWS policy documents

A policy document is read as statements, never as lines. Each statement is assessed with
its `Effect`, `Principal`, `Action`, `Resource` and `Condition` together, and with the
kind of policy the carrying attribute establishes:

| Kind | Example attribute | What `Principal` means |
| --- | --- | --- |
| Identity | `aws_iam_policy.policy` | absent; a `Principal` element is not valid |
| Resource | `aws_s3_bucket_policy.policy`, `aws_kms_key.policy` | who may reach the resource |
| Trust | `aws_iam_role.assume_role_policy` | who may assume the role |
| VPC endpoint | `aws_vpc_endpoint.policy` | a boundary on traffic through the endpoint |
| Service control | `aws_organizations_policy.content` | a boundary, never a grant |

`jsonencode({...})`, a heredoc JSON document, and a referenced
`data "aws_iam_policy_document"` are all read. A document that composes others through
`source_policy_documents` or `override_policy_documents` is left unresolved and keeps its
literal detection: the provider merges those with its own precedence, so reading only the
direct statements would publish a partial document as the resolved one. Such a document is
bound as UNKNOWN rather than left undefined, so a `try` around it stays uncertain instead
of falling back to a value the provider would never produce, and only a document this
scanner actually rendered suppresses its own literal findings. A document a referencing resource carries
is assessed once, at the resource; a document no recognised resource consumes keeps its
literal line rules, because it attaches to nothing this scanner can establish.

### Decisions

- A `Deny` statement never produces an exposure finding. A statement with no `Effect` is
  malformed; it is read as the `Allow` its author meant, because reading it as `Deny`
  would hide a grant the corrected document would make.
- `NotAction`, `NotResource` and `NotPrincipal` invert the element's meaning. No claim is
  made about such a statement.
- `Principal = "*"` is assessed against the conditions beside it. A positive match on a
  caller-scoping key (`aws:PrincipalOrgID`, `aws:PrincipalAccount`, `aws:PrincipalArn`,
  `aws:SourceAccount`, `aws:SourceArn`, and the rest of that family) restricts the
  statement, and no public-access claim is made. A condition on an unrelated key, or a
  negated operator, restricts nothing and the finding stands.
- A `Principal` ARN that merely contains a wildcard
  (`arn:aws:iam::123456789012:role/app-*`) names a scoped set of roles. It is not every
  principal and is not reported as one.
- A condition whose value this scan cannot establish leaves the statement UNKNOWN. The
  finding is reported at medium with the reason stated, never dropped as safe and never
  claimed as public.
- An `...IfExists` operator, and a `ForAllValues:` set test, both evaluate true when the
  key is absent from the request, so a caller that does not carry the key is allowed and
  the condition narrows nobody. It counts as a restriction only alongside a `Null` check
  whose every alternative requires that key to be present: a `true` alternative beside the
  `false` one permits the absent state again.
- Condition values are alternatives, ORed together. For a pattern operator such as
  `StringLike` or `ArnLike`, one `"*"` alternative matches everything, so the specific
  values beside it establish no restriction. That is a known ineffective restriction, not
  an unresolved one, so the statement reports at its full severity.
- A VPC endpoint policy is an additional boundary, not an independent grant. An
  unconstrained one is reported at medium, and the description says it does not by itself
  grant access to the target service.
- `sts:AssumeRoleWithWebIdentity` and `sts:AssumeRoleWithSAML` callers carry no
  `aws:PrincipalOrgID`, so a principal-org restriction is never recommended for them.
  Those statements are assessed on their destination scope instead: an explicit role ARN,
  `aws:ResourceOrgID`, or `aws:ResourceAccount`.

### Severity mapping

| Finding | Severity | When |
| --- | --- | --- |
| `terraform-wildcard-principal` | high | resource or trust policy, wildcard principal, no condition that narrows the caller |
| `terraform-wildcard-principal` | medium | endpoint policy, federation statement, network-only condition, or an unresolved condition value |
| `terraform-iam-wildcard-resource` | high | identity or resource policy, `Resource = "*"`, no condition that narrows it |
| `terraform-iam-wildcard-resource` | medium | endpoint policy, federation destination, or an unresolved condition value |
| `terraform-iam-wildcard` | medium | `Action = "*"` in an allowing statement |

A trust policy's `Resource` element is not used by AWS and is not assessed.

## Kubernetes, Helm and Kustomize

A Kubernetes resource is the resource it declares, in whichever syntax declared it. A
manifest authored as JSON is parsed and assessed exactly as its YAML equivalent is, and
produces the same findings. A JSON document is classified at its ROOT: an ARM deployment
template carries `apiVersion` and `kind` inside its resources, and claiming it as a
Kubernetes manifest on that basis sent it to a parser that scanned nothing.

Helm charts and Kustomize overlays carry their security-relevant values in templates and
patches, so they have to be rendered before the Kubernetes rules can read them. Rendering
executes untrusted input, so it is off unless a sandbox runner is configured (the API) or
an explicit trusted-local exec is enabled (the CLI).

An input left unrendered is reported, never returned as a clean result:

| Situation | What is reported |
| --- | --- |
| Helm rendering disabled, binary absent, or the render failed | an unrendered chart, with the reason |
| Kustomize rendering disabled, binary absent, the render failed, or the render budget was reached | an unassessed input, with the reason |

Both make the `iac` engine's coverage partial, so `--require-complete` rejects the run.
The manifests behind an unrendered input are still scanned raw, so this is a coverage gap
and never a lost scan: a base manifest's findings stand, and only the patches or values
that were never applied are missing. A Helm library chart declares no resources of its
own and is not counted as a gap.

Unresolved Terraform attributes are different. They sit inside the published evaluation
contract above, so they are reported as a warning that names them rather than as a
coverage gap.

## Network rules

An exposure finding requires an allowing rule. The decision is read from
`rule_action` (AWS network ACL), `access` (Azure network security rule), `action` (GCP
firewall policy), and the `allow`/`deny` sub-block of `google_compute_firewall`. A rule
that denies `0.0.0.0/0` restricts access and produces no finding.

Direction is read from the `ingress`/`egress` sub-block, from a `type`/`direction`
attribute, from `aws_network_acl_rule`'s boolean `egress`, or from the CIDR attribute's
own name. Egress exposure is reported at medium, ingress at high.

## S3 and EBS policy

`aws_s3_bucket_versioning`, and the other hardening resources the provider split out of
`aws_s3_bucket`, are bound to the bucket they name, by reference
(`aws_s3_bucket.b.id`) or by literal bucket name. An Enabled versioning resource
suppresses the no-versioning finding for that bucket only. When the reference does not
resolve, nothing is suppressed unless the module holds exactly one bucket: suppressing
across unrelated buckets is how a genuinely unversioned bucket disappears.

EBS encryption is reported at two severities on purpose:

- `encrypted = false` is high. The value is proven, and the volume is unencrypted.
- an omitted `encrypted` is medium. EBS encryption-by-default is a per-region account
  setting that infrastructure code cannot observe, so the volume is unencrypted unless
  that setting is on. The finding states the assumption rather than claiming the stronger
  fact.

A minimal `aws_s3_bucket` deliberately does not emit a missing-encryption or
missing-public-access-block finding. Since April 2023 new buckets have S3 Block Public
Access enabled and ACLs disabled by default, and since January 2023 all new objects are
encrypted with SSE-S3 by default, so those findings would describe a configuration AWS no
longer produces. What remains reportable is a configuration that explicitly weakens a
default: `terraform-public-access-block-disabled` for a public-access block set to
`false`, and `terraform-public-bucket-acl` for a public ACL. Bucket-level findings that
survive on their own evidence (logging, versioning) are unchanged.

These are IaC observations. They describe the configuration in the repository, not the
state of a cloud account: a resource may have drifted, may not be applied, or may be
overridden elsewhere.
