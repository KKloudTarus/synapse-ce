# Terraform/HCL language-pack rule specs (#1135, EPIC #1120). The IaC misconfig engine
# (internal/infrastructure/tools/misconfig/terraform.go) already covers Terraform security and
# configuration comprehensively (secrets, provisioners, lifecycle ignore_changes = all, open CIDRs,
# resource encryption, ...). To avoid duplicate detections, this langpack adds ONLY the pure HCL
# quality/hotspot line patterns the misconfig engine does not emit: a deprecated interpolation-only
# string, and a generic cleartext http:// endpoint anywhere in a value (the misconfig rules are
# resource-specific, e.g. Azure storage HTTPS, not a general http:// check). Ids are namespaced `tf-*`.
CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "tf")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "terraform", "iac"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="tf-cleartext-http-endpoint", type="hotspot", qual="sec", sev="medium", cwe="CWE-319", owasp="A02:2021",
      title="Cleartext HTTP endpoint in Terraform",
      desc="A configuration value points at an http:// URL, so traffic to it is unencrypted.",
      rationale="An http:// endpoint transmits data in cleartext and is open to interception and tampering (CWE-319). Use https:// unless the target genuinely has no TLS and the risk is accepted. This is a general http:// check across any value, complementing the resource-specific misconfig rules.",
      remediation="Use an https:// URL, or document why cleartext is acceptable for this endpoint.",
      source="https://cwe.mitre.org/data/definitions/319.html",
      re=r'=\s*"http://',
      nc='endpoint = "http://metadata.internal"',
      c='endpoint = "https://metadata.internal"'),
    r(id="tf-deprecated-interpolation", type="smell", qual="maint", sev="low",
      title="Deprecated interpolation-only string",
      desc="A value wraps a single reference in \"${ ... }\", the pre-0.12 interpolation syntax.",
      rationale="Since Terraform 0.12 a bare reference is preferred over an interpolation-only string; the wrapped form is legacy noise that hurts readability and can mask type information.",
      remediation='Drop the quotes and braces: name = var.name instead of name = "${var.name}".',
      source="https://developer.hashicorp.com/terraform/language/expressions/strings",
      re=r'=\s*"\$\{[^}"]+\}"',
      nc='name = "${var.name}"',
      c='name = var.name',
      effort=5),
]
