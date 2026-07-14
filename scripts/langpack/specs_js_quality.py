CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])  # quality/style, not security
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# JS/TS quality pack: ESLint idioms. Clean-room prose.
RULES = [
    r(id="js-compare-boolean-literal", type="smell", qual="maint", sev="low", cwe="",
      title="Comparison to a boolean literal", desc="x === true / x === false is redundant.",
      rationale="Comparing a boolean to true/false is noise; use the value (or its negation) directly.",
      remediation="Use the condition directly: if (ready) / if (!ready).",
      source="https://eslint.org/docs/latest/rules/no-unneeded-ternary",
      re=r"(===|!==|==|!=)\s*(true|false)\b", nc="if (ready === true) {", c="if (ready) {"),
]
