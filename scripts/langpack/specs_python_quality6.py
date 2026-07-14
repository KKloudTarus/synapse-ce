CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality/correctness pack, batch 6: pylint + flake8-simplify comparison idioms. Clean-room.
RULES = [
    r(id="python-comparison-of-constants", type="bug", qual="rel", sev="medium", cwe="",
      title="Comparison of two literals", desc="Comparing two constants always yields the same result.",
      rationale="A literal-to-literal comparison is dead code; the result never depends on program state.",
      remediation="Compare against a variable, or remove the constant condition.",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/refactor/comparison-of-constants.html",
      re=r"\b\d+\s*(==|!=)\s*\d+\b", nc="if 1 == 2:", c="if count == 2:"),
    r(id="python-not-in", type="smell", qual="maint", sev="low", cwe="",
      title="not x in y", desc="not x in y is clearer written as x not in y.",
      rationale="The dedicated not-in operator reads better than negating a membership test.",
      remediation="Use x not in y.",
      source="https://peps.python.org/pep-0008/",
      re=r"\bnot\s+\w+\s+in\b", nc="if not key in mapping:", c="if key not in mapping:"),
    r(id="python-not-is", type="smell", qual="maint", sev="low", cwe="",
      title="not x is y", desc="not x is y is clearer written as x is not y.",
      rationale="The dedicated is-not operator reads better than negating an identity test.",
      remediation="Use x is not y.",
      source="https://peps.python.org/pep-0008/",
      re=r"\bnot\s+\w+\s+is\b", nc="if not value is None:", c="if value is not None:"),
    r(id="python-negated-equality", type="smell", qual="maint", sev="low", cwe="",
      title="not a == b", desc="not a == b is clearer written as a != b.",
      rationale="Negating an equality test is harder to read than the inequality operator.",
      remediation="Use a != b.",
      source="https://github.com/MartinThoma/flake8-simplify",
      re=r"\bnot\s+\w+\s*==", nc="if not a == b:", c="if a != b:"),
    r(id="python-negated-inequality", type="smell", qual="maint", sev="low", cwe="",
      title="not a != b", desc="not a != b is clearer written as a == b.",
      rationale="Negating an inequality test is harder to read than the equality operator.",
      remediation="Use a == b.",
      source="https://github.com/MartinThoma/flake8-simplify",
      re=r"\bnot\s+\w+\s*!=", nc="if not a != b:", c="if a == b:"),
    r(id="python-yoda-condition", type="smell", qual="maint", sev="low", cwe="",
      title="Yoda condition", desc="Writing the literal on the left of == is harder to read.",
      rationale="Yoda conditions (5 == x) invert the natural reading order of a comparison.",
      remediation="Put the variable first: x == 5.",
      source="https://en.wikipedia.org/wiki/Yoda_conditions",
      re=r"\b\d+\s*==\s*[a-zA-Z_]", nc="if 5 == count:", c="if count == 5:"),
]
