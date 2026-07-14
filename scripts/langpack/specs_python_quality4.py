CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality/correctness pack, batch 4: flake8-bugbear + pylint refactor idioms. Clean-room prose.
RULES = [
    r(id="python-use-list-literal", type="smell", qual="maint", sev="low", cwe="",
      title="list() instead of []", desc="list() with no arguments is slower and less clear than [].",
      rationale="The [] literal is faster and more idiomatic than calling the list constructor.",
      remediation="Use [] for an empty list.",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/refactor/use-list-literal.html",
      re=r"\blist\s*\(\s*\)", nc="items = list()", c="items = []"),
    r(id="python-use-dict-literal", type="smell", qual="maint", sev="low", cwe="",
      title="dict() instead of {}", desc="dict() with no arguments is slower and less clear than {}.",
      rationale="The {} literal is faster and more idiomatic than calling the dict constructor.",
      remediation="Use {} for an empty dict.",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/refactor/use-dict-literal.html",
      re=r"\bdict\s*\(\s*\)", nc="mapping = dict()", c="mapping = {}"),
    r(id="python-function-call-in-default", type="bug", qual="rel", sev="medium", cwe="",
      title="Function call in a default argument", desc="A call in a default argument is evaluated once at definition time.",
      rationale="Default arguments are evaluated once, so a call there is shared across invocations (bugbear B008).",
      remediation="Use None as the default and compute the value inside the function.",
      source="https://github.com/PyCQA/flake8-bugbear",
      re=r"def\s+\w+\s*\([^)]*=\s*\w+\s*\(", nc="def process(items=get_default()):", c="def process(items=None):"),
    r(id="python-getattr-constant", type="smell", qual="maint", sev="low", cwe="",
      title="getattr with a constant attribute", desc="getattr(obj, \"name\") is just obj.name.",
      rationale="A constant attribute name does not need getattr; direct access is clearer (bugbear B009).",
      remediation="Use direct attribute access: obj.name.",
      source="https://github.com/PyCQA/flake8-bugbear",
      re=r'''getattr\s*\([^,]+,\s*["']\w+["']\s*\)''', nc='value = getattr(obj, "name")', c="value = obj.name"),
    r(id="python-setattr-constant", type="smell", qual="maint", sev="low", cwe="",
      title="setattr with a constant attribute", desc="setattr(obj, \"name\", v) is just obj.name = v.",
      rationale="A constant attribute name does not need setattr; direct assignment is clearer (bugbear B010).",
      remediation="Use direct assignment: obj.name = value.",
      source="https://github.com/PyCQA/flake8-bugbear",
      re=r'''setattr\s*\([^,]+,\s*["']\w+["']\s*,''', nc='setattr(obj, "name", value)', c="obj.name = value"),
    r(id="python-assert-false", type="bug", qual="rel", sev="medium", cwe="",
      title="assert False", desc="assert False is removed when Python runs with -O.",
      rationale="Assertions are stripped under optimization, so assert False will not raise (bugbear B011).",
      remediation="Raise AssertionError explicitly instead.",
      source="https://github.com/PyCQA/flake8-bugbear",
      re=r"assert\s+False\b", nc="assert False", c='raise AssertionError("unreachable")'),
    r(id="python-redundant-except-tuple", type="smell", qual="maint", sev="low", cwe="",
      title="Single-element exception tuple", desc="except (E): has redundant parentheses.",
      rationale="A one-element exception tuple is just the exception; drop the parentheses.",
      remediation="Write except E:.",
      source="https://peps.python.org/pep-0008/",
      re=r"except\s*\(\s*\w+\s*\)", nc="except (ValueError):", c="except ValueError:"),
    r(id="python-raise-literal", type="bug", qual="rel", sev="medium", cwe="",
      title="Raising a string literal", desc="raise \"msg\" is a TypeError; only exceptions can be raised.",
      rationale="Raising a string raises TypeError in Python 3 (bugbear B016).",
      remediation="Raise an exception instance, e.g. raise ValueError(\"msg\").",
      source="https://github.com/PyCQA/flake8-bugbear",
      re=r'''raise\s+["']''', nc='raise "invalid state"', c='raise RuntimeError("invalid state")'),
]
