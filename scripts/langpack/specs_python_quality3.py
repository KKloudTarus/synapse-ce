CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality/correctness pack, third batch: pylint refactor idioms. Clean-room prose.
RULES = [
    r(id="python-unnecessary-dunder-call", type="smell", qual="maint", sev="low", cwe="",
      title="Direct dunder call", desc="Calling __len__/__str__ directly is less readable than the builtin.",
      rationale="Dunder methods are meant to back builtins/operators; call len(x)/str(x) instead of x.__len__().",
      remediation="Use the builtin: len(x), str(x), bool(x), iter(x), next(x).",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/convention/unnecessary-dunder-call.html",
      re=r"\.__(len|str|bool|iter|next|contains)__\s*\(", nc="n = obj.__len__()", c="n = len(obj)"),
    r(id="python-useless-object-inheritance", type="smell", qual="maint", sev="low", cwe="",
      title="Explicit object inheritance", desc="Inheriting from object is redundant in Python 3.",
      rationale="All Python 3 classes are new-style, so (object) adds noise.",
      remediation="Drop the explicit object base class.",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/refactor/useless-object-inheritance.html",
      re=r"class\s+\w+\s*\(\s*object\s*\)", nc="class Handler(object):", c="class Handler:"),
    r(id="python-len-gt-zero", type="smell", qual="maint", sev="low", cwe="",
      title="len() > 0 comparison", desc="len(x) > 0 is less clear than a truthiness check.",
      rationale="A non-empty collection is already truthy, so len(x) > 0 is redundant.",
      remediation="Use if x: instead of if len(x) > 0:.",
      source="https://peps.python.org/pep-0008/",
      re=r"len\s*\([^)]*\)\s*>\s*0\b", nc="if len(items) > 0:", c="if items:"),
]
