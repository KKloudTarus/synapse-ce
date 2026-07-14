CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality/correctness pack, batch 5: logging idioms + flake8-comprehensions. Clean-room prose.
RULES = [
    r(id="python-logging-percent-format", type="smell", qual="maint", sev="low", cwe="",
      title="Eager %-formatting in logging", desc="Formatting the message with % happens even when the level is disabled.",
      rationale="Passing an already %-formatted string does the work eagerly; use lazy logging args.",
      remediation='Pass arguments to the logger: logger.info("user %s", name).',
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/warning/logging-not-lazy.html",
      re=r'''\.(debug|info|warning|error|critical|exception)\s*\(\s*["'][^"']*["']\s*%''',
      nc='logger.info("user %s" % name)', c='logger.info("user %s", name)'),
    r(id="python-unnecessary-list-call", type="smell", qual="maint", sev="low", cwe="",
      title="list() around a list literal", desc="list([...]) is just [...].",
      rationale="Wrapping a list literal in list() is redundant work (flake8-comprehensions C411).",
      remediation="Use the list literal directly.",
      source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\blist\s*\(\s*\[", nc="values = list([1, 2, 3])", c="values = [1, 2, 3]"),
    r(id="python-unnecessary-dict-call", type="smell", qual="maint", sev="low", cwe="",
      title="dict() around a dict literal", desc="dict({...}) is just {...}.",
      rationale="Wrapping a dict literal in dict() is redundant work (flake8-comprehensions C418).",
      remediation="Use the dict literal directly.",
      source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\bdict\s*\(\s*\{", nc='config = dict({"a": 1})', c='config = {"a": 1}'),
]
