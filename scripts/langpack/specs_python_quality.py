CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])  # quality/correctness, not security
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality/correctness pack: pylint / pycodestyle-family idioms. Clean-room prose.
RULES = [
    r(id="python-consider-using-enumerate", type="smell", qual="maint", sev="low", cwe="",
      title="range(len(...)) loop", desc="Iterating range(len(seq)) is less readable than enumerate.",
      rationale="enumerate yields index and value together and reads more clearly than indexing by range(len()).",
      remediation="Use for i, value in enumerate(seq).",
      source="https://docs.python.org/3/library/functions.html#enumerate",
      re=r"range\s*\(\s*len\s*\(", nc="for i in range(len(items)):", c="for i, item in enumerate(items):"),
    r(id="python-has-key", type="bug", qual="rel", sev="medium", cwe="",
      title="dict.has_key()", desc="has_key was removed in Python 3 and raises AttributeError.",
      rationale="dict.has_key does not exist in Python 3; use the in operator.",
      remediation="Use key in mapping.",
      source="https://docs.python.org/3/whatsnew/3.0.html",
      re=r"\.has_key\s*\(", nc="if config.has_key(name):", c="if name in config:"),
    r(id="python-raise-notimplemented", type="bug", qual="rel", sev="medium", cwe="",
      title="raise NotImplemented", desc="NotImplemented is a value, not an exception; raising it fails.",
      rationale="raise NotImplemented raises a TypeError; the intended abstract-method marker is NotImplementedError.",
      remediation="Raise NotImplementedError instead.",
      source="https://docs.python.org/3/library/exceptions.html#NotImplementedError",
      re=r"raise\s+NotImplemented\b", nc="raise NotImplemented", c='raise NotImplementedError("not ready")'),
    r(id="python-double-negation", type="smell", qual="maint", sev="low", cwe="",
      title="Double negation", desc="not not x is a confusing way to write a boolean coercion.",
      rationale="Repeated not is hard to read; use the value directly or bool(x).",
      remediation="Use x for a truthiness test, or bool(x) when a boolean is required.",
      source="https://peps.python.org/pep-0008/",
      re=r"\bnot\s+not\b", nc="if not not value:", c="if value:"),
    r(id="python-statement-semicolon", type="smell", qual="maint", sev="low", cwe="",
      title="Trailing or compound-statement semicolon", desc="A line-ending semicolon is unnecessary in Python.",
      rationale="Python does not need statement terminators; a trailing ; is noise (pycodestyle E703).",
      remediation="Remove the trailing semicolon and put each statement on its own line.",
      source="https://pycodestyle.pycqa.org/en/latest/intro.html",
      re=r";\s*$", nc="value = compute();", c="value = compute()"),
    r(id="python-datetime-utcnow", type="bug", qual="rel", sev="low", cwe="",
      title="datetime.utcnow()", desc="utcnow returns a naive datetime and is deprecated in 3.12+.",
      rationale="utcnow yields a naive (tz-unaware) datetime that misbehaves in arithmetic and comparisons.",
      remediation="Use datetime.now(timezone.utc) for an aware UTC timestamp.",
      source="https://docs.python.org/3/library/datetime.html#datetime.datetime.utcnow",
      re=r"datetime\.utcnow\s*\(", nc="ts = datetime.utcnow()", c="ts = datetime.now(timezone.utc)"),
    r(id="python-constant-if-test", type="bug", qual="rel", sev="medium", cwe="",
      title="Constant if condition", desc="if True: / if False: has a dead branch.",
      rationale="A literal True/False if condition means one branch is dead code, usually leftover debugging.",
      remediation="Use a real condition, or remove the dead branch.",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/warning/using-constant-test.html",
      re=r"^\s*if\s+(True|False)\s*:", nc="if True:", c="if enabled:"),
    r(id="python-super-with-arguments", type="smell", qual="maint", sev="low", cwe="",
      title="super() with explicit arguments", desc="Passing the class and self to super() is the Python 2 style.",
      rationale="Python 3 allows the argument-free super(); the explicit form is redundant.",
      remediation="Use super() with no arguments inside a normal method.",
      source="https://docs.python.org/3/library/functions.html#super",
      re=r"super\s*\(\s*\w+\s*,\s*self\s*\)", nc="super(MyClass, self).__init__()", c="super().__init__()"),
]
