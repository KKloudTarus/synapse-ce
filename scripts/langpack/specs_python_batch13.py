CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality pack, batch 13: flake8-simplify / comprehensions / bugbear / pyupgrade / refurb.
RULES = [
    r(id="python-or-true", type="bug", qual="rel", sev="medium", cwe="", title="Constant True in an or",
      desc="`x or True` is always True.", rationale="A literal True on the right of or makes the whole expression constant (flake8-simplify SIM223).",
      remediation="Remove the constant, or fix the intended condition.", source="https://github.com/MartinThoma/flake8-simplify",
      re=r"\bor\s+True\b", nc="if enabled or True:", c="if enabled or fallback:"),
    r(id="python-and-false", type="bug", qual="rel", sev="medium", cwe="", title="Constant False in an and",
      desc="`x and False` is always False.", rationale="A literal False on the right of and makes the whole expression constant (flake8-simplify SIM222).",
      remediation="Remove the constant, or fix the intended condition.", source="https://github.com/MartinThoma/flake8-simplify",
      re=r"\band\s+False\b", nc="if enabled and False:", c="if enabled and ready:"),
    r(id="python-environ-lowercase", type="smell", qual="maint", sev="low", cwe="", title="Lowercase environment variable",
      desc="Environment variable names are conventionally uppercase.", rationale="A lowercase os.environ key is unusual and often a typo (flake8-simplify SIM112).",
      remediation="Use the uppercase variable name.", source="https://github.com/MartinThoma/flake8-simplify",
      re=r'''os\.environ\[["'][a-z][a-z_]*["']\]''', nc='token = os.environ["api_key"]', c='token = os.environ["API_KEY"]'),
    r(id="python-set-list-literal", type="smell", qual="maint", sev="low", cwe="", title="set() around a list literal",
      desc="set([...]) is clearer as a set literal or comprehension.", rationale="Building a list first then a set is wasteful (flake8-comprehensions C405).",
      remediation="Use a set literal {..} or comprehension.", source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\bset\s*\(\s*\[", nc="s = set([1, 2, 3])", c="s = {1, 2, 3}"),
    r(id="python-dict-list-literal", type="smell", qual="maint", sev="low", cwe="", title="dict() around a list of pairs",
      desc="dict([(k, v)]) is clearer as a dict literal or comprehension.", rationale="Building a list of tuples first is wasteful (flake8-comprehensions C406).",
      remediation="Use a dict literal or comprehension.", source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\bdict\s*\(\s*\[", nc="d = dict([(1, 2)])", c="d = {1: 2}"),
    r(id="python-list-sorted", type="smell", qual="maint", sev="low", cwe="", title="list(sorted(...))",
      desc="sorted() already returns a list.", rationale="Wrapping sorted() in list() is redundant (flake8-comprehensions C413).",
      remediation="Use sorted(...) directly.", source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\b(list|reversed)\s*\(\s*sorted\s*\(", nc="ordered = list(sorted(items))", c="ordered = sorted(items)"),
    r(id="python-isinstance-type-none", type="smell", qual="maint", sev="low", cwe="", title="isinstance(x, type(None))",
      desc="isinstance(x, type(None)) is just x is None.", rationale="Comparing against type(None) is a convoluted None check (refurb FURB168).",
      remediation="Use x is None.", source="https://github.com/dosisod/refurb",
      re=r"isinstance\s*\([^,]+,\s*type\s*\(\s*None\s*\)\s*\)", nc="if isinstance(value, type(None)):", c="if value is None:"),
    r(id="python-coding-comment", type="smell", qual="maint", sev="low", cwe="", title="Redundant coding comment",
      desc="A UTF-8 coding comment is unnecessary in Python 3.", rationale="Python 3 source is UTF-8 by default, so the coding cookie is redundant (pyupgrade UP009).",
      remediation="Remove the coding comment.", source="https://github.com/asottile/pyupgrade",
      re=r'''coding[:=]\s*["']?utf''', nc="# -*- coding: utf-8 -*-", c="# module summary", skip=""),
    r(id="python-str-literal-wrap", type="smell", qual="maint", sev="low", cwe="", title="str() around a string literal",
      desc="str(\"x\") is just \"x\".", rationale="Wrapping a string literal in str() is redundant (pyupgrade UP018).",
      remediation="Use the string literal directly.", source="https://github.com/asottile/pyupgrade",
      re=r'''\bstr\s*\(\s*["']''', nc='label = str("ready")', c='label = "ready"'),
    r(id="python-subprocess-universal-newlines", type="smell", qual="maint", sev="low", cwe="", title="subprocess universal_newlines",
      desc="universal_newlines was renamed text.", rationale="The text keyword is the modern spelling of universal_newlines (pyupgrade UP021).",
      remediation="Use text=True.", source="https://github.com/asottile/pyupgrade",
      re=r"universal_newlines\s*=", nc="subprocess.run(cmd, universal_newlines=True)", c="subprocess.run(cmd, text=True)"),
    r(id="python-version-info-py2-block", type="smell", qual="maint", sev="low", cwe="", title="Outdated Python 2 version block",
      desc="sys.version_info < (3, 0) is always False on Python 3.", rationale="A guard for Python < 3.0 is dead code on Python 3 (pyupgrade UP036).",
      remediation="Remove the Python 2 branch.", source="https://github.com/asottile/pyupgrade",
      re=r"sys\.version_info\s*<\s*\(\s*3\s*,\s*0", nc="if sys.version_info < (3, 0):", c="if sys.version_info < (3, 8):"),
    r(id="python-no-plus-plus", type="bug", qual="rel", sev="medium", cwe="", title="++ / -- has no effect",
      desc="Python has no increment/decrement operators.", rationale="++x parses as +(+x) and does nothing (flake8-bugbear B002).",
      remediation="Use x += 1 / x -= 1.", source="https://github.com/PyCQA/flake8-bugbear",
      re=r"(\+\+|--)[a-zA-Z_]", nc="++count", c="count += 1"),
    r(id="python-hasattr-call", type="smell", qual="maint", sev="low", cwe="", title="hasattr(x, \"__call__\")",
      desc="hasattr(x, \"__call__\") is just callable(x).", rationale="The callable() builtin is the clear way to test callability (flake8-bugbear B004).",
      remediation="Use callable(x).", source="https://github.com/PyCQA/flake8-bugbear",
      re=r'''hasattr\s*\([^,]+,\s*["']__call__["']\s*\)''', nc='if hasattr(obj, "__call__"):', c="if callable(obj):"),
    r(id="python-abstractproperty", type="smell", qual="maint", sev="low", cwe="", title="Deprecated @abstractproperty",
      desc="abc.abstractproperty is deprecated.", rationale="abstractproperty is deprecated in favor of stacking @property and @abstractmethod.",
      remediation="Use @property over @abstractmethod.", source="https://docs.python.org/3/library/abc.html",
      re=r"@abstractproperty\b", nc="@abstractproperty", c="@property"),
    r(id="python-asyncio-get-event-loop", type="smell", qual="maint", sev="low", cwe="", title="asyncio.get_event_loop()",
      desc="get_event_loop() with no running loop is deprecated.", rationale="asyncio.get_event_loop is deprecated for that use since 3.10; prefer asyncio.run / get_running_loop.",
      remediation="Use asyncio.run() or asyncio.get_running_loop().", source="https://docs.python.org/3/library/asyncio-eventloop.html",
      re=r"asyncio\.get_event_loop\s*\(\s*\)", nc="loop = asyncio.get_event_loop()", c="loop = asyncio.get_running_loop()"),
]
