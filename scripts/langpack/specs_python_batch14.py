CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality pack, batch 14: pyupgrade, flake8-logging, comprehensions/pie, reliability bugs.
RULES = [
    r(id="python-double-list-call", type="smell", qual="maint", sev="low", cwe="", title="list(list(...))",
      desc="Wrapping list() in list() copies twice.", rationale="Nested list() calls are redundant (flake8-comprehensions C414).",
      remediation="Call list() once.", source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\blist\s*\(\s*list\s*\(", nc="out = list(list(gen))", c="out = list(gen)"),
    r(id="python-or-false-redundant", type="smell", qual="maint", sev="low", cwe="", title="Redundant or False",
      desc="`x or False` is just x (for booleans).", rationale="Or-ing with False adds nothing (flake8-simplify SIM221).",
      remediation="Drop the `or False`.", source="https://github.com/MartinThoma/flake8-simplify",
      re=r"\bor\s+False\b", nc="return valid or False", c="return valid"),
    r(id="python-metaclass-py2", type="bug", qual="rel", sev="medium", cwe="", title="Python 2 __metaclass__",
      desc="The __metaclass__ attribute has no effect in Python 3.", rationale="Python 3 sets a metaclass with class C(metaclass=...); __metaclass__ is silently ignored (pyupgrade UP001).",
      remediation="Use class C(metaclass=Meta).", source="https://github.com/asottile/pyupgrade",
      re=r"^\s*__metaclass__\s*=", nc="    __metaclass__ = ABCMeta", c="class C(metaclass=ABCMeta):"),
    r(id="python-builtins-import", type="smell", qual="maint", sev="low", cwe="", title="Import from builtins",
      desc="builtins members are available without importing.", rationale="Importing range/str/etc from builtins is a Python 2 compatibility artifact (pyupgrade UP029).",
      remediation="Use the builtin directly without importing.", source="https://github.com/asottile/pyupgrade",
      re=r"from\s+builtins\s+import\b", nc="from builtins import range", c="values = range(10)"),
    r(id="python-collections-abc-import", type="bug", qual="rel", sev="medium", cwe="", title="ABC imported from collections",
      desc="Container ABCs moved to collections.abc and were removed from collections in 3.10.", rationale="from collections import Mapping raises ImportError on Python 3.10+ (pyupgrade UP035).",
      remediation="Import from collections.abc.", source="https://docs.python.org/3/whatsnew/3.10.html",
      re=r"from\s+collections\s+import\s+[^(#\n]*\b(Mapping|Sequence|Iterable|Iterator|Callable|MutableMapping|MutableSequence|Set|Hashable|Container|Sized)\b",
      nc="from collections import Mapping", c="from collections.abc import Mapping"),
    r(id="python-class-empty-parens", type="smell", qual="maint", sev="low", cwe="", title="Empty parentheses on class",
      desc="class Foo() has redundant empty parentheses.", rationale="A class with no bases needs no parentheses (pyupgrade UP039).",
      remediation="Write class Foo:.", source="https://github.com/asottile/pyupgrade",
      re=r"class\s+\w+\s*\(\s*\)", nc="class Handler():", c="class Handler:"),
    r(id="python-logger-direct-instantiation", type="smell", qual="maint", sev="low", cwe="", title="Direct Logger instantiation",
      desc="Logger objects should come from logging.getLogger.", rationale="Instantiating logging.Logger bypasses the logger registry (flake8-logging LOG001).",
      remediation="Use logging.getLogger(name).", source="https://github.com/adamchainz/flake8-logging",
      re=r"logging\.Logger\s*\(", nc='log = logging.Logger("app")', c='log = logging.getLogger("app")'),
    r(id="python-getlogger-file", type="smell", qual="maint", sev="low", cwe="", title="getLogger(__file__)",
      desc="Loggers should be named with __name__, not __file__.", rationale="__file__ is a path, giving inconsistent logger names (flake8-logging LOG002).",
      remediation="Use logging.getLogger(__name__).", source="https://github.com/adamchainz/flake8-logging",
      re=r"getLogger\s*\(\s*__file__\s*\)", nc="log = logging.getLogger(__file__)", c="log = logging.getLogger(__name__)"),
    r(id="python-logging-warn-constant", type="smell", qual="maint", sev="low", cwe="", title="Deprecated logging.WARN",
      desc="logging.WARN is a deprecated alias for logging.WARNING.", rationale="Use the canonical WARNING level constant (flake8-logging LOG009).",
      remediation="Use logging.WARNING.", source="https://github.com/adamchainz/flake8-logging",
      re=r"\blogging\.WARN\b", nc="log.setLevel(logging.WARN)", c="log.setLevel(logging.WARNING)"),
    r(id="python-lambda-reimplements-builtin", type="smell", qual="maint", sev="low", cwe="", title="lambda: [] / lambda: {}",
      desc="lambda: [] just calls list; use the builtin.", rationale="A lambda returning an empty container reimplements list/dict (flake8-pie PIE807).",
      remediation="Use list / dict as the factory.", source="https://github.com/sbdchd/flake8-pie",
      re=r"lambda\s*:\s*(\[\s*\]|\{\s*\})", nc="field(default_factory=lambda: [])", c="field(default_factory=list)"),
    r(id="python-single-string-slots", type="bug", qual="rel", sev="medium", cwe="", title="__slots__ set to a string",
      desc="A string __slots__ iterates its characters as slot names.", rationale="__slots__ = \"name\" creates slots n, a, m, e, not a single slot (pylint W0333).",
      remediation="Use a tuple/list: __slots__ = (\"name\",).", source="https://docs.python.org/3/reference/datamodel.html#slots",
      re=r'''__slots__\s*=\s*["']''', nc='__slots__ = "name"', c='__slots__ = ("name",)'),
    r(id="python-dict-fromkeys-mutable", type="bug", qual="rel", sev="medium", cwe="", title="dict.fromkeys with a mutable value",
      desc="All keys share the same mutable object.", rationale="dict.fromkeys(keys, []) gives every key the same list, so mutating one mutates all.",
      remediation="Use a dict comprehension: {k: [] for k in keys}.", source="https://docs.python.org/3/library/stdtypes.html#dict.fromkeys",
      re=r"dict\.fromkeys\s*\([^,)]+,\s*(\[|\{)", nc="cache = dict.fromkeys(keys, [])", c="cache = {k: [] for k in keys}"),
]
