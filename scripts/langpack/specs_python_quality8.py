CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality pack, batch 8: naive datetime (flake8-datetimez), removed/deprecated APIs (pyupgrade),
# threading hazard (bugbear). Clean-room prose.
RULES = [
    r(id="python-datetime-now-naive", type="smell", qual="maint", sev="low", cwe="",
      title="Naive datetime.now()", desc="datetime.now() with no tz returns a timezone-unaware value.",
      rationale="A naive datetime misbehaves in arithmetic and comparison across timezones (flake8-datetimez DTZ005).",
      remediation="Pass a tz: datetime.now(timezone.utc).",
      source="https://github.com/pjknkda/flake8-datetimez",
      re=r"datetime\.now\s*\(\s*\)", nc="ts = datetime.now()", c="ts = datetime.now(timezone.utc)"),
    r(id="python-datetime-today", type="smell", qual="maint", sev="low", cwe="",
      title="datetime.today()", desc="datetime.today() returns a naive local datetime.",
      rationale="today() is timezone-unaware and ties the value to the machine's local zone (DTZ002).",
      remediation="Use datetime.now(timezone.utc).",
      source="https://github.com/pjknkda/flake8-datetimez",
      re=r"datetime\.today\s*\(", nc="d = datetime.today()", c="d = datetime.now(timezone.utc)"),
    r(id="python-datetime-fromtimestamp-naive", type="smell", qual="maint", sev="low", cwe="",
      title="Naive datetime.fromtimestamp()", desc="fromtimestamp() without tz assumes local time.",
      rationale="Omitting tz makes the result depend on the machine's local zone (DTZ006).",
      remediation="Pass tz: datetime.fromtimestamp(ts, timezone.utc).",
      source="https://github.com/pjknkda/flake8-datetimez",
      re=r"datetime\.fromtimestamp\s*\(\s*\w+\s*\)", nc="dt = datetime.fromtimestamp(ts)", c="dt = datetime.fromtimestamp(ts, timezone.utc)"),
    r(id="python-io-open-alias", type="smell", qual="maint", sev="low", cwe="",
      title="io.open alias", desc="io.open is just the builtin open in Python 3.",
      rationale="io.open is a redundant alias for the builtin open (pyupgrade UP020).",
      remediation="Call open() directly.",
      source="https://github.com/asottile/pyupgrade",
      re=r"\bio\.open\s*\(", nc="f = io.open(path)", c="f = open(path)"),
    r(id="python-deprecated-collections-abc", type="bug", qual="rel", sev="medium", cwe="",
      title="Deprecated collections ABC access", desc="ABCs moved to collections.abc and were removed from collections in 3.10.",
      rationale="collections.Mapping and friends raise AttributeError on Python 3.10+.",
      remediation="Import from collections.abc.",
      source="https://docs.python.org/3/whatsnew/3.10.html",
      re=r"\bcollections\.(Mapping|Sequence|Iterable|Iterator|Callable|MutableMapping|MutableSequence|Set|Hashable)\b",
      nc="isinstance(x, collections.Mapping)", c="isinstance(x, collections.abc.Mapping)"),
    r(id="python-typing-text-alias", type="smell", qual="maint", sev="low", cwe="",
      title="typing.Text alias", desc="typing.Text is a deprecated alias for str.",
      rationale="typing.Text exists only for Python 2 compatibility (pyupgrade UP019).",
      remediation="Use the built-in str type in the annotation.",
      source="https://github.com/asottile/pyupgrade",
      re=r"\btyping\.Text\b", nc="name: typing.Text = value", c="name: str = value"),
    r(id="python-deprecated-imp-module", type="bug", qual="rel", sev="medium", cwe="",
      title="Deprecated imp module", desc="The imp module was removed in Python 3.12.",
      rationale="import imp raises ModuleNotFoundError on Python 3.12+.",
      remediation="Use importlib.",
      source="https://docs.python.org/3/whatsnew/3.12.html",
      re=r"\bimport\s+imp\b", nc="import imp", c="import importlib"),
    r(id="python-asyncio-coroutine-decorator", type="bug", qual="rel", sev="medium", cwe="",
      title="@asyncio.coroutine decorator", desc="asyncio.coroutine was removed in Python 3.11.",
      rationale="The generator-based coroutine decorator raises AttributeError on 3.11+.",
      remediation="Define the function with async def.",
      source="https://docs.python.org/3/whatsnew/3.11.html",
      re=r"@asyncio\.coroutine\b", nc="@asyncio.coroutine", c="async def fetch():"),
    r(id="python-elementtree-getchildren", type="bug", qual="rel", sev="medium", cwe="",
      title="ElementTree getchildren()", desc="Element.getchildren() was removed in Python 3.9.",
      rationale="getchildren() raises AttributeError on 3.9+; iterate the element directly.",
      remediation="Iterate the element: for child in element.",
      source="https://docs.python.org/3/whatsnew/3.9.html",
      re=r"\.getchildren\s*\(", nc="for child in root.getchildren():", c="for child in root:"),
    r(id="python-subprocess-preexec-fn", type="bug", qual="rel", sev="medium", cwe="",
      title="subprocess preexec_fn", desc="preexec_fn is unsafe in the presence of threads.",
      rationale="preexec_fn can deadlock in a multithreaded process (bugbear/subprocess docs).",
      remediation="Use start_new_session=True or pass_fds instead where possible.",
      source="https://docs.python.org/3/library/subprocess.html#subprocess.Popen",
      re=r"preexec_fn\s*=", nc="subprocess.Popen(cmd, preexec_fn=os.setsid)", c="subprocess.Popen(cmd, start_new_session=True)"),
]
