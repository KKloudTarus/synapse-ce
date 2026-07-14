CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "bug")
    k.setdefault("qual", "rel")
    k.setdefault("sev", "medium")
    k.setdefault("cwe", "")
    return k


PEP594 = "https://peps.python.org/pep-0594/"

# Removed stdlib modules: `import X` raises ModuleNotFoundError on the given Python version.
REMOVED_MODULES = [
    ("imghdr", "3.13", "the filetype package or Pillow"),
    ("sndhdr", "3.13", "a dedicated audio library"),
    ("nntplib", "3.13", "a third-party NNTP client"),
    ("aifc", "3.13", "a maintained audio library"),
    ("audioop", "3.13", "a maintained audio library"),
    ("cgitb", "3.13", "the traceback module"),
    ("mailcap", "3.13", "the mimetypes module or explicit configuration"),
    ("pipes", "3.13", "the subprocess and shlex modules"),
    ("sunau", "3.13", "a maintained audio library"),
    ("xdrlib", "3.13", "a maintained serialization library"),
    ("chunk", "3.13", "a maintained container-format library"),
    ("uu", "3.13", "the base64 module"),
    ("crypt", "3.13", "hashlib or the passlib package"),
    ("nis", "3.13", "a platform-specific service"),
    ("spwd", "3.13", "the python-pam package or a platform service"),
    ("ossaudiodev", "3.13", "a maintained audio library"),
    ("lib2to3", "3.13", "a maintained migration tool"),
    ("smtpd", "3.12", "the aiosmtpd package"),
    ("asynchat", "3.12", "asyncio"),
    ("formatter", "3.10", "a maintained text-formatting library"),
    ("parser", "3.10", "the ast module"),
    ("md5", "3.0", "hashlib"),
]

RULES = [
    r(id=f"python-module-{name}", title=f"Removed {name} module",
      desc=f"The {name} module was removed in Python {ver}.",
      rationale=f"import {name} raises ModuleNotFoundError on Python {ver}+.",
      remediation=f"Use {alt} instead.", source=PEP594,
      re=rf"^\s*import\s+{name}\b", nc=f"import {name}", c="import os")
    for (name, ver, alt) in REMOVED_MODULES
]

# Removed / deprecated APIs.
RULES += [
    r(id="python-inspect-formatargspec", title="inspect.formatargspec()", desc="formatargspec was removed in Python 3.11.",
      rationale="inspect.formatargspec raises AttributeError on Python 3.11+.", remediation="Use inspect.signature and format it yourself.",
      source="https://docs.python.org/3/whatsnew/3.11.html", re=r"inspect\.formatargspec\s*\(",
      nc="text = inspect.formatargspec(*spec)", c="text = str(inspect.signature(fn))"),
    r(id="python-ast-deprecated-nodes", title="Deprecated ast node classes", desc="ast.Str/Num/Bytes/NameConstant were removed in Python 3.12.",
      rationale="These ast node subclasses were folded into ast.Constant and raise AttributeError on 3.12+.", remediation="Use ast.Constant.",
      source="https://docs.python.org/3/whatsnew/3.12.html", re=r"\bast\.(Str|Num|Bytes|NameConstant|Ellipsis)\b",
      nc="if isinstance(node, ast.Str):", c="if isinstance(node, ast.Constant):"),
    r(id="python-typing-io-re", type="smell", qual="maint", sev="low", title="typing.io / typing.re", desc="typing.io and typing.re are deprecated.",
      rationale="These pseudo-submodules are deprecated; import the names from typing directly.", remediation="Use typing.IO / typing.Pattern directly.",
      source="https://docs.python.org/3/library/typing.html", re=r"\btyping\.(io|re)\b",
      nc="handle: typing.io.TextIO", c="handle: typing.TextIO"),
    r(id="python-typing-bytestring", type="smell", qual="maint", sev="low", title="typing.ByteString", desc="typing.ByteString is deprecated.",
      rationale="typing.ByteString is deprecated since Python 3.9; use a concrete type or collections.abc.Buffer.", remediation="Use bytes / bytearray, or collections.abc.Buffer.",
      source="https://docs.python.org/3/library/typing.html", re=r"\btyping\.ByteString\b",
      nc="data: typing.ByteString", c="data: bytes"),
    r(id="python-datetime-utcfromtimestamp", type="smell", qual="maint", sev="low", title="datetime.utcfromtimestamp()", desc="utcfromtimestamp returns a naive datetime and is deprecated.",
      rationale="utcfromtimestamp yields a naive value and is deprecated in Python 3.12.", remediation="Use datetime.fromtimestamp(ts, timezone.utc).",
      source="https://docs.python.org/3/library/datetime.html", re=r"datetime\.utcfromtimestamp\s*\(",
      nc="dt = datetime.utcfromtimestamp(ts)", c="dt = datetime.fromtimestamp(ts, timezone.utc)"),
    r(id="python-ssl-match-hostname", type="smell", qual="maint", sev="low", title="ssl.match_hostname()", desc="ssl.match_hostname is deprecated.",
      rationale="Manual hostname matching is deprecated; let SSLContext verify the hostname.", remediation="Set SSLContext.check_hostname = True and pass server_hostname.",
      source="https://docs.python.org/3/library/ssl.html", re=r"\bssl\.match_hostname\s*\(",
      nc="ssl.match_hostname(cert, host)", c="context.check_hostname = True"),
    r(id="python-unittest-makesuite", title="unittest makeSuite()", desc="makeSuite was removed in Python 3.13.",
      rationale="unittest.makeSuite raises AttributeError on Python 3.13+.", remediation="Use TestLoader.loadTestsFromTestCase.",
      source="https://docs.python.org/3/whatsnew/3.13.html", re=r"\bmakeSuite\s*\(",
      nc="suite = makeSuite(MyTest)", c="suite = loader.loadTestsFromTestCase(MyTest)"),
    r(id="python-array-tostring", title="array/ndarray tostring()", desc="tostring() was removed/deprecated in favor of tobytes().",
      rationale="array.tostring was removed in Python 3.9 and numpy tostring is deprecated.", remediation="Use tobytes().",
      source="https://docs.python.org/3/whatsnew/3.9.html", re=r"\.tostring\s*\(", nc="raw = arr.tostring()", c="raw = arr.tobytes()"),
    r(id="python-numpy-int0", type="smell", qual="maint", sev="low", title="numpy.int0 alias", desc="np.int0 is a deprecated alias.",
      rationale="np.int0/uint0 are deprecated aliases; use the sized integer type.", remediation="Use np.intp.",
      source="https://numpy.org/doc/stable/release/1.24.0-notes.html", re=r"\bnp\.int0\b", nc="i = np.int0", c="i = np.intp"),
    r(id="python-collections-abc-bytestring", type="smell", qual="maint", sev="low", title="collections.abc.ByteString", desc="collections.abc.ByteString is deprecated.",
      rationale="ByteString is deprecated since Python 3.12; use a concrete type or Buffer.", remediation="Use (bytes, bytearray) or collections.abc.Buffer.",
      source="https://docs.python.org/3/library/collections.abc.html", re=r"collections\.abc\.ByteString\b",
      nc="if isinstance(x, collections.abc.ByteString):", c="if isinstance(x, (bytes, bytearray)):"),
]
