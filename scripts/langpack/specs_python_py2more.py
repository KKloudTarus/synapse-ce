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


SRC = "https://docs.python.org/3/whatsnew/3.0.html"


# Python quality pack: Python-2 builtins / methods removed in Python 3 (each fails at runtime on 3).
RULES = [
    r(id="python-apply-builtin", title="Python 2 apply()", desc="The apply builtin was removed in Python 3.",
      rationale="apply(f, args) raises NameError on Python 3.", remediation="Call f(*args, **kwargs) directly.",
      source=SRC, re=r"(^|[^.\w])apply\s*\(", nc="result = apply(func, args)", c="result = func(*args)"),
    r(id="python-execfile-builtin", title="Python 2 execfile()", desc="execfile was removed in Python 3.",
      rationale="execfile raises NameError on Python 3.", remediation="Use exec(open(path).read()) or import the module.",
      source=SRC, re=r"\bexecfile\s*\(", nc='execfile("setup.py")', c='exec(open("setup.py").read())'),
    r(id="python-reload-builtin", title="Python 2 reload()", desc="The reload builtin moved to importlib.",
      rationale="reload() raises NameError on Python 3.", remediation="Use importlib.reload(module).",
      source=SRC, re=r"(^|[^.\w])reload\s*\(", nc="reload(config)", c="importlib.reload(config)"),
    r(id="python-file-builtin", title="Python 2 file()", desc="The file builtin was removed in Python 3.",
      rationale="file() raises NameError on Python 3.", remediation="Use open() to obtain a file object.",
      source=SRC, re=r"(^|[^.\w])file\s*\(", nc="handle = file(path)", c="handle = open(path)"),
    r(id="python-long-builtin", title="Python 2 long()", desc="The long type was merged into int.",
      rationale="long() raises NameError on Python 3.", remediation="Use int(); Python 3 ints are unbounded.",
      source=SRC, re=r"(^|[^.\w])long\s*\(", nc="value = long(count)", c="value = int(count)"),
    r(id="python-cmp-builtin", title="Python 2 cmp()", desc="The cmp builtin was removed in Python 3.",
      rationale="cmp() raises NameError on Python 3.", remediation="Use (a > b) - (a < b), or a key function.",
      source=SRC, re=r"(^|[^.\w])cmp\s*\(", nc="order = cmp(a, b)", c="order = (a > b) - (a < b)"),
    r(id="python-buffer-builtin", title="Python 2 buffer()", desc="The buffer builtin was removed in Python 3.",
      rationale="buffer() raises NameError on Python 3.", remediation="Use memoryview().",
      source=SRC, re=r"(^|[^.\w])buffer\s*\(", nc="view = buffer(data)", c="view = memoryview(data)"),
    r(id="python-intern-builtin", title="Python 2 intern()", desc="The intern builtin moved to sys.intern.",
      rationale="intern() raises NameError on Python 3.", remediation="Use sys.intern().",
      source=SRC, re=r"(^|[^.\w])intern\s*\(", nc="key = intern(name)", c="key = sys.intern(name)"),
    r(id="python-sys-maxint", title="Python 2 sys.maxint", desc="sys.maxint was replaced by sys.maxsize.",
      rationale="sys.maxint raises AttributeError on Python 3.", remediation="Use sys.maxsize.",
      source=SRC, re=r"\bsys\.maxint\b", nc="limit = sys.maxint", c="limit = sys.maxsize"),
    r(id="python-types-py2", title="Python 2 types.*Type", desc="types.StringType and friends were removed in Python 3.",
      rationale="types.StringType/IntType/etc raise AttributeError on Python 3.", remediation="Compare against the builtin type (str, int, ...).",
      source=SRC, re=r"\btypes\.(StringType|IntType|LongType|ListType|DictType|TupleType|UnicodeType|FloatType|BooleanType)\b",
      nc="if kind == types.StringType:", c="if kind is str:"),
    r(id="python-itertools-imap", title="Python 2 itertools.imap", desc="itertools.imap was removed in Python 3.",
      rationale="itertools.imap raises AttributeError on Python 3; map is lazy.", remediation="Use the builtin map().",
      source=SRC, re=r"\bitertools\.imap\b", nc="out = itertools.imap(f, xs)", c="out = map(f, xs)"),
    r(id="python-itertools-ifilter", title="Python 2 itertools.ifilter", desc="itertools.ifilter was removed in Python 3.",
      rationale="itertools.ifilter raises AttributeError on Python 3; filter is lazy.", remediation="Use the builtin filter().",
      source=SRC, re=r"\bitertools\.ifilter\b", nc="out = itertools.ifilter(pred, xs)", c="out = filter(pred, xs)"),
    r(id="python-dict-view-methods", title="Python 2 dict.view* methods", desc="viewkeys/viewvalues/viewitems were removed in Python 3.",
      rationale="These raise AttributeError on Python 3; keys/values/items already return views.", remediation="Use keys()/values()/items().",
      source=SRC, re=r"\.view(keys|values|items)\s*\(", nc="for k in data.viewkeys():", c="for k in data.keys():"),
    r(id="python-nonzero-method", title="Python 2 __nonzero__", desc="__nonzero__ was renamed __bool__ in Python 3.",
      rationale="Python 3 calls __bool__, so __nonzero__ is never used.", remediation="Rename the method to __bool__.",
      source=SRC, re=r"def\s+__nonzero__\s*\(", nc="def __nonzero__(self):", c="def __bool__(self):"),
    r(id="python-unicode-method", title="Python 2 __unicode__", desc="__unicode__ has no effect in Python 3.",
      rationale="Python 3 uses __str__ for text, so __unicode__ is dead code.", remediation="Move the logic into __str__.",
      source=SRC, re=r"def\s+__unicode__\s*\(", nc="def __unicode__(self):", c="def __str__(self):"),
    r(id="python-div-method", title="Python 2 __div__", desc="__div__ was replaced by __truediv__ in Python 3.",
      rationale="Python 3 dispatches / to __truediv__, so __div__ is never called.", remediation="Rename to __truediv__.",
      source=SRC, re=r"def\s+__div__\s*\(", nc="def __div__(self, other):", c="def __truediv__(self, other):"),
    r(id="python-getslice-method", title="Python 2 __getslice__", desc="__getslice__ was removed in Python 3.",
      rationale="Python 3 passes slice objects to __getitem__, so __getslice__ is never called.", remediation="Handle slices in __getitem__.",
      source=SRC, re=r"def\s+__getslice__\s*\(", nc="def __getslice__(self, i, j):", c="def __getitem__(self, index):"),
    r(id="python-cmp-method", title="Python 2 __cmp__", desc="__cmp__ was removed in Python 3.",
      rationale="Python 3 uses rich comparison methods, so __cmp__ is never called.", remediation="Implement __eq__/__lt__ (functools.total_ordering helps).",
      source=SRC, re=r"def\s+__cmp__\s*\(", nc="def __cmp__(self, other):", c="def __lt__(self, other):"),
    r(id="python-coerce-method", title="Python 2 __coerce__", desc="__coerce__ was removed in Python 3.",
      rationale="Python 3 has no numeric coercion protocol, so __coerce__ is dead code.", remediation="Remove __coerce__ and handle types in the operator methods.",
      source=SRC, re=r"def\s+__coerce__\s*\(", nc="def __coerce__(self, other):", c="def __add__(self, other):"),
    r(id="python-idiv-method", title="Python 2 __idiv__", desc="__idiv__ was replaced by __itruediv__ in Python 3.",
      rationale="Python 3 dispatches /= to __itruediv__, so __idiv__ is never called.", remediation="Rename to __itruediv__.",
      source=SRC, re=r"def\s+__idiv__\s*\(", nc="def __idiv__(self, other):", c="def __itruediv__(self, other):"),
]
