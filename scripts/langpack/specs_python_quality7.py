CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality pack, batch 7: flake8-comprehensions/bugbear, pandas-vet, numpy deprecations, naming.
RULES = [
    r(id="python-comprehension-in-call", type="smell", qual="maint", sev="low", cwe="",
      title="List comprehension inside any/all/sum", desc="A generator expression avoids building an intermediate list.",
      rationale="any/all/sum short-circuit or stream, so a list comprehension wastes memory (flake8-comprehensions C419).",
      remediation="Drop the brackets to pass a generator: any(x for x in items).",
      source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\b(any|all|sum|sorted|min|max)\s*\(\s*\[", nc="if any([x > 0 for x in items]):", c="if any(x > 0 for x in items):"),
    r(id="python-unnecessary-tuple-call", type="smell", qual="maint", sev="low", cwe="",
      title="tuple() around a tuple literal", desc="tuple((...)) is just (...).",
      rationale="Wrapping a tuple literal in tuple() is redundant work.",
      remediation="Use the tuple literal directly.",
      source="https://github.com/adamchainz/flake8-comprehensions",
      re=r"\btuple\s*\(\s*\(", nc="point = tuple((1, 2))", c="point = (1, 2)"),
    r(id="python-strip-multichar", type="bug", qual="rel", sev="medium", cwe="",
      title="Multi-character strip argument", desc="str.strip(\"ab\") removes any of the characters a, b, not the substring.",
      rationale="strip/lstrip/rstrip treat the argument as a character set, a frequent misunderstanding (bugbear B005).",
      remediation="Use removeprefix/removesuffix (3.9+) to strip a substring.",
      source="https://github.com/PyCQA/flake8-bugbear",
      re=r'''\.(strip|lstrip|rstrip)\s*\(\s*["'][^"']{2,}["']\s*\)''', nc='name = value.strip("prefix")', c='name = value.removeprefix("prefix")'),
    r(id="python-class-name-not-capwords", type="smell", qual="maint", sev="low", cwe="",
      title="Class name not in CapWords", desc="Class names should use the CapWords convention.",
      rationale="PEP 8 recommends CapWords for class names; a lowercase initial is inconsistent (pep8-naming N801).",
      remediation="Rename the class to CapWords, e.g. MyClass.",
      source="https://peps.python.org/pep-0008/#class-names",
      re=r"\bclass\s+[a-z]", nc="class myModel:", c="class MyModel:"),
    r(id="python-pandas-inplace", type="smell", qual="maint", sev="low", cwe="",
      title="pandas inplace=True", desc="inplace mutation is discouraged and often no faster.",
      rationale="pandas inplace=True hinders method chaining and is being deprecated (pandas-vet PD002).",
      remediation="Assign the result: df = df.drop(...).",
      source="https://github.com/deppen8/pandas-vet",
      re=r"inplace\s*=\s*True\b", nc="df.drop(columns=[c], inplace=True)", c="df = df.drop(columns=[c])"),
    r(id="python-pandas-ix", type="bug", qual="rel", sev="medium", cwe="",
      title="Deprecated pandas .ix indexer", desc=".ix was removed from pandas.",
      rationale="The ambiguous .ix indexer was removed; use .loc or .iloc.",
      remediation="Use .loc (label) or .iloc (position).",
      source="https://pandas.pydata.org/docs/whatsnew/v1.0.0.html",
      re=r"\.ix\s*\[", nc="row = df.ix[0]", c="row = df.iloc[0]"),
    r(id="python-numpy-deprecated-alias", type="bug", qual="rel", sev="medium", cwe="",
      title="Deprecated numpy type alias", desc="np.int/np.float/np.bool were removed in NumPy 1.24.",
      rationale="These aliases now raise AttributeError; use the explicit dtype or the Python builtin.",
      remediation="Use np.float64 / np.int_ / bool as appropriate.",
      source="https://numpy.org/doc/stable/release/1.24.0-notes.html",
      re=r"\bnp\.(bool|int|float|object|str|long)\b", nc="arr = np.zeros(3, dtype=np.float)", c="arr = np.zeros(3, dtype=np.float64)"),
]
