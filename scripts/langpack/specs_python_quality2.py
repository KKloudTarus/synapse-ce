CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python quality/correctness pack, second batch: pylint idioms. Clean-room prose.
RULES = [
    r(id="python-consider-iterating-dict", type="smell", qual="maint", sev="low", cwe="",
      title="Iterating dict.keys()", desc="Looping over dict.keys() is redundant; iterate the dict directly.",
      rationale="Iterating a mapping already yields its keys, so .keys() is unnecessary.",
      remediation="Write for key in mapping.",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/refactor/consider-iterating-dictionary.html",
      re=r"\bin\s+\w+\.keys\s*\(\s*\)\s*:", nc="for k in config.keys():", c="for k in config:"),
    r(id="python-dict-get-none-default", type="smell", qual="maint", sev="low", cwe="",
      title="Redundant None default in dict.get", desc="dict.get(key, None) is the same as dict.get(key).",
      rationale="None is already the default second argument to dict.get, so passing it adds noise.",
      remediation="Call mapping.get(key).",
      source="https://docs.python.org/3/library/stdtypes.html#dict.get",
      re=r"\.get\s*\([^,)]+,\s*None\s*\)", nc='value = data.get("name", None)', c='value = data.get("name")'),
    r(id="python-consider-sys-exit", type="smell", qual="maint", sev="low", cwe="",
      title="Builtin exit() used", desc="The builtin exit() is meant for the interactive shell, not programs.",
      rationale="exit()/quit() are added by the site module and may be absent; use sys.exit in code.",
      remediation="Import sys and call sys.exit(code).",
      source="https://pylint.readthedocs.io/en/stable/user_guide/messages/refactor/consider-using-sys-exit.html",
      re=r"(^|[^.\w])exit\s*\(", nc="exit(1)", c="sys.exit(1)"),
    r(id="python-redundant-u-prefix", type="smell", qual="maint", sev="low", cwe="",
      title="Redundant u string prefix", desc="The u\"\" prefix is a no-op in Python 3.",
      rationale="All Python 3 str literals are unicode, so the u prefix is redundant.",
      remediation="Remove the u prefix.",
      source="https://peps.python.org/pep-0008/",
      re=r'''\bu["']''', nc='label = u"text"', c='label = "text"'),
]
