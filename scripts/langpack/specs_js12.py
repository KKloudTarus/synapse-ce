CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="js-setimmediate-string", type="hotspot", qual="sec", sev="medium", cwe="CWE-95", owasp="A03:2021",
      title="setImmediate with a string argument", desc="setImmediate(\"code\") evaluates the string like eval.",
      rationale="Passing a string to setImmediate implicitly calls eval on it.",
      remediation="Pass a function reference: setImmediate(fn).",
      source="https://cwe.mitre.org/data/definitions/95.html",
      re=r'''setImmediate\s*\(\s*["'`]''', nc='setImmediate("run()");', c="setImmediate(run);"),
]
