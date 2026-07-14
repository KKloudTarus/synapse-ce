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
    r(id="js-buffer-constructor", type="hotspot", qual="sec", sev="medium", cwe="CWE-665", owasp="A05:2021",
      title="Deprecated Buffer() constructor", desc="new Buffer(size) allocates uninitialized memory that may leak data.",
      rationale="The legacy Buffer constructor returns uninitialized memory and is deprecated for safety reasons.",
      remediation="Use Buffer.alloc(size) (zero-filled) or Buffer.from(data).",
      source="https://cwe.mitre.org/data/definitions/665.html",
      re=r"new\s+Buffer\s*\(", nc="const buf = new Buffer(64);", c="const buf = Buffer.alloc(64);"),
]
