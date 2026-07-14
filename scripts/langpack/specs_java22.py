CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="java-hardcoded-tmp-path", type="hotspot", qual="sec", sev="low", cwe="CWE-377", owasp="A01:2021",
      title="Hardcoded /tmp path", desc="A literal /tmp path is predictable and world-writable.",
      rationale="Fixed /tmp paths enable symlink and race attacks by other local users.",
      remediation="Use Files.createTempFile / File.createTempFile.",
      source="https://cwe.mitre.org/data/definitions/377.html",
      re=r'"/tmp/', nc='File lock = new File("/tmp/app.lock");', c='File lock = File.createTempFile("app", ".lock");'),
]
