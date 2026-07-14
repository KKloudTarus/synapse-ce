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
    r(id="java-x-forwarded-for-trust", type="hotspot", qual="sec", sev="medium", cwe="CWE-348", owasp="A07:2021",
      title="Trusting the X-Forwarded-For header", desc="X-Forwarded-For is client-controlled and easily spoofed.",
      rationale="Using X-Forwarded-For for the client IP (auth, rate limiting) can be spoofed unless set by a trusted proxy.",
      remediation="Use the connection's remote address, or only trust XFF from a known proxy.",
      source="https://cwe.mitre.org/data/definitions/348.html",
      re=r'getHeader\s*\(\s*"X-Forwarded-For"', nc='String ip = request.getHeader("X-Forwarded-For");', c="String ip = request.getRemoteAddr();"),
]
