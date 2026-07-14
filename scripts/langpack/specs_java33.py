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
    r(id="java-cleartext-url-http", type="hotspot", qual="sec", sev="medium", cwe="CWE-319", owasp="A02:2021",
      title="Cleartext HTTP URL", desc="Constructing a URL with the http:// scheme sends traffic unencrypted.",
      rationale="An http:// endpoint transmits data in cleartext, exposing it to interception and tampering.",
      remediation="Use https:// for network endpoints.", source="https://cwe.mitre.org/data/definitions/319.html",
      re=r'new\s+URL\s*\(\s*"http://', nc='new URL("http://api.example.com/data");', c='new URL("https://api.example.com/data");'),
]
