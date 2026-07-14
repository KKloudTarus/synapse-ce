CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: reflected XSS from request header/URI + weak PBE scheme.
RULES = [
    r(id="java-write-request-header", type="hotspot", qual="sec", sev="high", cwe="CWE-79", owasp="A03:2021",
      title="Request header written to response", desc="Echoing a request header to the response enables reflected XSS.",
      rationale="A request header written to the response without encoding is reflected XSS.",
      remediation="HTML-encode the value before writing it.", source="https://cwe.mitre.org/data/definitions/79.html",
      re=r"\.write\s*\([^)]*getHeader", nc='out.write(request.getHeader("Referer"));', c="out.write(escapeHtml(referer));"),
    r(id="java-write-request-uri", type="hotspot", qual="sec", sev="high", cwe="CWE-79", owasp="A03:2021",
      title="Request URI written to response", desc="Echoing the request URI to the response enables reflected XSS.",
      rationale="The request URI/URL is attacker-influenced; writing it unencoded is reflected XSS.",
      remediation="HTML-encode the value before writing it.", source="https://cwe.mitre.org/data/definitions/79.html",
      re=r"\.write\s*\([^)]*getRequestUR[IL]", nc="out.write(request.getRequestURI());", c="out.write(escapeHtml(uri));"),
    r(id="java-pbe-sha1", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="PBEWithSHA1 key derivation", desc="PBE schemes built on SHA-1/DES are weak.",
      rationale="PBEWithSHA1And* schemes use weak primitives and low iteration defaults.",
      remediation="Use PBKDF2WithHmacSHA256 with a high iteration count.", source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'"PBEWithSHA1', nc='SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");', c='SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");'),
]
