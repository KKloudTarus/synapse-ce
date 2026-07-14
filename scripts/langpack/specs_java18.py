CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: LDAP filter injection + classloader path traversal.
RULES = [
    r(id="java-ldap-filter-concat", type="vuln", qual="sec", sev="high", cwe="CWE-90", owasp="A03:2021",
      title="LDAP filter built by concatenation", desc="A search filter assembled with + from input enables LDAP injection.",
      rationale="Concatenating untrusted input into an LDAP search filter allows filter manipulation.",
      remediation="Escape the value with an LDAP encoder, or use parameterized search.", source="https://cwe.mitre.org/data/definitions/90.html",
      re=r'\.search\s*\([^)]*"[^"]*"\s*\+', nc='ctx.search(base, "(uid=" + user + ")", controls);', c="ctx.search(base, filter, args, controls);"),
    r(id="java-classloader-getresource-param", type="hotspot", qual="sec", sev="medium", cwe="CWE-22", owasp="A01:2021",
      title="getResource path from request", desc="Loading a resource named by request input enables path traversal.",
      rationale="A classloader/servlet resource path taken from input can escape the intended location.",
      remediation="Map the requested name through an allowlist.", source="https://cwe.mitre.org/data/definitions/22.html",
      re=r"getResource\s*\([^)]*getParameter", nc='URL u = getClass().getResource(request.getParameter("f"));', c="URL u = getClass().getResource(allowlist.resolve(key));"),
]
