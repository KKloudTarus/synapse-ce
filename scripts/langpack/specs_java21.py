CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: TLS endpoint identification, servlet path, LDAP anonymous bind, upload filename.
RULES = [
    r(id="java-tls-no-endpoint-identification", type="vuln", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="TLS endpoint identification disabled", desc="Setting the algorithm to null disables hostname verification.",
      rationale="A null endpoint-identification algorithm skips hostname verification, enabling MITM.",
      remediation='Set it to "HTTPS".', source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"setEndpointIdentificationAlgorithm\s*\(\s*null", nc="params.setEndpointIdentificationAlgorithm(null);", c='params.setEndpointIdentificationAlgorithm("HTTPS");'),
    r(id="java-getrealpath-param", type="hotspot", qual="sec", sev="high", cwe="CWE-22", owasp="A01:2021",
      title="getRealPath from request parameter", desc="Resolving a real path from request input enables path traversal.",
      rationale="A servlet real path built from input can escape the web root.",
      remediation="Map the requested value through an allowlist.", source="https://cwe.mitre.org/data/definitions/22.html",
      re=r"getRealPath\s*\([^)]*getParameter", nc='String p = ctx.getRealPath(request.getParameter("f"));', c='String p = ctx.getRealPath("/WEB-INF/data");'),
    r(id="java-ldap-anonymous-auth", type="hotspot", qual="sec", sev="medium", cwe="CWE-287", owasp="A07:2021",
      title="LDAP anonymous authentication", desc="SECURITY_AUTHENTICATION set to none disables LDAP auth.",
      rationale="An LDAP context with authentication none binds anonymously.",
      remediation='Use "simple" (over TLS) or a stronger SASL mechanism with credentials.', source="https://cwe.mitre.org/data/definitions/287.html",
      re=r'SECURITY_AUTHENTICATION[^;]*"none"', nc='env.put(Context.SECURITY_AUTHENTICATION, "none");', c='env.put(Context.SECURITY_AUTHENTICATION, "simple");'),
    r(id="java-upload-original-filename-path", type="hotspot", qual="sec", sev="high", cwe="CWE-22", owasp="A01:2021",
      title="File built from upload filename", desc="Using the client filename in a path enables traversal.",
      rationale="getOriginalFilename is client-controlled and can contain ../ to escape the upload directory.",
      remediation="Generate a safe server-side name; never trust the client filename.", source="https://cwe.mitre.org/data/definitions/22.html",
      re=r"new\s+File\s*\([^)]*getOriginalFilename", nc="File dest = new File(uploadDir, part.getOriginalFilename());", c="File dest = new File(uploadDir, safeGeneratedName);"),
]
