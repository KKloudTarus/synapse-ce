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
    r(id="java-spring-permit-all-requests", type="hotspot", qual="sec", sev="high", cwe="CWE-862", owasp="A01:2021",
      title="Permit-all on every request", desc="anyRequest().permitAll() leaves all endpoints unauthenticated.",
      rationale="Permitting all requests removes authentication from every endpoint.",
      remediation="Require authentication by default; permit only the specific public endpoints.",
      source="https://cwe.mitre.org/data/definitions/862.html",
      re=r"anyRequest\s*\(\s*\)\s*\.\s*permitAll", nc="http.authorizeHttpRequests(a -> a.anyRequest().permitAll());", c="http.authorizeHttpRequests(a -> a.anyRequest().authenticated());"),
    r(id="java-cors-allowed-headers-wildcard", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="Wildcard CORS headers", desc="allowedHeaders(\"*\") permits any request header cross-origin.",
      rationale="A wildcard allowed-headers list broadens the CORS attack surface.",
      remediation="List the specific headers the endpoint needs.",
      source="https://cwe.mitre.org/data/definitions/942.html",
      re=r'allowedHeaders\s*\(\s*"\*"', nc='config.allowedHeaders("*");', c='config.allowedHeaders("Content-Type", "Authorization");'),
]
