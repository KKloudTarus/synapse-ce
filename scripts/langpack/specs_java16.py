CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: XPath/regex/reflection injection, header CRLF, HQL injection, reflected XSS.
RULES = [
    r(id="java-pattern-from-param", type="hotspot", qual="sec", sev="medium", cwe="CWE-1333", owasp="A03:2021",
      title="Regex compiled from request", desc="Pattern.compile on request input risks ReDoS/injection.",
      rationale="A regex built from untrusted input can be crafted to cause catastrophic backtracking (ReDoS).",
      remediation="Use a fixed pattern, or validate/limit the input.", source="https://cwe.mitre.org/data/definitions/1333.html",
      re=r"Pattern\.compile\s*\([^)]*getParameter", nc='Pattern p = Pattern.compile(request.getParameter("re"));', c="Pattern p = Pattern.compile(FIXED_RE);"),
    r(id="java-xpath-eval-param", type="hotspot", qual="sec", sev="high", cwe="CWE-643", owasp="A03:2021",
      title="XPath evaluated from request", desc="Evaluating an XPath built from input enables XPath injection.",
      rationale="An XPath expression built from untrusted input can be manipulated to extract other nodes.",
      remediation="Use a fixed expression with variable bindings.", source="https://cwe.mitre.org/data/definitions/643.html",
      re=r"\.evaluate\s*\([^)]*getParameter", nc='String v = (String) xpath.evaluate(request.getParameter("q"), doc);', c="String v = (String) xpath.evaluate(FIXED_XPATH, doc);"),
    r(id="java-classforname-param", type="hotspot", qual="sec", sev="high", cwe="CWE-470", owasp="A03:2021",
      title="Class.forName from request", desc="Loading a class named by request input is unsafe reflection.",
      rationale="Instantiating an attacker-chosen class can invoke unexpected code paths.",
      remediation="Map the input to an allowlisted class.", source="https://cwe.mitre.org/data/definitions/470.html",
      re=r"Class\.forName\s*\([^)]*getParameter", nc='Class<?> c = Class.forName(request.getParameter("cls"));', c="Class<?> c = ALLOWED.get(key);"),
    r(id="java-header-crlf-param", type="hotspot", qual="sec", sev="medium", cwe="CWE-113", owasp="A03:2021",
      title="Response header from request", desc="Setting a header value from request input allows CRLF/header injection.",
      rationale="Unsanitized request input in a response header can inject CRLF and split the response.",
      remediation="Strip CR/LF (or reject) before writing the header value.", source="https://cwe.mitre.org/data/definitions/113.html",
      re=r"\.(setHeader|addHeader)\s*\([^,]+,\s*[^)]*getParameter", nc='response.setHeader("X-Prev", request.getParameter("p"));', c='response.setHeader("X-Prev", sanitize(p));'),
    r(id="java-hql-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="HQL/JPQL built by concatenation", desc="createQuery with a concatenated string enables HQL injection.",
      rationale="A Hibernate/JPA query assembled with + from input is injectable.",
      remediation="Use named parameters (:param) and setParameter.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'createQuery\s*\(\s*"[^"]*"\s*\+', nc='session.createQuery("FROM User WHERE name=\'" + name + "\'");', c='session.createQuery("FROM User WHERE name=:name");'),
    r(id="java-native-sql-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="Native SQL query built by concatenation", desc="createSQLQuery/createNativeQuery with concatenation enables SQL injection.",
      rationale="A native SQL query assembled with + from input is injectable.",
      remediation="Use bound parameters.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'create(SQLQuery|NativeQuery)\s*\(\s*"[^"]*"\s*\+', nc='session.createSQLQuery("SELECT * FROM u WHERE id=" + id);', c='session.createNativeQuery("SELECT * FROM u WHERE id=:id");'),
    r(id="java-servlet-print-param", type="hotspot", qual="sec", sev="high", cwe="CWE-79", owasp="A03:2021",
      title="Request parameter written to response", desc="Writing request input to the response body enables reflected XSS.",
      rationale="Echoing untrusted input to the response without encoding is reflected XSS.",
      remediation="HTML-encode the value before writing it.", source="https://cwe.mitre.org/data/definitions/79.html",
      re=r"\.print(ln)?\s*\([^)]*getParameter", nc='out.println(request.getParameter("msg"));', c="out.println(escapeHtml(msg));"),
]
