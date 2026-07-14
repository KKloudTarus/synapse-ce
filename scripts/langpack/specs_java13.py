CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: injection / deserialization / traversal sinks (find-sec-bugs families).
RULES = [
    r(id="java-open-redirect", type="hotspot", qual="sec", sev="medium", cwe="CWE-601", owasp="A01:2021",
      title="Open redirect from request parameter", desc="Redirecting to a request-controlled URL enables open redirect.",
      rationale="sendRedirect with a value taken straight from the request lets an attacker choose the destination.",
      remediation="Redirect only to an allowlisted, validated destination.", source="https://cwe.mitre.org/data/definitions/601.html",
      re=r"\.sendRedirect\s*\([^)]*getParameter", nc='response.sendRedirect(request.getParameter("url"));', c="response.sendRedirect(allowlist.resolve(key));"),
    r(id="java-sql-string-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="SQL built by string concatenation", desc="Concatenating input into a JDBC query enables SQL injection.",
      rationale="A query assembled with + from input is a classic SQL-injection vector.",
      remediation="Use a PreparedStatement with bound parameters.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'\.(executeQuery|executeUpdate|execute)\s*\(\s*"[^"]*"\s*\+', nc='stmt.executeQuery("SELECT * FROM u WHERE id=" + id);',
      c='PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id=?");'),
    r(id="java-path-traversal-param", type="hotspot", qual="sec", sev="high", cwe="CWE-22", owasp="A01:2021",
      title="File path from request parameter", desc="Building a File from a request parameter enables path traversal.",
      rationale="A file path taken from the request can contain ../ to escape the intended directory.",
      remediation="Canonicalize and confirm the path stays within an allowed base directory.", source="https://cwe.mitre.org/data/definitions/22.html",
      re=r"new\s+File\s*\([^)]*getParameter", nc='File f = new File(request.getParameter("name"));', c="File f = new File(baseDir, safeName);"),
    r(id="java-command-exec-concat", type="vuln", qual="sec", sev="high", cwe="CWE-78", owasp="A03:2021",
      title="Command built by string concatenation", desc="Runtime.exec with a concatenated string enables command injection.",
      rationale="Passing a shell string built from input to exec allows command injection.",
      remediation="Use ProcessBuilder with an argument list.", source="https://cwe.mitre.org/data/definitions/78.html",
      re=r'\.exec\s*\(\s*"[^"]*"\s*\+', nc='Runtime.getRuntime().exec("ping " + host);', c='new ProcessBuilder("ping", host).start();'),
    r(id="java-ognl-injection", type="vuln", qual="sec", sev="high", cwe="CWE-917", owasp="A03:2021",
      title="OGNL expression evaluation", desc="Ognl.getValue evaluates an expression that may be attacker-controlled.",
      rationale="Evaluating an OGNL expression from input allows expression-language injection and RCE.",
      remediation="Do not evaluate OGNL from untrusted input.", source="https://cwe.mitre.org/data/definitions/917.html",
      re=r"\bOgnl\.getValue\s*\(", nc="Object v = Ognl.getValue(expr, root);", c="Object v = accessor.get(root, key);"),
    r(id="java-groovy-shell", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="GroovyShell evaluation", desc="GroovyShell executes arbitrary Groovy code.",
      rationale="Evaluating a script through GroovyShell on untrusted input allows code injection.",
      remediation="Avoid dynamic script evaluation, or use a strict SecureASTCustomizer sandbox.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"new\s+GroovyShell\s*\(", nc="new GroovyShell().evaluate(userScript);", c="Object r = compiledScript.run();"),
    r(id="java-xstream-deserialization", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="XStream deserialization", desc="XStream.fromXML can instantiate arbitrary types (gadget RCE).",
      rationale="An unhardened XStream deserializes arbitrary classes from XML, enabling RCE.",
      remediation="Configure XStream security permissions with a type allowlist.", source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"new\s+XStream\s*\(", nc="Object o = new XStream().fromXML(xml);", c="Object o = createHardenedXStream().fromXML(xml);"),
    r(id="java-log-injection", type="hotspot", qual="sec", sev="medium", cwe="CWE-117", owasp="A09:2021",
      title="Log entry from request parameter", desc="Logging raw request input allows log forging/injection.",
      rationale="Concatenating untrusted input into a log message allows newline/CRLF log forging.",
      remediation="Use parameterized logging and/or sanitize newlines from the value.", source="https://cwe.mitre.org/data/definitions/117.html",
      re=r"\.(info|debug|error|warn|trace)\s*\([^)]*getParameter", nc='log.info("user=" + request.getParameter("u"));', c='log.info("user={}", sanitize(user));'),
    r(id="java-format-string-var", type="hotspot", qual="sec", sev="medium", cwe="CWE-134", owasp="A03:2021",
      title="Externally controlled format string", desc="A non-literal format string can leak data or crash.",
      rationale="Passing a variable format string to String.format risks format-string attacks.",
      remediation="Use a constant format string and pass values as arguments.", source="https://cwe.mitre.org/data/definitions/134.html",
      re=r"String\.format\s*\(\s*[a-z]\w*\s*,", nc="String msg = String.format(userFormat, value);", c='String msg = String.format("%s", value);'),
    r(id="java-zip-slip", type="hotspot", qual="sec", sev="high", cwe="CWE-22", owasp="A01:2021",
      title="Zip Slip path traversal", desc="new File(dir, entry.getName()) can write outside dir.",
      rationale="A zip entry name with ../ escapes the extraction directory (Zip Slip).",
      remediation="Canonicalize the resolved path and verify it starts with the target directory.", source="https://cwe.mitre.org/data/definitions/22.html",
      re=r"new\s+File\s*\([^,)]+,\s*\w+\.getName\s*\(\s*\)\s*\)", nc="File out = new File(destDir, entry.getName());", c="File out = safeResolve(destDir, entry.getName());"),
]
