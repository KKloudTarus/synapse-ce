CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: Spring Security config weakening + weak password encoders + injection sinks.
RULES = [
    r(id="java-spring-frame-options-disable", type="hotspot", qual="sec", sev="medium", cwe="CWE-1021", owasp="A05:2021",
      title="X-Frame-Options disabled", desc="Disabling frame options removes clickjacking protection.",
      rationale="frameOptions().disable() lets the app be framed, enabling clickjacking.",
      remediation="Keep frame options (sameOrigin/deny).", source="https://cwe.mitre.org/data/definitions/1021.html",
      re=r"\.frameOptions\s*\(\s*\)\s*\.\s*disable", nc="http.headers().frameOptions().disable();", c="http.headers().frameOptions().sameOrigin();"),
    r(id="java-noop-password-encoder", type="vuln", qual="sec", sev="high", cwe="CWE-916", owasp="A02:2021",
      title="NoOpPasswordEncoder", desc="NoOpPasswordEncoder stores passwords in plaintext.",
      rationale="NoOpPasswordEncoder performs no hashing, so passwords are stored in clear.",
      remediation="Use BCryptPasswordEncoder / Argon2 / PBKDF2.", source="https://cwe.mitre.org/data/definitions/916.html",
      re=r"\bNoOpPasswordEncoder\b", nc="PasswordEncoder e = NoOpPasswordEncoder.getInstance();", c="PasswordEncoder e = new BCryptPasswordEncoder();"),
    r(id="java-weak-password-encoder", type="vuln", qual="sec", sev="high", cwe="CWE-916", owasp="A02:2021",
      title="Weak Spring password encoder", desc="MD5/SHA password encoders are fast and unsalted-by-default.",
      rationale="Md5/Sha/MessageDigest password encoders are deprecated and unfit for password storage.",
      remediation="Use BCryptPasswordEncoder / Argon2 / PBKDF2.", source="https://cwe.mitre.org/data/definitions/916.html",
      re=r"new\s+(Md5PasswordEncoder|ShaPasswordEncoder|MessageDigestPasswordEncoder)\s*\(", nc="PasswordEncoder e = new Md5PasswordEncoder();", c="PasswordEncoder e = new BCryptPasswordEncoder();"),
    r(id="java-standard-password-encoder", type="vuln", qual="sec", sev="medium", cwe="CWE-916", owasp="A02:2021",
      title="StandardPasswordEncoder", desc="StandardPasswordEncoder (SHA-256) is deprecated for passwords.",
      rationale="StandardPasswordEncoder is deprecated and not resistant to modern cracking.",
      remediation="Use BCryptPasswordEncoder / Argon2 / PBKDF2.", source="https://cwe.mitre.org/data/definitions/916.html",
      re=r"new\s+StandardPasswordEncoder\s*\(", nc="PasswordEncoder e = new StandardPasswordEncoder();", c="PasswordEncoder e = new BCryptPasswordEncoder();"),
    r(id="java-mysql-allow-load-local", type="hotspot", qual="sec", sev="medium", cwe="CWE-611", owasp="A05:2021",
      title="MySQL allowLoadLocalInfile", desc="allowLoadLocalInfile=true lets the server read local files.",
      rationale="Enabling LOAD DATA LOCAL exposes the client to a malicious/compromised MySQL server reading local files.",
      remediation="Do not enable allowLoadLocalInfile unless strictly required.", source="https://cwe.mitre.org/data/definitions/611.html",
      re=r"allowLoadLocalInfile\s*=\s*true", nc='url = "jdbc:mysql://h/db?allowLoadLocalInfile=true";', c='url = "jdbc:mysql://h/db";'),
    r(id="java-request-dispatcher-param", type="hotspot", qual="sec", sev="high", cwe="CWE-22", owasp="A01:2021",
      title="RequestDispatcher path from request", desc="Forwarding to a request-controlled path enables traversal.",
      rationale="Building a dispatcher path from a request parameter allows path traversal / access to hidden resources.",
      remediation="Map the requested value through an allowlist before dispatching.", source="https://cwe.mitre.org/data/definitions/22.html",
      re=r"getRequestDispatcher\s*\([^)]*getParameter", nc='request.getRequestDispatcher(request.getParameter("page")).forward(req, resp);', c="request.getRequestDispatcher(allowlist.resolve(key)).forward(req, resp);"),
    r(id="java-exec-shell-array", type="hotspot", qual="sec", sev="high", cwe="CWE-78", owasp="A03:2021",
      title="Runtime.exec invoking a shell", desc="Executing sh/bash/cmd with -c runs a shell command line.",
      rationale="Spawning a shell to run a command line invites command injection when the command is built from input.",
      remediation="Invoke the target program directly with an argument list, not via a shell.", source="https://cwe.mitre.org/data/definitions/78.html",
      re=r'\.exec\s*\(\s*new\s+String\s*\[\s*\]\s*\{\s*"(sh|bash|cmd|/bin/sh|/bin/bash)"', nc='Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});', c='new ProcessBuilder("mytool", arg).start();'),
    r(id="java-cors-allowed-methods-wildcard", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="Wildcard CORS methods", desc="allowedMethods(\"*\") permits any HTTP method cross-origin.",
      rationale="A wildcard method list broadens the CORS attack surface.",
      remediation="List the specific methods the endpoint supports.", source="https://cwe.mitre.org/data/definitions/942.html",
      re=r'allowedMethods\s*\(\s*"\*"', nc='config.allowedMethods("*");', c='config.allowedMethods("GET", "POST");'),
    r(id="java-content-type-options-disable", type="hotspot", qual="sec", sev="medium", cwe="CWE-693", owasp="A05:2021",
      title="X-Content-Type-Options disabled", desc="Disabling contentTypeOptions allows MIME sniffing.",
      rationale="Turning off X-Content-Type-Options: nosniff enables MIME-sniffing attacks.",
      remediation="Keep contentTypeOptions enabled.", source="https://cwe.mitre.org/data/definitions/693.html",
      re=r"contentTypeOptions\s*\(\s*\)\s*\.\s*disable", nc="http.headers().contentTypeOptions().disable();", c="http.headers();"),
    r(id="java-hsts-disable", type="hotspot", qual="sec", sev="medium", cwe="CWE-319", owasp="A05:2021",
      title="HSTS disabled", desc="Disabling HSTS lets browsers connect over plaintext HTTP.",
      rationale="Turning off HTTP Strict Transport Security permits protocol downgrade.",
      remediation="Keep HSTS enabled with an appropriate max-age.", source="https://cwe.mitre.org/data/definitions/319.html",
      re=r"httpStrictTransportSecurity\s*\(\s*\)\s*\.\s*disable", nc="http.headers().httpStrictTransportSecurity().disable();", c="http.headers();"),
]
