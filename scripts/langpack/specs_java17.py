CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: crypto/JWT/native-load/process/hostname sinks.
RULES = [
    r(id="java-securerandom-sha1prng", type="hotspot", qual="sec", sev="medium", cwe="CWE-330", owasp="A02:2021",
      title="SecureRandom SHA1PRNG", desc="Explicitly requesting SHA1PRNG pins a weaker algorithm.",
      rationale="SHA1PRNG is legacy; the platform default SecureRandom is stronger and self-seeding.",
      remediation="Use new SecureRandom() (or getInstanceStrong()).", source="https://cwe.mitre.org/data/definitions/330.html",
      re=r'getInstance\s*\(\s*"SHA1PRNG"', nc='SecureRandom r = SecureRandom.getInstance("SHA1PRNG");', c="SecureRandom r = new SecureRandom();"),
    r(id="java-jwt-signwith-none", type="vuln", qual="sec", sev="high", cwe="CWE-347", owasp="A02:2021",
      title="JWT signed with NONE", desc="Signing with the none algorithm produces an unsigned token.",
      rationale="A none-algorithm JWT has no signature and can be forged.",
      remediation="Sign with a real algorithm (HS256/RS256) and a key.", source="https://cwe.mitre.org/data/definitions/347.html",
      re=r"signWith\s*\(\s*SignatureAlgorithm\.NONE", nc="Jwts.builder().signWith(SignatureAlgorithm.NONE);", c="Jwts.builder().signWith(key, SignatureAlgorithm.HS256);"),
    r(id="java-system-load-param", type="hotspot", qual="sec", sev="high", cwe="CWE-114", owasp="A03:2021",
      title="Native library loaded from request", desc="System.load with request input loads an attacker-chosen library.",
      rationale="Loading a native library path from input can execute arbitrary native code.",
      remediation="Load only fixed, bundled library names.", source="https://cwe.mitre.org/data/definitions/114.html",
      re=r"System\.load\s*\([^)]*getParameter", nc='System.load(request.getParameter("lib"));', c='System.loadLibrary("mynative");'),
    r(id="java-processbuilder-param", type="hotspot", qual="sec", sev="high", cwe="CWE-78", owasp="A03:2021",
      title="ProcessBuilder command from request", desc="Building a process command from request input enables command injection.",
      rationale="A ProcessBuilder command taken from input lets an attacker choose the program/arguments.",
      remediation="Use a fixed program with validated, separate arguments.", source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"new\s+ProcessBuilder\s*\([^)]*getParameter", nc='new ProcessBuilder(request.getParameter("cmd")).start();', c='new ProcessBuilder("mytool", validatedArg).start();'),
    r(id="java-hibernate-sqlrestriction", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="Hibernate sqlRestriction concatenation", desc="sqlRestriction with a concatenated string enables SQL injection.",
      rationale="A raw SQL fragment built with + from input is injectable.",
      remediation="Use bound parameters instead of string concatenation.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'sqlRestriction\s*\(\s*"[^"]*"\s*\+', nc='criteria.add(Restrictions.sqlRestriction("name=\'" + n + "\'"));', c='criteria.add(Restrictions.eq("name", n));'),
    r(id="java-rsa-no-padding", type="vuln", qual="sec", sev="medium", cwe="CWE-780", owasp="A02:2021",
      title="RSA without OAEP padding", desc='RSA with NoPadding leaks structure and is insecure.',
      rationale="Textbook RSA (NoPadding) is deterministic and insecure; use OAEP.",
      remediation='Use "RSA/ECB/OAEPWithSHA-256AndMGF1Padding".', source="https://cwe.mitre.org/data/definitions/780.html",
      re=r'getInstance\s*\(\s*"RSA/[^"]*NoPadding"', nc='Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");', c='Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");'),
    r(id="java-okhttp-hostname-verifier-true", type="vuln", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="Hostname verifier that returns true", desc="A verifier lambda returning true accepts any hostname.",
      rationale="A hostname verifier that always returns true disables TLS identity checks (MITM).",
      remediation="Use the default verifier, or one that actually validates the hostname.", source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"hostnameVerifier\s*\([^;{]*->\s*true", nc="builder.hostnameVerifier((host, session) -> true);", c="builder.hostnameVerifier(OkHostnameVerifier.INSTANCE);"),
]
