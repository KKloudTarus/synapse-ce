CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack, framework families: Spring Security (CSRF/CORS), Jackson / SnakeYAML / SpEL
# (deserialization + expression injection), JJWT, Guava hashing, JCA key generation. Concept origins
# cited (CWE, OWASP, find-sec-bugs, framework docs); prose authored clean-room.
RULES = [
    r(id="java-cors-allow-all-origin", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="Wildcard CORS origin", desc="Allowing origin \"*\" lets any site read authenticated responses.",
      rationale="A wildcard allowed-origin defeats the same-origin policy for the response.",
      remediation="Configure an explicit allowlist of trusted origins.",
      source="https://cwe.mitre.org/data/definitions/942.html",
      re=r'\b(addAllowedOrigin|allowedOrigins)\s*\(\s*"\*"', nc='config.addAllowedOrigin("*");',
      c='config.addAllowedOrigin("https://app.example.com");'),
    r(id="java-csrf-disabled", type="hotspot", qual="sec", sev="medium", cwe="CWE-352", owasp="A01:2021",
      title="CSRF protection disabled", desc="Disabling Spring Security CSRF protection exposes state-changing endpoints.",
      rationale="Turning off CSRF lets a malicious site forge authenticated state-changing requests.",
      remediation="Keep CSRF protection on for cookie/session-authenticated endpoints.",
      source="https://cwe.mitre.org/data/definitions/352.html",
      re=r"csrf\s*\(\s*\)\s*\.\s*disable", nc="http.csrf().disable();", c="http.csrf(Customizer.withDefaults());"),
    r(id="java-jjwt-unsigned", type="vuln", qual="sec", sev="high", cwe="CWE-347", owasp="A02:2021",
      title="JWT parsed without a signature", desc="parseClaimsJwt reads an unsigned JWT, so claims are unverified.",
      rationale="Parsing an unsigned JWT accepts forged claims; only parseClaimsJws verifies a signature.",
      remediation="Use parseClaimsJws with the expected signing key.",
      source="https://cwe.mitre.org/data/definitions/347.html",
      re=r"parseClaimsJwt\s*\(", nc="Jws claims = Jwts.parser().parseClaimsJwt(token);",
      c="Jws claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token);"),
    r(id="java-guava-md5", type="hotspot", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="Guava MD5 hashing", desc="Hashing.md5() uses the broken MD5 algorithm.",
      rationale="Guava's md5 hash function is unfit for security use.",
      remediation="Use Hashing.sha256() or stronger.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"Hashing\.md5\s*\(", nc="HashCode h = Hashing.md5().hashBytes(data);", c="HashCode h = Hashing.sha256().hashBytes(data);"),
    r(id="java-guava-sha1", type="hotspot", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="Guava SHA-1 hashing", desc="Hashing.sha1() uses the deprecated SHA-1 algorithm.",
      rationale="Guava's sha1 hash function has practical collisions.",
      remediation="Use Hashing.sha256() or stronger.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"Hashing\.sha1\s*\(", nc="HashCode h = Hashing.sha1().hashBytes(data);", c="HashCode h = Hashing.sha256().hashBytes(data);"),
    r(id="java-hmac-md5", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="HmacMD5 message authentication", desc="HmacMD5 builds a MAC on the broken MD5 primitive.",
      rationale="MD5-based HMAC is weaker than SHA-2 alternatives and discouraged.",
      remediation="Use HmacSHA256 or stronger.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'getInstance\s*\(\s*"HmacMD5"', nc='Mac mac = Mac.getInstance("HmacMD5");', c='Mac mac = Mac.getInstance("HmacSHA256");'),
    r(id="java-jackson-default-typing", type="vuln", qual="sec", sev="high", cwe="CWE-502", owasp="A08:2021",
      title="Jackson enableDefaultTyping", desc="enableDefaultTyping enables polymorphic deserialization gadget attacks.",
      rationale="Default typing lets crafted JSON instantiate arbitrary types, enabling RCE.",
      remediation="Do not enable default typing; use explicit @JsonTypeInfo with a validator.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"enableDefaultTyping\s*\(", nc="mapper.enableDefaultTyping();", c="mapper.setPolymorphicTypeValidator(ptv);"),
    r(id="java-jackson-activate-default-typing", type="vuln", qual="sec", sev="high", cwe="CWE-502", owasp="A08:2021",
      title="Jackson activateDefaultTyping", desc="activateDefaultTyping enables polymorphic deserialization attacks.",
      rationale="Activating default typing (even with a permissive validator) risks gadget-chain RCE.",
      remediation="Avoid default typing; restrict types with a strict PolymorphicTypeValidator.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"activateDefaultTyping\s*\(", nc="mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator());",
      c="mapper.setPolymorphicTypeValidator(strictValidator);"),
    r(id="java-snakeyaml-unsafe-constructor", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="SnakeYAML default constructor", desc="new Yaml() can instantiate arbitrary types from YAML tags.",
      rationale="The default SnakeYAML loader honors type tags, enabling deserialization RCE.",
      remediation="Construct Yaml with a SafeConstructor (and a restrictive LoaderOptions).",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"new\s+Yaml\s*\(\s*\)", nc="Yaml yaml = new Yaml();", c="Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));"),
    r(id="java-spel-parser", type="hotspot", qual="sec", sev="medium", cwe="CWE-94", owasp="A03:2021",
      title="Spring SpEL expression parser", desc="SpelExpressionParser can evaluate arbitrary expressions (code injection).",
      rationale="Parsing an attacker-influenced SpEL expression allows remote code execution.",
      remediation="Do not build SpEL from input; use a SimpleEvaluationContext and a fixed expression.",
      source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"new\s+SpelExpressionParser\s*\(", nc="ExpressionParser p = new SpelExpressionParser();", c="Expression e = PRECOMPILED_EXPRESSION;"),
    r(id="java-des-keygen", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="DES key generation", desc="Generating a DES key selects a 56-bit, brute-forceable cipher.",
      rationale="DES key material is far too short for modern security; use AES.",
      remediation="Generate an AES key (e.g. KeyGenerator.getInstance(\"AES\")).",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'KeyGenerator\.getInstance\s*\(\s*"DES"', nc='KeyGenerator kg = KeyGenerator.getInstance("DES");', c='KeyGenerator kg = KeyGenerator.getInstance("AES");'),
]
