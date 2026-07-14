CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: hardcoded key/IV material, Android insecure SSL factory, ContentResolver SQLi.
RULES = [
    r(id="java-hardcoded-secret-key", type="hotspot", qual="sec", sev="high", cwe="CWE-321", owasp="A02:2021",
      title="Hardcoded key material in SecretKeySpec", desc="A string literal used as key material is a hardcoded key.",
      rationale="A key built from a string literal is embedded in the binary and cannot be rotated.",
      remediation="Load the key from a secrets manager / KMS, not a literal.", source="https://cwe.mitre.org/data/definitions/321.html",
      re=r'new\s+SecretKeySpec\s*\(\s*"', nc='SecretKey k = new SecretKeySpec("s3cr3tk3y0123456".getBytes(), "AES");', c='SecretKey k = new SecretKeySpec(loadKey(), "AES");'),
    r(id="java-hardcoded-iv", type="hotspot", qual="sec", sev="medium", cwe="CWE-329", owasp="A02:2021",
      title="Hardcoded initialization vector", desc="A string-literal IV is static and predictable.",
      rationale="A hardcoded IV makes encryption deterministic, leaking equality of plaintexts.",
      remediation="Generate a random IV per encryption with SecureRandom.", source="https://cwe.mitre.org/data/definitions/329.html",
      re=r'new\s+IvParameterSpec\s*\(\s*"', nc='IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());', c="IvParameterSpec iv = new IvParameterSpec(randomIv);"),
    r(id="java-android-ssl-getinsecure", type="vuln", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="SSLCertificateSocketFactory.getInsecure", desc="getInsecure returns a factory that skips certificate validation.",
      rationale="The insecure socket factory disables certificate checks, enabling MITM.",
      remediation="Use a validating SSLSocketFactory.", source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"SSLCertificateSocketFactory\.getInsecure\s*\(", nc="SocketFactory f = SSLCertificateSocketFactory.getInsecure(0, null);", c="SocketFactory f = SSLSocketFactory.getDefault();"),
    r(id="java-android-content-query-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="ContentResolver query selection concatenation", desc="A selection built with + from input enables SQL injection.",
      rationale="An Android ContentResolver selection assembled with + from input is injectable.",
      remediation="Use ? placeholders and the selectionArgs parameter.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'\.query\s*\([^)]*"[^"]*"\s*\+', nc='resolver.query(uri, null, "name=" + name, null, null);', c='resolver.query(uri, null, "name=?", new String[]{name}, null);'),
]
