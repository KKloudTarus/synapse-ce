CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="python-hashlib-md4", type="hotspot", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="MD4 via hashlib.new", desc='hashlib.new("md4") selects the broken MD4 algorithm.',
      rationale="MD4 is even weaker than MD5 and unfit for any security use.",
      remediation='Use a strong digest such as hashlib.new("sha256").',
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'''hashlib\.new\s*\(\s*["']md4''', nc='h = hashlib.new("md4")', c='h = hashlib.new("sha256")'),
    r(id="python-jwt-algorithms-null", type="vuln", qual="sec", sev="high", cwe="CWE-347", owasp="A02:2021",
      title="JWT decoded with algorithms=None", desc="algorithms=None disables algorithm restriction.",
      rationale="Passing algorithms=None lets a token pick any algorithm, including none, enabling forgery.",
      remediation="Pass an explicit allowlist, e.g. algorithms=[\"HS256\"].",
      source="https://cwe.mitre.org/data/definitions/347.html",
      re=r"jwt\.decode\s*\([^)]*algorithms\s*=\s*None", nc="jwt.decode(token, key, algorithms=None)",
      c='jwt.decode(token, key, algorithms=["HS256"])'),
    r(id="python-hmac-md5", type="hotspot", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="HMAC with MD5", desc="hmac.new(..., digestmod=hashlib.md5) builds a MAC on MD5.",
      rationale="An MD5-based HMAC is weaker than SHA-2 alternatives and discouraged.",
      remediation="Use digestmod=hashlib.sha256.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"hmac\.new\s*\([^)]*digestmod\s*=\s*hashlib\.md5", nc="mac = hmac.new(key, msg, digestmod=hashlib.md5)",
      c="mac = hmac.new(key, msg, digestmod=hashlib.sha256)"),
]
