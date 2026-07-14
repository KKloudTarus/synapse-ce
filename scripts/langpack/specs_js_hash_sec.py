CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# JS/TS security pack: weak Node crypto hashes.
RULES = [
    r(id="js-crypto-hash-md5", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="MD5 via crypto.createHash", desc='createHash("md5") uses the broken MD5 algorithm.',
      rationale="MD5 is collision-prone and unfit for security use.",
      remediation='Use createHash("sha256") or stronger.',
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'''createHash\s*\(\s*["']md5["']''', nc='const h = crypto.createHash("md5");', c='const h = crypto.createHash("sha256");'),
    r(id="js-crypto-hash-sha1", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="SHA-1 via crypto.createHash", desc='createHash("sha1") uses the deprecated SHA-1 algorithm.',
      rationale="SHA-1 has practical collisions and is unfit for signatures or integrity.",
      remediation='Use createHash("sha256") or stronger.',
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'''createHash\s*\(\s*["']sha1["']''', nc='const h = crypto.createHash("sha1");', c='const h = crypto.createHash("sha256");'),
]
