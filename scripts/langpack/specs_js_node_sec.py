CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# JS/TS security pack: Node crypto misuse.
RULES = [
    r(id="js-crypto-createcipher", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="crypto.createCipher()", desc="createCipher derives a key with no IV and a weak KDF.",
      rationale="crypto.createCipher is deprecated and insecure: it uses MD5-based key derivation and no IV.",
      remediation="Use crypto.createCipheriv with a random IV and a proper key.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"crypto\.createCipher\s*\(", nc='const c = crypto.createCipher("aes192", password);',
      c='const c = crypto.createCipheriv("aes-256-gcm", key, iv);'),
    r(id="js-crypto-createdecipher", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="crypto.createDecipher()", desc="createDecipher mirrors the insecure createCipher.",
      rationale="crypto.createDecipher is deprecated and insecure (weak KDF, no IV).",
      remediation="Use crypto.createDecipheriv with the IV.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"crypto\.createDecipher\s*\(", nc='const d = crypto.createDecipher("aes192", password);',
      c='const d = crypto.createDecipheriv("aes-256-gcm", key, iv);'),
    r(id="js-pseudo-random-bytes", type="hotspot", qual="sec", sev="medium", cwe="CWE-338", owasp="A02:2021",
      title="crypto.pseudoRandomBytes()", desc="pseudoRandomBytes is not cryptographically secure.",
      rationale="pseudoRandomBytes (an alias of prng) is not suitable for tokens, keys, or nonces.",
      remediation="Use crypto.randomBytes for security-sensitive values.",
      source="https://cwe.mitre.org/data/definitions/338.html",
      re=r"\bpseudoRandomBytes\s*\(", nc="const t = crypto.pseudoRandomBytes(16);", c="const t = crypto.randomBytes(16);"),
]
