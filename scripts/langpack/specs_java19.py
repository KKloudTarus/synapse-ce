CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "A02:2021")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "vuln")
    k.setdefault("qual", "sec")
    k.setdefault("sev", "medium")
    k.setdefault("cwe", "CWE-327")
    return k


# Java security pack: additional weak-cipher / weak-digest / key-derivation sinks + world file perms.
RULES = [
    r(id="java-cipher-idea", title="IDEA cipher", desc="IDEA is a legacy 64-bit-block cipher.",
      rationale="IDEA's 64-bit block is vulnerable to birthday attacks on large data; use AES.",
      remediation="Use AES-GCM.", source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'Cipher\.getInstance\s*\(\s*"IDEA', nc='Cipher c = Cipher.getInstance("IDEA/CBC/PKCS5Padding");', c='Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
    r(id="java-cipher-rc2", title="RC2 cipher", desc="RC2 is a weak legacy cipher.",
      rationale="RC2 is obsolete and weak; use AES.", remediation="Use AES-GCM.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r'Cipher\.getInstance\s*\(\s*"RC2', nc='Cipher c = Cipher.getInstance("RC2");', c='Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
    r(id="java-cipher-arcfour", title="ARCFOUR (RC4) cipher", desc="ARCFOUR is the RC4 stream cipher.",
      rationale="RC4/ARCFOUR has keystream biases and is prohibited.", remediation="Use AES-GCM.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r'Cipher\.getInstance\s*\(\s*"ARCFOUR', nc='Cipher c = Cipher.getInstance("ARCFOUR");', c='Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
    r(id="java-digest-md2", title="MD2 message digest", desc="MD2 is a broken hash.",
      rationale="MD2 is obsolete and broken; use SHA-256 or stronger.", remediation="Use SHA-256.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r'getInstance\s*\(\s*"MD2"', nc='MessageDigest md = MessageDigest.getInstance("MD2");', c='MessageDigest md = MessageDigest.getInstance("SHA-256");'),
    r(id="java-des-secretkeyfactory", title="DES key factory", desc="SecretKeyFactory for DES selects a 56-bit cipher.",
      rationale="DES keys are far too short; use AES.", remediation="Use an AES key factory / KeyGenerator.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r'SecretKeyFactory\.getInstance\s*\(\s*"DES(/|")', nc='SecretKeyFactory.getInstance("DES");', c='SecretKeyFactory.getInstance("AES");'),
    r(id="java-desede-secretkeyfactory", title="Triple DES key factory", desc="SecretKeyFactory for DESede selects 3DES.",
      rationale="Triple DES is deprecated by NIST; use AES.", remediation="Use an AES key factory / KeyGenerator.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r'SecretKeyFactory\.getInstance\s*\(\s*"DESede', nc='SecretKeyFactory.getInstance("DESede");', c='SecretKeyFactory.getInstance("AES");'),
    r(id="java-des-keyspec", title="DESKeySpec", desc="DESKeySpec builds a DES key.",
      rationale="DESKeySpec creates a 56-bit DES key; use AES.", remediation="Use SecretKeySpec with an AES key.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r"new\s+DESKeySpec\s*\(", nc="KeySpec ks = new DESKeySpec(key);", c='SecretKey k = new SecretKeySpec(key, "AES");'),
    r(id="java-desede-keyspec", title="DESedeKeySpec", desc="DESedeKeySpec builds a 3DES key.",
      rationale="DESedeKeySpec creates a triple-DES key; use AES.", remediation="Use SecretKeySpec with an AES key.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r"new\s+DESedeKeySpec\s*\(", nc="KeySpec ks = new DESedeKeySpec(key);", c='SecretKey k = new SecretKeySpec(key, "AES");'),
    r(id="java-pbe-md5-des", title="PBEWithMD5AndDES", desc="This PBE scheme uses broken MD5 and weak DES.",
      rationale="PBEWithMD5AndDES relies on MD5 and DES, both unfit for security.", remediation="Use PBKDF2WithHmacSHA256.",
      source="https://cwe.mitre.org/data/definitions/327.html", re=r'"PBEWithMD5AndDES"', nc='SecretKeyFactory.getInstance("PBEWithMD5AndDES");', c='SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");'),
    r(id="java-posix-world-permissions", type="hotspot", qual="sec", sev="medium", cwe="CWE-732", owasp="A01:2021",
      title="World-accessible POSIX permissions", desc="rwxrwxrwx grants full access to every user.",
      rationale="Setting 777-equivalent POSIX permissions exposes the file to all users.",
      remediation="Grant the least permission needed (e.g. rw-------).", source="https://cwe.mitre.org/data/definitions/732.html",
      re=r'fromString\s*\(\s*"rwxrwxrwx"', nc='Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxrwxrwx"));', c='Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));'),
]
