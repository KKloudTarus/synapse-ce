CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java crypto sinks: weak key generation, static IV, predictable-seeded SecureRandom.
RULES = [
    r(id="java-desede-keygen", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="Triple DES key generation", desc="Generating a DESede key selects the deprecated 3DES cipher.",
      rationale="Triple DES is slow and deprecated by NIST; generate an AES key instead.",
      remediation='Use KeyGenerator.getInstance("AES").',
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'KeyGenerator\.getInstance\s*\(\s*"DESede"', nc='KeyGenerator kg = KeyGenerator.getInstance("DESede");', c='KeyGenerator kg = KeyGenerator.getInstance("AES");'),
    r(id="java-static-iv", type="vuln", qual="sec", sev="medium", cwe="CWE-329", owasp="A02:2021",
      title="Static/zero initialization vector", desc="Building an IvParameterSpec from a fresh byte array uses an all-zero, static IV.",
      rationale="A constant IV makes CBC/CTR encryption deterministic, leaking equality of plaintexts.",
      remediation="Generate a random IV with SecureRandom for each encryption.",
      source="https://cwe.mitre.org/data/definitions/329.html",
      re=r"new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[", nc="IvParameterSpec iv = new IvParameterSpec(new byte[16]);",
      c="IvParameterSpec iv = new IvParameterSpec(randomIv);"),
    r(id="java-securerandom-constant-seed", type="hotspot", qual="sec", sev="medium", cwe="CWE-336", owasp="A02:2021",
      title="SecureRandom seeded with a constant", desc="Seeding SecureRandom with a literal makes its output predictable.",
      rationale="A fixed seed produces the same sequence every run, defeating the CSPRNG.",
      remediation="Do not call setSeed with a constant; let SecureRandom self-seed.",
      source="https://cwe.mitre.org/data/definitions/336.html",
      re=r"\.setSeed\s*\(\s*[0-9]", nc="random.setSeed(12345L);", c="byte[] seed = random.generateSeed(16);"),
]
