CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="java-securerandom-time-seed", type="hotspot", qual="sec", sev="medium", cwe="CWE-337", owasp="A02:2021",
      title="SecureRandom seeded with current time", desc="Seeding with the clock makes output predictable.",
      rationale="Seeding a PRNG with System.currentTimeMillis makes the sequence guessable to an attacker who knows the approximate time.",
      remediation="Do not seed with the clock; let SecureRandom self-seed.",
      source="https://cwe.mitre.org/data/definitions/337.html",
      re=r"setSeed\s*\(\s*System\.currentTimeMillis", nc="random.setSeed(System.currentTimeMillis());", c="random = new SecureRandom();"),
]
