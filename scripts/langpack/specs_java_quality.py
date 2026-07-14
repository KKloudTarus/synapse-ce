CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])  # quality/style, not security
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java quality/style pack: PMD / Checkstyle idioms. Clean-room prose.
RULES = [
    r(id="java-modifier-order", type="smell", qual="maint", sev="low", cwe="",
      title="Non-canonical modifier order", desc="An access modifier should precede static/final/abstract.",
      rationale="The JLS-recommended order puts the access modifier first (public static, not static public); the reverse is harder to scan.",
      remediation="Write the access modifier first, e.g. public static void.",
      source="https://docs.oracle.com/javase/specs/jls/se17/html/jls-8.html",
      re=r"\b(static|final|abstract)\s+(public|protected|private)\b", nc="static public void main(String[] args) {",
      c="public static void main(String[] args) {"),
]
