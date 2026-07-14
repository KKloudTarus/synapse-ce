CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java quality/reliability pack: SpotBugs/PMD idioms.
RULES = [
    r(id="java-stringbuilder-char-arg", type="bug", qual="rel", sev="medium", cwe="", title="StringBuilder(char)",
      desc="new StringBuilder('x') treats the char as an int capacity, not content.",
      rationale="A char argument is widened to int and used as the initial capacity, not appended (SpotBugs).",
      remediation="Pass a String: new StringBuilder(\"x\").", source="https://spotbugs.readthedocs.io/en/stable/bugDescriptions.html",
      re=r"new\s+String(Builder|Buffer)\s*\(\s*'", nc="StringBuilder sb = new StringBuilder('a');", c='StringBuilder sb = new StringBuilder("a");'),
    r(id="java-throws-exception", type="smell", qual="maint", sev="low", cwe="", title="Method throws generic Exception",
      desc="Declaring throws Exception forces callers to handle everything.",
      rationale="A broad throws Exception hides which failures can occur; declare the specific checked types (PMD SignatureDeclareThrowsException).",
      remediation="Declare the specific checked exception types.", source="https://pmd.github.io/pmd/pmd_rules_java_design.html",
      re=r"throws\s+Exception\b", nc="void load() throws Exception {", c="void load() throws IOException {"),
    r(id="java-throws-throwable", type="smell", qual="maint", sev="low", cwe="", title="Method throws Throwable",
      desc="Declaring throws Throwable is even broader than Exception.",
      rationale="Throwable includes Error; a method should not declare it as thrown.",
      remediation="Declare the specific checked exception types.", source="https://pmd.github.io/pmd/pmd_rules_java_design.html",
      re=r"throws\s+Throwable\b", nc="void load() throws Throwable {", c="void load() throws IOException {"),
]
