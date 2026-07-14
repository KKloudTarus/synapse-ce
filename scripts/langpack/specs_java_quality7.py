CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


# Java quality pack: naming conventions + redundant negation.
RULES = [
    r(id="java-class-name-lowercase", title="Class name not in PascalCase", desc="Class names should start with an uppercase letter.",
      rationale="Java class names use UpperCamelCase; a lowercase initial is inconsistent (PMD ClassNamingConventions).",
      remediation="Rename the class to PascalCase.", source="https://pmd.github.io/pmd/pmd_rules_java_codestyle.html",
      re=r"\bclass\s+[a-z]", nc="class userService {", c="class UserService {"),
    r(id="java-method-name-uppercase", title="Method name not in camelCase", desc="Method names should start with a lowercase letter.",
      rationale="Java method names use lowerCamelCase; an uppercase initial reads like a type/constructor (PMD MethodNamingConventions).",
      remediation="Rename the method to camelCase.", source="https://pmd.github.io/pmd/pmd_rules_java_codestyle.html",
      re=r"\b(void|boolean|int|long|double|float|char|byte|short|String)\s+[A-Z]\w*\s*\(", nc="public void DoWork() {", c="public void doWork() {"),
    r(id="java-redundant-double-negation", title="Double negation", desc="!! is a redundant double negation.",
      rationale="Two logical-not operators cancel out; write the expression directly.",
      remediation="Use the boolean directly (or Boolean.valueOf to coerce).", source="https://pmd.github.io/pmd/pmd_rules_java_design.html",
      re=r"!!", nc="if (!!ready) {", c="if (ready) {"),
]
