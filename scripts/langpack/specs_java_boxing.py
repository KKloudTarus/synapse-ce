CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 5)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


JLS = "https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/Integer.html"


def boxctor(name):
    return r(id="java-new-" + name.lower(), title="new " + name + "(...) constructor",
             desc="The " + name + " boxing constructor is deprecated since JDK 9.",
             rationale="Wrapper constructors always allocate; " + name + ".valueOf caches and is the documented replacement.",
             remediation="Use " + name + ".valueOf(...).", source=JLS,
             re=r"new\s+" + name + r"\s*\(",
             nc="new " + name + "(x)", c=name + ".valueOf(x)")


# Java quality pack: deprecated primitive-wrapper constructors (JDK 9+).
RULES = [
    boxctor("Integer"),
    boxctor("Long"),
    boxctor("Double"),
    boxctor("Boolean"),
    boxctor("Short"),
    boxctor("Byte"),
    boxctor("Float"),
    boxctor("Character"),
]
