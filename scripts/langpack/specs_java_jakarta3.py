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


JAKARTA = "https://jakarta.ee/blogs/javax-jakartaee-namespace-ecosystem-progress/"


def jakarta(name, pkg, sample):
    return r(id="java-javax-" + name, title="javax." + pkg + " namespace",
             desc="The javax." + pkg + " packages were renamed to jakarta." + pkg + ".",
             rationale="Jakarta EE 9+ renamed the javax.* enterprise namespace to jakarta.*.",
             remediation="Migrate to the jakarta." + pkg + " namespace.", source=JAKARTA,
             re=r"import\s+javax\." + pkg.replace(".", r"\.") + r"\.",
             nc="import javax." + pkg + "." + sample + ";",
             c="import jakarta." + pkg + "." + sample + ";")


# Java quality pack: javax -> jakarta migration (Jakarta EE 9+), remaining EE packages.
RULES = [
    jakarta("jws", "jws", "WebService"),
    jakarta("batch", "batch", "api.Batchlet"),
    jakarta("security-enterprise", "security.enterprise", "SecurityContext"),
    jakarta("decorator", "decorator", "Decorator"),
    jakarta("interceptor", "interceptor", "AroundInvoke"),
]
