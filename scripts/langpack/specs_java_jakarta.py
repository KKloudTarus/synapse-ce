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


def jakarta(name, pkg, jpkg, sample):
    return r(id="java-javax-" + name, title="javax." + name + " namespace",
             desc="The javax." + name + " packages were renamed to jakarta." + name + ".",
             rationale="Jakarta EE 9+ renamed the javax.* enterprise namespace to jakarta.*.",
             remediation="Migrate to the jakarta." + name + " namespace.", source=JAKARTA,
             re=r"import\s+javax\." + pkg + r"\.",
             nc="import javax." + pkg + "." + sample + ";",
             c="import jakarta." + jpkg + "." + sample + ";")


# Java quality pack: javax -> jakarta namespace migration (Jakarta EE 9+).
RULES = [
    jakarta("persistence", "persistence", "persistence", "Entity"),
    jakarta("servlet", "servlet", "servlet", "http.HttpServlet"),
    jakarta("ejb", "ejb", "ejb", "Stateless"),
    jakarta("jaxrs", "ws.rs", "ws.rs", "GET"),
    jakarta("inject", "inject", "inject", "Inject"),
    jakarta("jms", "jms", "jms", "Message"),
    jakarta("mail", "mail", "mail", "Message"),
    jakarta("validation", "validation", "validation", "constraints.NotNull"),
    jakarta("annotation", "annotation", "annotation", "PostConstruct"),
    jakarta("faces", "faces", "faces", "bean.ManagedBean"),
]
