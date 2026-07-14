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


HB = "https://docs.jboss.org/hibernate/orm/current/javadocs/"

# Java quality pack: Hibernate Session method deprecations.
RULES = [
    r(id="java-hibernate-saveorupdate", title="Session.saveOrUpdate()", desc="saveOrUpdate is deprecated in Hibernate 6.",
      rationale="Session.saveOrUpdate is deprecated in favor of the JPA merge/persist semantics.", remediation="Use merge() or persist().",
      source=HB, re=r"\.saveOrUpdate\s*\(", nc="session.saveOrUpdate(entity);", c="session.merge(entity);"),
    r(id="java-hibernate-load", title="Session.load(Class, id)", desc="Session.load is deprecated in Hibernate 6.",
      rationale="Session.load is deprecated in favor of getReference (lazy) / get (eager).", remediation="Use getReference() or byId().getReference().",
      source=HB, re=r"\.load\s*\(\s*\w+\.class", nc="User u = session.load(User.class, id);", c="User u = session.getReference(User.class, id);"),
]
