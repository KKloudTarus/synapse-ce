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


# Java quality pack: end-of-life frameworks / removed JDK bridges.
RULES = [
    r(id="java-jboss-seam-import", title="JBoss Seam import", desc="JBoss Seam is end-of-life.",
      rationale="JBoss Seam is EOL; its concepts moved into CDI/Weld.", remediation="Use CDI (jakarta.enterprise / jakarta.inject).",
      source="https://www.seamframework.org/", re=r"import\s+org\.jboss\.seam\.", nc="import org.jboss.seam.annotations.In;", c="import jakarta.inject.Inject;"),
    r(id="java-richfaces-import", title="RichFaces import", desc="RichFaces is end-of-life.",
      rationale="RichFaces reached end-of-life in 2016.", remediation="Migrate to PrimeFaces or plain Jakarta Faces.",
      source="https://github.com/richfaces/richfaces", re=r"import\s+org\.richfaces\.", nc="import org.richfaces.component.UITab;", c="// migrate to PrimeFaces or Jakarta Faces"),
    r(id="java-jdbc-odbc-bridge-import", title="JDBC-ODBC bridge import", desc="The JDBC-ODBC bridge was removed in JDK 8.",
      rationale="sun.jdbc.odbc (the JDBC-ODBC bridge) was removed in JDK 8.", remediation="Use a native JDBC driver for the database.",
      source="https://www.oracle.com/java/technologies/javase/8-whats-new.html", re=r"import\s+sun\.jdbc\.odbc\.", nc="import sun.jdbc.odbc.JdbcOdbcDriver;", c="// use a native JDBC driver"),
]
