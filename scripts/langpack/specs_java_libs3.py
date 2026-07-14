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


# Java quality pack: retired third-party libraries superseded by maintained forks.
RULES = [
    r(id="java-fest-assert-import", title="FEST-Assert import", desc="org.fest.assertions is the retired FEST library.",
      rationale="FEST-Assert is retired; AssertJ is the maintained successor.", remediation="Use AssertJ (org.assertj).",
      source="https://assertj.github.io/doc/", re=r"import\s+org\.fest\.assertions\.", nc="import org.fest.assertions.Assertions;", c="import org.assertj.core.api.Assertions;"),
    r(id="java-xmlbeans-import", title="Apache XMLBeans import", desc="Apache XMLBeans is largely dormant.",
      rationale="Apache XMLBeans is effectively unmaintained; prefer JAXB or a maintained binding.", remediation="Use JAXB (jakarta.xml.bind) or another maintained binding.",
      source="https://xmlbeans.apache.org/", re=r"import\s+org\.apache\.xmlbeans\.", nc="import org.apache.xmlbeans.XmlObject;", c="import jakarta.xml.bind.JAXBContext;"),
    r(id="java-itext2-import", title="iText 2 / com.lowagie import", desc="com.lowagie is the abandoned iText 2 line.",
      rationale="com.lowagie (iText 2) is abandoned and predates the AGPL relicensing; use a maintained fork.", remediation="Use OpenPDF or a licensed modern iText.",
      source="https://github.com/LibrePDF/OpenPDF", re=r"import\s+com\.lowagie\.text\.", nc="import com.lowagie.text.Document;", c="import com.openpdf.text.Document;"),
]
