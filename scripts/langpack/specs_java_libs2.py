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


# Java quality pack: dead/legacy third-party library imports.
RULES = [
    r(id="java-jdom1-import", title="JDOM 1 import", desc="org.jdom is the legacy JDOM 1.",
      rationale="JDOM 1 (org.jdom) is superseded by JDOM 2 (org.jdom2).", remediation="Use org.jdom2.",
      source="https://github.com/hunterhacker/jdom", re=r"import\s+org\.jdom\.", nc="import org.jdom.Document;", c="import org.jdom2.Document;"),
    r(id="java-cglib-import", title="cglib import", desc="cglib is effectively unmaintained.",
      rationale="cglib struggles on modern JDKs; ByteBuddy is the maintained bytecode library.", remediation="Use ByteBuddy.",
      source="https://bytebuddy.net/", re=r"import\s+net\.sf\.cglib\.", nc="import net.sf.cglib.proxy.Enhancer;", c="import net.bytebuddy.ByteBuddy;"),
    r(id="java-xalan-import", title="Bundled Xalan import", desc="Direct org.apache.xalan use is discouraged.",
      rationale="Importing bundled Xalan pins an internal implementation instead of using JAXP.", remediation="Use the JAXP TransformerFactory (javax.xml.transform).",
      source="https://xalan.apache.org/", re=r"import\s+org\.apache\.xalan\.", nc="import org.apache.xalan.processor.TransformerFactoryImpl;", c="import javax.xml.transform.TransformerFactory;"),
    r(id="java-oro-import", title="Jakarta ORO import", desc="Jakarta ORO is a dead regex library.",
      rationale="Jakarta ORO is retired; java.util.regex is the standard replacement.", remediation="Use java.util.regex.",
      source="https://attic.apache.org/projects/jakarta-oro.html", re=r"import\s+org\.apache\.oro\.", nc="import org.apache.oro.text.regex.Perl5Matcher;", c="import java.util.regex.Pattern;"),
    r(id="java-commons-digester1-import", title="Commons Digester 1/2 import", desc="commons.digester is the legacy Digester.",
      rationale="Commons Digester 1/2 (org.apache.commons.digester) is superseded by digester3.", remediation="Use commons-digester3 or a modern parser binding.",
      source="https://commons.apache.org/proper/commons-digester/", re=r"import\s+org\.apache\.commons\.digester\.", nc="import org.apache.commons.digester.Digester;", c="import org.apache.commons.digester3.Digester;"),
]
