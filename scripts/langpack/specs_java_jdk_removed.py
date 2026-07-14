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


# Java quality pack: modules removed from the JDK (Java 11-17). The imports no longer resolve
# from the JDK; several require a replacement dependency or a different technology.
RULES = [
    r(id="java-jdk-jaxb-import", title="JAXB (javax.xml.bind) import", desc="JAXB was removed from the JDK in Java 11.",
      rationale="javax.xml.bind is no longer part of the JDK (JEP 320).", remediation="Add the Jakarta XML Binding dependency and use jakarta.xml.bind.",
      source="https://openjdk.org/jeps/320", re=r"import\s+javax\.xml\.bind\.", nc="import javax.xml.bind.JAXBContext;", c="import jakarta.xml.bind.JAXBContext;"),
    r(id="java-jdk-jaxws-import", title="JAX-WS (javax.xml.ws) import", desc="JAX-WS was removed from the JDK in Java 11.",
      rationale="javax.xml.ws is no longer part of the JDK (JEP 320).", remediation="Add the Jakarta XML Web Services dependency.",
      source="https://openjdk.org/jeps/320", re=r"import\s+javax\.xml\.ws\.", nc="import javax.xml.ws.Service;", c="import jakarta.xml.ws.Service;"),
    r(id="java-jdk-soap-import", title="SOAP (javax.xml.soap) import", desc="The SOAP API was removed from the JDK in Java 11.",
      rationale="javax.xml.soap is no longer part of the JDK (JEP 320).", remediation="Add the Jakarta SOAP dependency.",
      source="https://openjdk.org/jeps/320", re=r"import\s+javax\.xml\.soap\.", nc="import javax.xml.soap.SOAPMessage;", c="import jakarta.xml.soap.SOAPMessage;"),
    r(id="java-jdk-activation-import", title="Activation (javax.activation) import", desc="JAF was removed from the JDK in Java 11.",
      rationale="javax.activation is no longer part of the JDK (JEP 320).", remediation="Add the Jakarta Activation dependency.",
      source="https://openjdk.org/jeps/320", re=r"import\s+javax\.activation\.", nc="import javax.activation.DataHandler;", c="import jakarta.activation.DataHandler;"),
    r(id="java-jdk-corba-import", type="bug", qual="rel", sev="medium", title="CORBA (org.omg.CORBA) import", desc="CORBA was removed from the JDK in Java 11.",
      rationale="org.omg.CORBA is no longer part of the JDK (JEP 320) and has no standard replacement.", remediation="Use gRPC/REST or a standalone CORBA library.",
      source="https://openjdk.org/jeps/320", re=r"import\s+org\.omg\.CORBA\.", nc="import org.omg.CORBA.ORB;", c="// migrate off CORBA (e.g. gRPC/REST)"),
    r(id="java-jdk-nashorn-import", type="bug", qual="rel", sev="medium", title="Nashorn (jdk.nashorn) import", desc="Nashorn was removed in Java 15.",
      rationale="jdk.nashorn was removed (JEP 372).", remediation="Use GraalJS or another scripting engine.",
      source="https://openjdk.org/jeps/372", re=r"import\s+jdk\.nashorn\.", nc="import jdk.nashorn.api.scripting.NashornScriptEngine;", c="// use GraalJS (org.graalvm.js)"),
    r(id="java-jdk-security-acl-import", type="bug", qual="rel", sev="medium", title="java.security.acl import", desc="java.security.acl was removed in Java 14.",
      rationale="The java.security.acl package was removed (JEP 411 lineage).", remediation="Use java.security.Policy/Permission or an app-level ACL.",
      source="https://docs.oracle.com/en/java/javase/14/", re=r"import\s+java\.security\.acl\.", nc="import java.security.acl.Acl;", c="// java.security.acl removed"),
    r(id="java-jdk-applet-import", type="bug", qual="rel", sev="medium", title="java.applet import", desc="The applet API was removed.",
      rationale="java.applet.* was removed (JEP 398/504).", remediation="Migrate to a standalone application.",
      source="https://openjdk.org/jeps/398", re=r"import\s+java\.applet\.", nc="import java.applet.Applet;", c="import javax.swing.JPanel;"),
    r(id="java-jdk-rmi-activation-import", type="bug", qual="rel", sev="medium", title="java.rmi.activation import", desc="RMI Activation was removed in Java 17.",
      rationale="The RMI activation system was removed (JEP 407).", remediation="Restructure without RMI activation.",
      source="https://openjdk.org/jeps/407", re=r"import\s+java\.rmi\.activation\.", nc="import java.rmi.activation.Activatable;", c="// RMI activation removed"),
    r(id="java-jdk-pack200-import", type="bug", qual="rel", sev="medium", title="Pack200 import", desc="Pack200 was removed in Java 14.",
      rationale="java.util.jar.Pack200 was removed (JEP 367).", remediation="Use standard jar/zip compression.",
      source="https://openjdk.org/jeps/367", re=r"import\s+java\.util\.jar\.Pack200\b", nc="import java.util.jar.Pack200;", c="import java.util.jar.JarOutputStream;"),
]
