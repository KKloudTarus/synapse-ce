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


# Java quality pack: legacy/EOL library imports superseded by maintained alternatives.
RULES = [
    r(id="java-commons-logging-import", title="Jakarta Commons Logging import", desc="JCL is a legacy logging facade.",
      rationale="commons-logging has classloader issues; SLF4J is the modern facade.", remediation="Use SLF4J.",
      source="https://www.slf4j.org/", re=r"import\s+org\.apache\.commons\.logging\.", nc="import org.apache.commons.logging.Log;", c="import org.slf4j.Logger;"),
    r(id="java-struts1-import", title="Struts 1 import", desc="Apache Struts 1 is end-of-life.",
      rationale="Struts 1.x is EOL and unmaintained.", remediation="Use Spring MVC or Jakarta MVC.",
      source="https://struts.apache.org/", re=r"import\s+org\.apache\.struts\.action\.", nc="import org.apache.struts.action.Action;", c="import org.springframework.web.bind.annotation.RestController;"),
    r(id="java-ehcache2-import", title="Ehcache 2 import", desc="net.sf.ehcache is the legacy Ehcache 2.",
      rationale="Ehcache 2 (net.sf.ehcache) is superseded by Ehcache 3 (org.ehcache).", remediation="Use org.ehcache (Ehcache 3).",
      source="https://www.ehcache.org/", re=r"import\s+net\.sf\.ehcache\.", nc="import net.sf.ehcache.CacheManager;", c="import org.ehcache.CacheManager;"),
    r(id="java-dbcp1-import", title="Commons DBCP 1 import", desc="commons.dbcp is the legacy DBCP 1.",
      rationale="DBCP 1 is superseded by DBCP 2 (and HikariCP).", remediation="Use commons-dbcp2 or HikariCP.",
      source="https://commons.apache.org/proper/commons-dbcp/", re=r"import\s+org\.apache\.commons\.dbcp\.", nc="import org.apache.commons.dbcp.BasicDataSource;", c="import com.zaxxer.hikari.HikariDataSource;"),
    r(id="java-commons-configuration1-import", title="Commons Configuration 1 import", desc="commons.configuration is the legacy v1.",
      rationale="Commons Configuration 1 is superseded by configuration2.", remediation="Use org.apache.commons.configuration2.",
      source="https://commons.apache.org/proper/commons-configuration/", re=r"import\s+org\.apache\.commons\.configuration\.", nc="import org.apache.commons.configuration.Configuration;", c="import org.apache.commons.configuration2.Configuration;"),
    r(id="java-commons-beanutils-import", title="Commons BeanUtils import", desc="commons-beanutils has had security issues.",
      rationale="Commons BeanUtils has a history of property-access CVEs; prefer explicit mapping (e.g. MapStruct).", remediation="Map fields explicitly or use MapStruct.",
      source="https://commons.apache.org/proper/commons-beanutils/", re=r"import\s+org\.apache\.commons\.beanutils\.", nc="import org.apache.commons.beanutils.BeanUtils;", c="// map fields explicitly (e.g. MapStruct)"),
    r(id="java-jackson1-import", title="Jackson 1.x import", desc="org.codehaus.jackson is the EOL Jackson 1.x.",
      rationale="Jackson 1.x (org.codehaus.jackson) is end-of-life.", remediation="Use Jackson 2 (com.fasterxml.jackson).",
      source="https://github.com/FasterXML/jackson", re=r"import\s+org\.codehaus\.jackson\.", nc="import org.codehaus.jackson.map.ObjectMapper;", c="import com.fasterxml.jackson.databind.ObjectMapper;"),
    r(id="java-xerces-import", title="Bundled Xerces import", desc="Direct org.apache.xerces use is discouraged.",
      rationale="Importing bundled Xerces bypasses the JAXP abstraction and pins an internal implementation.", remediation="Use the JAXP factories (javax.xml.parsers).",
      source="https://xerces.apache.org/", re=r"import\s+org\.apache\.xerces\.", nc="import org.apache.xerces.parsers.DOMParser;", c="import javax.xml.parsers.DocumentBuilderFactory;"),
]
