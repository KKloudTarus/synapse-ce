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


# Java quality pack: obsolete JEE/EJB2 patterns and EOL SOAP/REST frameworks.
RULES = [
    r(id="java-servlet-single-thread-model", title="SingleThreadModel", desc="SingleThreadModel is a deprecated servlet interface.",
      rationale="SingleThreadModel does not solve thread safety and is deprecated.", remediation="Make the servlet stateless/thread-safe instead.",
      source="https://jakarta.ee/specifications/servlet/", re=r"implements\s+SingleThreadModel\b", nc="class S extends HttpServlet implements SingleThreadModel {", c="class S extends HttpServlet {"),
    r(id="java-servlet-httputils", title="javax.servlet.http.HttpUtils", desc="HttpUtils is a deprecated servlet class.",
      rationale="HttpUtils was deprecated long ago; use HttpServletRequest methods.", remediation="Use request.getRequestURL()/getParameterMap().",
      source="https://jakarta.ee/specifications/servlet/", re=r"\bHttpUtils\b", nc="StringBuffer url = HttpUtils.getRequestURL(request);", c="StringBuffer url = request.getRequestURL();"),
    r(id="java-jsf-managed-bean", title="JSF @ManagedBean", desc="@ManagedBean is deprecated in favor of CDI.",
      rationale="JSF managed beans are deprecated; use CDI (@Named/@Inject).", remediation="Use CDI annotations (@Named).",
      source="https://jakarta.ee/specifications/faces/", re=r"@ManagedBean\b", nc="@ManagedBean", c="@Named"),
    r(id="java-ejb2-entity-bean", title="EJB 2 EntityBean", desc="EntityBean is the obsolete EJB 2 entity model.",
      rationale="EJB 2 entity beans are obsolete; use JPA entities.", remediation="Use a JPA @Entity.",
      source="https://jakarta.ee/specifications/enterprise-beans/", re=r"implements\s+EntityBean\b", nc="class AccountBean implements EntityBean {", c="@Entity class Account {}"),
    r(id="java-ejb2-session-bean", title="EJB 2 SessionBean", desc="SessionBean is the obsolete EJB 2 session model.",
      rationale="EJB 2 session beans are obsolete; use annotated EJB 3 beans.", remediation="Use @Stateless/@Stateful EJB 3 beans.",
      source="https://jakarta.ee/specifications/enterprise-beans/", re=r"implements\s+SessionBean\b", nc="class OrderBean implements SessionBean {", c="@Stateless class OrderService {}"),
    r(id="java-jersey1-import", title="Jersey 1.x import", desc="com.sun.jersey is the EOL Jersey 1.x.",
      rationale="Jersey 1.x (com.sun.jersey) is end-of-life.", remediation="Use JAX-RS / Jakarta REST (org.glassfish.jersey / jakarta.ws.rs).",
      source="https://eclipse-ee4j.github.io/jersey/", re=r"import\s+com\.sun\.jersey\.", nc="import com.sun.jersey.api.client.Client;", c="import jakarta.ws.rs.client.Client;"),
    r(id="java-axis1-import", title="Apache Axis 1 import", desc="org.apache.axis is the EOL Axis 1.",
      rationale="Apache Axis 1.x is end-of-life.", remediation="Use JAX-WS (Jakarta XML Web Services) or Axis2.",
      source="https://axis.apache.org/", re=r"import\s+org\.apache\.axis\.", nc="import org.apache.axis.client.Call;", c="import jakarta.xml.ws.Service;"),
]
