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


# Java quality pack: deprecated/removed Spring, Hibernate, JUnit, Guava, and java.util.Date APIs.
RULES = [
    r(id="java-spring-websecurity-adapter", title="WebSecurityConfigurerAdapter", desc="This base class is deprecated in Spring Security 5.7+.",
      rationale="WebSecurityConfigurerAdapter is deprecated in favor of a SecurityFilterChain bean.",
      remediation="Expose a SecurityFilterChain @Bean.", source="https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter",
      re=r"\bWebSecurityConfigurerAdapter\b", nc="class SecurityConfig extends WebSecurityConfigurerAdapter {", c="@Bean SecurityFilterChain chain(HttpSecurity http) {"),
    r(id="java-spring-enable-global-method-security", title="@EnableGlobalMethodSecurity", desc="Deprecated in favor of @EnableMethodSecurity.",
      rationale="@EnableGlobalMethodSecurity is deprecated in Spring Security 6.", remediation="Use @EnableMethodSecurity.",
      source="https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html", re=r"@EnableGlobalMethodSecurity\b",
      nc="@EnableGlobalMethodSecurity(prePostEnabled = true)", c="@EnableMethodSecurity"),
    r(id="java-spring-webmvc-adapter", title="WebMvcConfigurerAdapter", desc="This base class is deprecated.",
      rationale="WebMvcConfigurerAdapter is deprecated; WebMvcConfigurer has default methods.", remediation="Implement WebMvcConfigurer directly.",
      source="https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/servlet/config/annotation/WebMvcConfigurer.html", re=r"\bWebMvcConfigurerAdapter\b",
      nc="class Cfg extends WebMvcConfigurerAdapter {", c="class Cfg implements WebMvcConfigurer {"),
    r(id="java-spring-handler-interceptor-adapter", title="HandlerInterceptorAdapter", desc="This base class is deprecated.",
      rationale="HandlerInterceptorAdapter is deprecated; HandlerInterceptor has default methods.", remediation="Implement HandlerInterceptor directly.",
      source="https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/servlet/HandlerInterceptor.html", re=r"\bHandlerInterceptorAdapter\b",
      nc="class Auth extends HandlerInterceptorAdapter {", c="class Auth implements HandlerInterceptor {"),
    r(id="java-hibernate-create-sql-query", title="Session.createSQLQuery()", desc="createSQLQuery was deprecated.",
      rationale="Hibernate deprecated createSQLQuery in favor of createNativeQuery.", remediation="Use createNativeQuery.",
      source="https://docs.jboss.org/hibernate/orm/current/javadocs/", re=r"\.createSQLQuery\s*\(", nc="session.createSQLQuery(sql);", c="session.createNativeQuery(sql);"),
    r(id="java-spring-hibernate-template", title="HibernateTemplate", desc="HibernateTemplate/getHibernateTemplate is legacy.",
      rationale="Spring's HibernateTemplate is a legacy DAO pattern; use the native Session/EntityManager.", remediation="Use EntityManager / Session directly.",
      source="https://docs.spring.io/spring-framework/docs/current/javadoc-api/", re=r"\bgetHibernateTemplate\s*\(", nc="getHibernateTemplate().save(entity);", c="entityManager.persist(entity);"),
    r(id="java-junit4-test-import", title="JUnit 4 Test import", desc="org.junit.Test is JUnit 4.",
      rationale="New tests should use JUnit 5 (org.junit.jupiter.api.Test).", remediation="Import org.junit.jupiter.api.Test.",
      source="https://junit.org/junit5/docs/current/user-guide/", re=r"import\s+org\.junit\.Test\b", nc="import org.junit.Test;", c="import org.junit.jupiter.api.Test;"),
    r(id="java-junit4-runwith", title="@RunWith (JUnit 4)", desc="@RunWith is the JUnit 4 runner annotation.",
      rationale="JUnit 5 uses @ExtendWith instead of @RunWith.", remediation="Use @ExtendWith.",
      source="https://junit.org/junit5/docs/current/user-guide/", re=r"@RunWith\b", nc="@RunWith(SpringRunner.class)", c="@ExtendWith(SpringExtension.class)"),
    r(id="java-junit3-import", type="bug", qual="rel", sev="medium", title="JUnit 3 framework import", desc="junit.framework is JUnit 3.",
      rationale="junit.framework.* is the obsolete JUnit 3 API.", remediation="Use JUnit 5 (org.junit.jupiter.api).",
      source="https://junit.org/junit5/docs/current/user-guide/", re=r"import\s+junit\.framework\.", nc="import junit.framework.TestCase;", c="import org.junit.jupiter.api.Test;"),
    r(id="java-guava-first-non-null", title="Objects.firstNonNull (Guava)", desc="Guava Objects.firstNonNull moved to MoreObjects.",
      rationale="com.google.common.base.Objects.firstNonNull is deprecated in favor of MoreObjects.", remediation="Use MoreObjects.firstNonNull.",
      source="https://guava.dev/releases/snapshot/api/docs/", re=r"\bObjects\.firstNonNull\b", nc="String v = Objects.firstNonNull(a, b);", c="String v = MoreObjects.firstNonNull(a, b);"),
    r(id="java-date-year-month-ctor", type="bug", qual="rel", sev="medium", title="Deprecated Date(year, month) constructor", desc="The multi-arg Date constructor is deprecated and 1900-based.",
      rationale="new Date(year, month, ...) is deprecated and error-prone (1900-based year, 0-based month).", remediation="Use java.time (LocalDate/LocalDateTime).",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/Date.html", re=r"new\s+Date\s*\(\s*\d+\s*,\s*\d+", nc="Date d = new Date(2020, 0, 1);", c="LocalDate d = LocalDate.of(2020, 1, 1);"),
    r(id="java-date-tolocalestring", title="Date.toLocaleString()", desc="Date.toLocaleString is deprecated.",
      rationale="java.util.Date.toLocaleString is deprecated in favor of DateFormat / java.time formatting.", remediation="Use DateTimeFormatter.",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/Date.html", re=r"\.toLocaleString\s*\(", nc="String s = date.toLocaleString();", c="String s = formatter.format(instant);"),
]
