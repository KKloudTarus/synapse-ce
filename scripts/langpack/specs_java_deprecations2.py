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


# Java quality pack: deprecated/removed Spring, Hibernate, and EOL third-party libraries.
RULES = [
    r(id="java-spring-enable-webmvc-security", title="@EnableWebMvcSecurity", desc="Removed in favor of @EnableWebSecurity.",
      rationale="@EnableWebMvcSecurity was removed; @EnableWebSecurity enables Spring MVC integration.", remediation="Use @EnableWebSecurity.",
      source="https://docs.spring.io/spring-security/reference/", re=r"@EnableWebMvcSecurity\b", nc="@EnableWebMvcSecurity", c="@EnableWebSecurity"),
    r(id="java-spring-enable-oauth2-sso", type="bug", qual="rel", sev="medium", title="@EnableOAuth2Sso", desc="Removed with Spring Security OAuth.",
      rationale="@EnableOAuth2Sso was part of the removed Spring Security OAuth project.", remediation="Use Spring Security's OAuth2 client support.",
      source="https://spring.io/projects/spring-security-oauth", re=r"@EnableOAuth2Sso\b", nc="@EnableOAuth2Sso", c="// use spring-security-oauth2-client"),
    r(id="java-spring-oauth2-resttemplate", type="bug", qual="rel", sev="medium", title="OAuth2RestTemplate", desc="Removed with Spring Security OAuth.",
      rationale="OAuth2RestTemplate was part of the removed Spring Security OAuth project.", remediation="Use WebClient with an OAuth2 client.",
      source="https://spring.io/projects/spring-security-oauth", re=r"\bOAuth2RestTemplate\b", nc="OAuth2RestTemplate t = new OAuth2RestTemplate(resource);", c="WebClient client = WebClient.builder().build();"),
    r(id="java-spring-resource-server-adapter", type="bug", qual="rel", sev="medium", title="ResourceServerConfigurerAdapter", desc="Removed with Spring Security OAuth.",
      rationale="ResourceServerConfigurerAdapter was part of the removed Spring Security OAuth project.", remediation="Configure a resource server via SecurityFilterChain.",
      source="https://spring.io/projects/spring-security-oauth", re=r"\bResourceServerConfigurerAdapter\b", nc="class Cfg extends ResourceServerConfigurerAdapter {", c="@Bean SecurityFilterChain chain(HttpSecurity http) {"),
    r(id="java-hibernate-create-criteria", title="Session.createCriteria()", desc="The legacy Criteria API is deprecated.",
      rationale="Hibernate's createCriteria is deprecated in favor of the JPA Criteria API.", remediation="Use CriteriaBuilder / CriteriaQuery.",
      source="https://docs.jboss.org/hibernate/orm/current/javadocs/", re=r"\.createCriteria\s*\(", nc="Criteria c = session.createCriteria(User.class);", c="CriteriaQuery<User> q = cb.createQuery(User.class);"),
    r(id="java-hibernate-detached-criteria", title="DetachedCriteria", desc="The legacy DetachedCriteria API is deprecated.",
      rationale="DetachedCriteria belongs to the deprecated legacy Criteria API.", remediation="Use the JPA Criteria API.",
      source="https://docs.jboss.org/hibernate/orm/current/javadocs/", re=r"\bDetachedCriteria\b", nc="DetachedCriteria dc = DetachedCriteria.forClass(User.class);", c="CriteriaQuery<User> q = cb.createQuery(User.class);"),
    r(id="java-apache-httpclient3", type="bug", qual="rel", sev="medium", title="Apache HttpClient 3 (EOL)", desc="commons-httpclient is end-of-life.",
      rationale="org.apache.commons.httpclient (HttpClient 3.x) is end-of-life and unmaintained.", remediation="Use Apache HttpClient 5 or java.net.http.HttpClient.",
      source="https://hc.apache.org/", re=r"import\s+org\.apache\.commons\.httpclient\.", nc="import org.apache.commons.httpclient.HttpClient;", c="import java.net.http.HttpClient;"),
    r(id="java-apache-default-httpclient", title="DefaultHttpClient", desc="DefaultHttpClient (HttpClient 4) is deprecated.",
      rationale="DefaultHttpClient is deprecated in favor of HttpClientBuilder / HttpClients.", remediation="Use HttpClients.createDefault() or HttpClientBuilder.",
      source="https://hc.apache.org/", re=r"\bDefaultHttpClient\b", nc="HttpClient c = new DefaultHttpClient();", c="CloseableHttpClient c = HttpClients.createDefault();"),
    r(id="java-log4j1-import", title="Log4j 1.x (EOL)", desc="org.apache.log4j is Log4j 1.x, which is end-of-life.",
      rationale="Log4j 1.x is end-of-life and has unpatched vulnerabilities.", remediation="Use SLF4J with Logback or Log4j 2.",
      source="https://logging.apache.org/log4j/1.2/", re=r"import\s+org\.apache\.log4j\.", nc="import org.apache.log4j.Logger;", c="import org.slf4j.Logger;"),
    r(id="java-commons-lang2-import", title="commons-lang 2.x", desc="org.apache.commons.lang is the old commons-lang 2.",
      rationale="commons-lang 2 is superseded by commons-lang3.", remediation="Use org.apache.commons.lang3.",
      source="https://commons.apache.org/proper/commons-lang/", re=r"import\s+org\.apache\.commons\.lang\.", nc="import org.apache.commons.lang.StringUtils;", c="import org.apache.commons.lang3.StringUtils;"),
    r(id="java-joda-time-import", title="Joda-Time", desc="Joda-Time is superseded by java.time.",
      rationale="Joda-Time is in maintenance mode; java.time is the standard since Java 8.", remediation="Use java.time.",
      source="https://www.joda.org/joda-time/", re=r"import\s+org\.joda\.time\.", nc="import org.joda.time.DateTime;", c="import java.time.ZonedDateTime;"),
    r(id="java-guava-lists-newarraylist", title="Lists.newArrayList()", desc="Guava Lists.newArrayList() is unneeded on Java 7+.",
      rationale="The empty Lists.newArrayList() predates the diamond operator and is unnecessary.", remediation="Use new ArrayList<>() or List.of().",
      source="https://github.com/google/guava/wiki", re=r"\bLists\.newArrayList\s*\(\s*\)", nc="List<String> l = Lists.newArrayList();", c="List<String> l = new ArrayList<>();"),
    r(id="java-guava-maps-newhashmap", title="Maps.newHashMap()", desc="Guava Maps.newHashMap() is unneeded on Java 7+.",
      rationale="The empty Maps.newHashMap() predates the diamond operator and is unnecessary.", remediation="Use new HashMap<>() or Map.of().",
      source="https://github.com/google/guava/wiki", re=r"\bMaps\.newHashMap\s*\(\s*\)", nc="Map<K, V> m = Maps.newHashMap();", c="Map<K, V> m = new HashMap<>();"),
]
