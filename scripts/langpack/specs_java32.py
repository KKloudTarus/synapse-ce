CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java pack: assorted precise quality/security rules.
RULES = [
    r(id="java-synchronized-on-string-literal", type="bug", qual="rel", sev="medium", cwe="CWE-662",
      title="synchronized on a string literal", desc="Locking on an interned string literal shares the monitor process-wide.",
      rationale="String literals are interned, so unrelated code holding the same literal contends on one monitor and can deadlock.",
      remediation="Lock on a private final Object.", source="https://cwe.mitre.org/data/definitions/662.html",
      re=r'synchronized\s*\(\s*"', nc='synchronized ("lock") {', c="synchronized (lock) {"),
    r(id="java-class-newinstance", type="smell", qual="maint", sev="low",
      title="Class.newInstance()", desc="Class.newInstance() is deprecated since JDK 9.",
      rationale="Class.newInstance swallows constructor exceptions and bypasses checked-exception rules; it is deprecated.",
      remediation="Use getDeclaredConstructor().newInstance().", source="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/Class.html",
      re=r"\.class\.newInstance\s*\(", nc="Foo f = Foo.class.newInstance();", c="Foo f = Foo.class.getDeclaredConstructor().newInstance();"),
    r(id="java-file-delete-on-exit", type="smell", qual="maint", sev="low",
      title="File.deleteOnExit()", desc="deleteOnExit accumulates entries for the life of the JVM.",
      rationale="deleteOnExit never releases its list, leaking memory in long-running processes and only deleting on clean exit.",
      remediation="Delete the file explicitly in a finally block or use Files.createTempFile with a shutdown-safe cleanup.",
      source="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html",
      re=r"\.deleteOnExit\s*\(\s*\)", nc="temp.deleteOnExit();", c="try { ... } finally { Files.deleteIfExists(temp.toPath()); }"),
    r(id="java-spring-autowired-field", type="smell", qual="maint", sev="low",
      title="Field injection with @Autowired", desc="Inline @Autowired field injection hides dependencies and hinders testing.",
      rationale="Field injection makes dependencies non-final and untestable without a container; constructor injection is preferred.",
      remediation="Use constructor injection.", source="https://docs.spring.io/spring-framework/reference/core/beans/dependencies/factory-collaborators.html",
      re=r"@Autowired\s+(private|protected|public)\s+[\w.<>\[\]]+\s+\w+\s*;",
      nc="@Autowired private OrderService orderService;", c="private final OrderService orderService; // constructor-injected"),
    r(id="java-spring-crossorigin-wildcard", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="@CrossOrigin wildcard origin", desc="@CrossOrigin with \"*\" allows any origin to call the endpoint.",
      rationale="A wildcard CORS origin lets any site issue credentialed cross-origin requests to the endpoint.",
      remediation="List the specific allowed origins.", source="https://cwe.mitre.org/data/definitions/942.html",
      re=r'@CrossOrigin\s*\([^)]*"\*"', nc='@CrossOrigin(origins = "*")', c='@CrossOrigin(origins = "https://app.example.com")'),
    r(id="java-digest-md4", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="MD4 message digest", desc="MD4 is a broken hash function.",
      rationale="MD4 is cryptographically broken and unsuitable for any security use.",
      remediation="Use SHA-256 or stronger.", source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'getInstance\s*\(\s*"MD4"', nc='MessageDigest.getInstance("MD4");', c='MessageDigest.getInstance("SHA-256");'),
]
