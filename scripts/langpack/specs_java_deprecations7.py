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


G = "https://github.com/google/guava/wiki"
JD = "https://docs.oracle.com/javase/8/docs/api/"

# Java quality pack: Guava factory/util methods unneeded on modern Java + deprecated JDK/JUnit APIs.
RULES = [
    r(id="java-guava-new-linkedlist", title="Lists.newLinkedList()", desc="Unneeded on Java 7+.",
      rationale="The empty Lists.newLinkedList() predates the diamond operator.", remediation="Use new LinkedList<>().",
      source=G, re=r"\bLists\.newLinkedList\s*\(\s*\)", nc="List<String> l = Lists.newLinkedList();", c="List<String> l = new LinkedList<>();"),
    r(id="java-guava-new-hashset", title="Sets.newHashSet()", desc="Unneeded on Java 7+.",
      rationale="The empty Sets.newHashSet() predates the diamond operator.", remediation="Use new HashSet<>().",
      source=G, re=r"\bSets\.newHashSet\s*\(\s*\)", nc="Set<String> s = Sets.newHashSet();", c="Set<String> s = new HashSet<>();"),
    r(id="java-guava-new-treemap", title="Maps.newTreeMap()", desc="Unneeded on Java 7+.",
      rationale="The empty Maps.newTreeMap() predates the diamond operator.", remediation="Use new TreeMap<>().",
      source=G, re=r"\bMaps\.newTreeMap\s*\(\s*\)", nc="Map<K, V> m = Maps.newTreeMap();", c="Map<K, V> m = new TreeMap<>();"),
    r(id="java-guava-new-concurrentmap", title="Maps.newConcurrentMap()", desc="Unneeded on Java 7+.",
      rationale="The empty Maps.newConcurrentMap() predates the diamond operator.", remediation="Use new ConcurrentHashMap<>().",
      source=G, re=r"\bMaps\.newConcurrentMap\s*\(\s*\)", nc="Map<K, V> m = Maps.newConcurrentMap();", c="Map<K, V> m = new ConcurrentHashMap<>();"),
    r(id="java-guava-objects-equal", title="Guava Objects.equal()", desc="Superseded by java.util.Objects.equals.",
      rationale="Guava's Objects.equal is superseded by the JDK's Objects.equals.", remediation="Use java.util.Objects.equals.",
      source=G, re=r"\bObjects\.equal\s*\(", nc="if (Objects.equal(a, b)) {", c="if (Objects.equals(a, b)) {"),
    r(id="java-guava-objects-hashcode", title="Guava Objects.hashCode(...)", desc="Superseded by java.util.Objects.hash.",
      rationale="Guava's varargs Objects.hashCode is superseded by the JDK's Objects.hash.", remediation="Use java.util.Objects.hash.",
      source=G, re=r"\bObjects\.hashCode\s*\(\s*\w+\s*,", nc="int h = Objects.hashCode(a, b);", c="int h = Objects.hash(a, b);"),
    r(id="java-junit3-testcase-extend", title="Extends JUnit 3 TestCase", desc="TestCase is the JUnit 3 base class.",
      rationale="Extending junit.framework.TestCase is the obsolete JUnit 3 style.", remediation="Write a plain JUnit 5 test class.",
      source="https://junit.org/junit5/docs/current/user-guide/", re=r"extends\s+TestCase\b", nc="class UserTest extends TestCase {", c="class UserTest {"),
    r(id="java-system-get-security-manager", title="System.getSecurityManager()", desc="The Security Manager is deprecated for removal.",
      rationale="System.getSecurityManager is deprecated for removal (JEP 411).", remediation="Do not rely on the Security Manager.",
      source="https://openjdk.org/jeps/411", re=r"System\.getSecurityManager\s*\(", nc="if (System.getSecurityManager() != null) {", c="// Security Manager is being removed"),
    r(id="java-date-utc", title="Date.UTC()", desc="Date.UTC is deprecated.",
      rationale="Date.UTC is deprecated in favor of java.time / Calendar.", remediation="Use java.time (e.g. LocalDateTime + ZoneOffset.UTC).",
      source=JD, re=r"\bDate\.UTC\s*\(", nc="long t = Date.UTC(2020, 0, 1, 0, 0, 0);", c="long t = LocalDateTime.of(2020,1,1,0,0).toEpochSecond(ZoneOffset.UTC);"),
    r(id="java-date-parse-static", title="Date.parse()", desc="Date.parse is deprecated.",
      rationale="The static Date.parse is deprecated in favor of DateFormat / java.time parsing.", remediation="Use DateTimeFormatter / Instant.parse.",
      source=JD, re=r"\bDate\.parse\s*\(", nc='long t = Date.parse("Jan 1 2020");', c='Instant t = Instant.parse("2020-01-01T00:00:00Z");'),
]
