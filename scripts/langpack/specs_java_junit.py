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


JUNIT5 = "https://junit.org/junit5/docs/current/user-guide/#migrating-from-junit4"

# Java quality pack: JUnit 4 -> 5 and Mockito migration (deprecated test APIs).
RULES = [
    r(id="java-junit4-before", title="@Before (JUnit 4)", desc="@Before is the JUnit 4 setup annotation.",
      rationale="JUnit 5 uses @BeforeEach.", remediation="Use @BeforeEach.", source=JUNIT5,
      re=r"@Before\b", nc="@Before", c="@BeforeEach"),
    r(id="java-junit4-after", title="@After (JUnit 4)", desc="@After is the JUnit 4 teardown annotation.",
      rationale="JUnit 5 uses @AfterEach.", remediation="Use @AfterEach.", source=JUNIT5,
      re=r"@After\b", nc="@After", c="@AfterEach"),
    r(id="java-junit4-beforeclass", title="@BeforeClass (JUnit 4)", desc="@BeforeClass is the JUnit 4 class-setup annotation.",
      rationale="JUnit 5 uses @BeforeAll.", remediation="Use @BeforeAll.", source=JUNIT5,
      re=r"@BeforeClass\b", nc="@BeforeClass", c="@BeforeAll"),
    r(id="java-junit4-afterclass", title="@AfterClass (JUnit 4)", desc="@AfterClass is the JUnit 4 class-teardown annotation.",
      rationale="JUnit 5 uses @AfterAll.", remediation="Use @AfterAll.", source=JUNIT5,
      re=r"@AfterClass\b", nc="@AfterClass", c="@AfterAll"),
    r(id="java-junit4-ignore", title="@Ignore (JUnit 4)", desc="@Ignore is the JUnit 4 skip annotation.",
      rationale="JUnit 5 uses @Disabled.", remediation="Use @Disabled.", source=JUNIT5,
      re=r"@Ignore\b", nc='@Ignore("flaky")', c='@Disabled("flaky")'),
    r(id="java-junit4-rule", title="@Rule (JUnit 4)", desc="@Rule is the JUnit 4 rule mechanism.",
      rationale="JUnit 5 replaces rules with extensions (@ExtendWith / @RegisterExtension).", remediation="Use a JUnit 5 extension.",
      source=JUNIT5, re=r"@Rule\b", nc="@Rule public TemporaryFolder folder = new TemporaryFolder();", c="@TempDir Path folder;"),
    r(id="java-junit4-expected-exception", title="ExpectedException rule", desc="ExpectedException is a JUnit 4 rule.",
      rationale="JUnit 5 uses assertThrows instead of the ExpectedException rule.", remediation="Use assertThrows(...).",
      source=JUNIT5, re=r"\bExpectedException\b", nc="ExpectedException thrown = ExpectedException.none();", c="assertThrows(IOException.class, () -> load());"),
    r(id="java-junit4-assert-that", title="Assert.assertThat (deprecated)", desc="JUnit's Assert.assertThat is deprecated.",
      rationale="JUnit deprecated Assert.assertThat; use Hamcrest's MatcherAssert or AssertJ.", remediation="Use MatcherAssert.assertThat or AssertJ.",
      source=JUNIT5, re=r"\bAssert\.assertThat\s*\(", nc="Assert.assertThat(actual, is(expected));", c="assertThat(actual).isEqualTo(expected);"),
    r(id="java-mockito-initmocks", title="MockitoAnnotations.initMocks", desc="initMocks is deprecated.",
      rationale="Mockito deprecated initMocks in favor of openMocks.", remediation="Use MockitoAnnotations.openMocks(this).",
      source="https://javadoc.io/doc/org.mockito/mockito-core/latest/org/mockito/MockitoAnnotations.html", re=r"MockitoAnnotations\.initMocks\s*\(",
      nc="MockitoAnnotations.initMocks(this);", c="MockitoAnnotations.openMocks(this);"),
    r(id="java-mockito-anyobject", title="Mockito.anyObject (deprecated)", desc="anyObject/anyVararg are deprecated matchers.",
      rationale="Mockito deprecated anyObject in favor of any.", remediation="Use Mockito.any().",
      source="https://javadoc.io/doc/org.mockito/mockito-core/latest/org/mockito/ArgumentMatchers.html", re=r"Mockito\.anyObject\s*\(",
      nc="when(svc.find(Mockito.anyObject())).thenReturn(u);", c="when(svc.find(Mockito.any())).thenReturn(u);"),
]
