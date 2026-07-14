CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","java");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","java"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="java-empty-static-block",type="smell",qual="maint",sev="low",cwe="",title="Empty static initializer",
   desc="An empty `static {}` block does nothing.",
   rationale="An empty static initializer is dead code, often a leftover.",
   remediation="Remove the empty static block.",
   source="https://pmd.github.io/pmd/pmd_rules_java_errorprone.html",
   re=r"static\s*\{\s*\}",nc="static {}",c="static { register(); }"),
 r(id="java-indexof-char",type="smell",qual="maint",sev="low",cwe="",title="indexOf with a single-character string",
   desc="indexOf(\"x\") is slower than indexOf('x').",
   rationale="Passing a single-char String to indexOf uses the slower CharSequence path; a char literal is faster.",
   remediation="Use a char literal: indexOf('x').",
   source="https://pmd.github.io/pmd/pmd_rules_java_performance.html",
   re=r'\.indexOf\s*\(\s*"[^"\\]"\s*\)',nc='int i = path.indexOf("/");',c="int i = path.indexOf('/');"),
 r(id="java-import-sun",type="smell",qual="maint",sev="medium",cwe="",title="Import of an internal sun.* API",
   desc="sun.* packages are internal, unsupported, and may be removed.",
   rationale="Depending on sun.* internal APIs is non-portable and breaks across JDK versions.",
   remediation="Use a supported public API.",
   source="https://openjdk.org/jeps/260",
   re=r"\bimport\s+sun\.",nc="import sun.misc.Unsafe;",c="import java.util.List;"),
 r(id="java-setaccessible-true",type="hotspot",qual="sec",sev="medium",cwe="CWE-266",owasp="A04:2021",title="Reflection setAccessible(true)",
   desc="setAccessible(true) bypasses access checks and encapsulation.",
   rationale="Suppressing Java access control via reflection can reach private state, break invariants, and evade the security manager.",
   remediation="Use a public API; reserve setAccessible for controlled framework internals.",
   source="https://cwe.mitre.org/data/definitions/266.html",
   re=r"setAccessible\s*\(\s*true\s*\)",nc="field.setAccessible(true);",c="return accessor.get();"),
 r(id="java-throw-raw-runtime",type="smell",qual="maint",sev="low",cwe="",title="Throwing a raw RuntimeException/Error",
   desc="Throwing RuntimeException/Throwable/Error directly gives callers nothing specific to catch.",
   rationale="A raw runtime exception type conveys no semantics; a specific subclass lets callers handle it deliberately (SonarJava S112).",
   remediation="Throw a specific exception subclass.",
   source="https://wiki.sei.cmu.edu/confluence/display/java/ERR07-J.+Do+not+throw+RuntimeException%2C+Exception%2C+or+Throwable",
   re=r"throw\s+new\s+(RuntimeException|Throwable|Error)\s*\(",nc='throw new RuntimeException("failed");',c='throw new IllegalStateException("failed");'),
]
