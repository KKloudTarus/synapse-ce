CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","java");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","java"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="java-equals-null",type="bug",qual="rel",sev="medium",cwe="",title="equals(null) is always false",
   desc="Calling equals(null) always returns false; a null check was intended.",
   rationale="Object.equals(null) is contractually false, so this test never succeeds — the author meant a == null comparison.",
   remediation="Use == null (or Objects.isNull).",
   source="https://errorprone.info/bugpattern/EqualsNull",
   re=r"\.equals\s*\(\s*null\s*\)",nc="if (name.equals(null)) skip();",c="if (name == null) skip();"),
 r(id="java-throw-npe",type="smell",qual="maint",sev="medium",cwe="",title="Throwing NullPointerException directly",
   desc="Throwing NullPointerException manually is indistinguishable from a real bug.",
   rationale="A hand-thrown NPE is confused with an accidental dereference; a specific exception documents the precondition (SEI CERT).",
   remediation="Throw IllegalArgumentException/IllegalStateException, or use Objects.requireNonNull.",
   source="https://wiki.sei.cmu.edu/confluence/display/java/ERR07-J.+Do+not+throw+RuntimeException%2C+Exception%2C+or+Throwable",
   re=r"throw\s+new\s+NullPointerException",nc='throw new NullPointerException("user");',c='throw new IllegalArgumentException("user is required");'),
 r(id="java-thread-yield",type="smell",qual="maint",sev="low",cwe="",title="Thread.yield() call",
   desc="Thread.yield() is a scheduler hint with no reliable effect.",
   rationale="yield() behavior is platform-dependent and rarely does anything useful; it usually masks a real synchronization need.",
   remediation="Use proper synchronization (locks, conditions, or java.util.concurrent).",
   source="https://wiki.sei.cmu.edu/confluence/display/java/THI00-J.+Do+not+invoke+Thread.run",
   re=r"\bThread\.yield\s*\(\s*\)",nc="while (busy) Thread.yield();",c="latch.await();"),
 r(id="java-redundant-intvalue",type="smell",qual="maint",sev="low",cwe="",title="Redundant valueOf().intValue()",
   desc="Integer.valueOf(s).intValue() boxes then unboxes needlessly.",
   rationale="Parsing to a wrapper only to unbox it allocates and is slower than parsing to a primitive directly.",
   remediation="Use Integer.parseInt(s) for a primitive result.",
   source="https://pmd.github.io/pmd/pmd_rules_java_performance.html",
   re=r"Integer\.valueOf\s*\([^)]*\)\.intValue\s*\(\)",nc="int n = Integer.valueOf(raw).intValue();",c="int n = Integer.parseInt(raw);"),
 r(id="java-string-length-zero",type="smell",qual="maint",sev="low",cwe="",title="length() == 0 instead of isEmpty()",
   desc="`s.length() == 0` is clearer as `s.isEmpty()`.",
   rationale="isEmpty() states intent directly for CharSequence emptiness checks.",
   remediation="Use s.isEmpty().",
   source="https://pmd.github.io/pmd/pmd_rules_java_performance.html",
   re=r"\.length\s*\(\s*\)\s*==\s*0",nc="if (title.length() == 0) fail();",c="if (title.isEmpty()) fail();"),
]
