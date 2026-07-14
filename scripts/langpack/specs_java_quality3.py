CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java quality/reliability pack: PMD / SpotBugs idioms.
RULES = [
    r(id="java-catch-throwable", type="bug", qual="rel", sev="medium", cwe="CWE-396", title="Catching Throwable",
      desc="Catching Throwable also swallows Errors like OutOfMemoryError.",
      rationale="Throwable includes Error; catching it hides serious JVM problems that should propagate.",
      remediation="Catch the specific checked exceptions you can handle.", source="https://wiki.sei.cmu.edu/confluence/display/java/ERR07-J.+Do+not+throw+RuntimeException%2C+Exception%2C+or+Throwable",
      re=r"catch\s*\(\s*(final\s+)?Throwable\b", nc="} catch (Throwable t) {", c="} catch (IOException e) {"),
    r(id="java-extends-thread", type="smell", qual="maint", sev="low", cwe="", title="Class extends Thread",
      desc="Extending Thread couples the task to the thread; prefer Runnable.",
      rationale="Implementing Runnable (or using an executor) separates the task from its execution and is more flexible.",
      remediation="Implement Runnable and submit it to an executor.", source="https://pmd.github.io/pmd/pmd_rules_java_multithreading.html",
      re=r"extends\s+Thread\b", nc="class Worker extends Thread {", c="class Worker implements Runnable {"),
    r(id="java-literals-first-equals", type="bug", qual="rel", sev="low", cwe="", title="Literal not first in equals",
      desc="var.equals(\"literal\") throws NPE when var is null.",
      rationale="Calling equals on a possibly-null variable risks NullPointerException; put the literal first.",
      remediation="Write \"literal\".equals(var).", source="https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html",
      re=r'\b\w+\.equals\s*\(\s*"', nc='if (role.equals("admin")) {', c='if ("admin".equals(role)) {'),
    r(id="java-public-finalize", type="smell", qual="maint", sev="low", cwe="", title="public finalize()",
      desc="finalize() should be protected, not public.",
      rationale="A public finalize lets any caller invoke finalization, and finalize is itself deprecated.",
      remediation="Avoid finalize; use try-with-resources or Cleaner. If overriding, keep it protected.",
      source="https://docs.oracle.com/javase/specs/jls/se17/html/jls-12.html", re=r"public\s+void\s+finalize\s*\(",
      nc="public void finalize() {", c="// use AutoCloseable / try-with-resources instead"),
]
