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


RULES = [
    r(id="java-vector-add-element", title="Vector.addElement()", desc="addElement is a legacy Vector method.",
      rationale="addElement is the legacy Vector API; use List.add on an ArrayList.", remediation="Use List.add(...) on an ArrayList.",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/Vector.html", re=r"\.addElement\s*\(", nc="items.addElement(value);", c="items.add(value);"),
    r(id="java-legacy-stack", title="java.util.Stack", desc="Stack is a legacy, synchronized Vector subclass.",
      rationale="java.util.Stack extends Vector and is synchronized; ArrayDeque is preferred.", remediation="Use Deque / ArrayDeque.",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/Stack.html", re=r"new\s+Stack\s*(<[^>]*>)?\s*\(", nc="Stack<Integer> s = new Stack<>();", c="Deque<Integer> s = new ArrayDeque<>();"),
    r(id="java-thread-dumpstack", title="Thread.dumpStack()", desc="dumpStack is a debugging leftover.",
      rationale="Thread.dumpStack prints to stderr and is usually leftover debugging.", remediation="Remove it, or log with a proper logger.",
      source="https://docs.oracle.com/javase/8/docs/api/java/lang/Thread.html", re=r"Thread\.dumpStack\s*\(", nc="Thread.dumpStack();", c='logger.debug("trace", new Throwable());'),
]
