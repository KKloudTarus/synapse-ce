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


# Java quality pack: JDK deprecated-for-removal / removed APIs and legacy collections.
RULES = [
    r(id="java-applet", type="bug", qual="rel", sev="medium", title="Applet API", desc="Applet/JApplet were removed from the JDK.",
      rationale="The applet API was removed; browsers no longer run applets.", remediation="Migrate to a standalone app or web technology.",
      source="https://openjdk.org/jeps/398", re=r"extends\s+J?Applet\b", nc="class Game extends JApplet {", c="class Game extends JPanel {"),
    r(id="java-set-security-manager", title="System.setSecurityManager()", desc="The SecurityManager is deprecated for removal.",
      rationale="The Security Manager is deprecated for removal (JEP 411).", remediation="Do not rely on the Security Manager; use OS/container isolation.",
      source="https://openjdk.org/jeps/411", re=r"System\.setSecurityManager\s*\(", nc="System.setSecurityManager(new SecurityManager());", c="// rely on container/OS sandboxing"),
    r(id="java-thread-suspend", title="Thread.suspend() / resume()", desc="Thread.suspend/resume are deprecated and deadlock-prone.",
      rationale="Thread.suspend can leave monitors held, causing deadlocks; it is deprecated.", remediation="Use cooperative interruption (a volatile flag / interrupt()).",
      source="https://docs.oracle.com/javase/8/docs/technotes/guides/concurrency/threadPrimitiveDeprecation.html", re=r"\.suspend\s*\(\s*\)", nc="worker.suspend();", c="worker.interrupt();"),
    r(id="java-run-finalizers-on-exit", type="bug", qual="rel", sev="medium", title="runFinalizersOnExit()", desc="runFinalizersOnExit was removed.",
      rationale="Runtime/System.runFinalizersOnExit was inherently unsafe and removed.", remediation="Use shutdown hooks or explicit cleanup.",
      source="https://docs.oracle.com/en/java/javase/17/docs/api/", re=r"runFinalizersOnExit\s*\(", nc="Runtime.runFinalizersOnExit(true);", c="Runtime.getRuntime().addShutdownHook(cleanupThread);"),
    r(id="java-run-finalization", title="System.runFinalization()", desc="runFinalization is deprecated for removal.",
      rationale="Finalization is deprecated for removal (JEP 421).", remediation="Use try-with-resources / Cleaner.",
      source="https://openjdk.org/jeps/421", re=r"System\.runFinalization\s*\(", nc="System.runFinalization();", c="// use try-with-resources / Cleaner"),
    r(id="java-observable-observer", title="Observable / Observer", desc="java.util.Observable and Observer are deprecated.",
      rationale="Observable/Observer are deprecated (thread-unsafe, limited).", remediation="Use PropertyChangeSupport, a Flow.Publisher, or a listener list.",
      source="https://docs.oracle.com/javase/9/docs/api/java/util/Observable.html", re=r"\b(extends\s+Observable|implements\s+Observer)\b", nc="class Model extends Observable {", c="class Model { private final PropertyChangeSupport pcs; }"),
    r(id="java-access-controller", title="AccessController.doPrivileged()", desc="AccessController is deprecated for removal.",
      rationale="AccessController.doPrivileged is deprecated for removal with the Security Manager (JEP 411).", remediation="Remove privileged blocks as the Security Manager is retired.",
      source="https://openjdk.org/jeps/411", re=r"AccessController\.doPrivileged\s*\(", nc="AccessController.doPrivileged(action);", c="action.run();"),
    r(id="java-vector-elementat", title="Vector.elementAt()", desc="elementAt is a legacy Vector method.",
      rationale="elementAt is the legacy accessor; use get on a List.", remediation="Use List.get(index).",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/Vector.html", re=r"\.elementAt\s*\(", nc="Object o = data.elementAt(0);", c="Object o = data.get(0);"),
    r(id="java-string-tokenizer", title="StringTokenizer", desc="StringTokenizer is a legacy tokenizer.",
      rationale="StringTokenizer is a legacy class; String.split or a Scanner is preferred.", remediation="Use String.split(regex).",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/StringTokenizer.html", re=r"new\s+StringTokenizer\s*\(", nc="StringTokenizer st = new StringTokenizer(line);", c='String[] parts = line.split("\\\\s+");'),
]
