CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="java-log-string-concat", type="smell", qual="maint", sev="low",
      title="String concatenation in a log call", desc="Building log messages with + defeats level guards and parameterization.",
      rationale="Concatenated log arguments are always evaluated even when the level is disabled; placeholders defer the work.",
      remediation="Use SLF4J {} placeholders and pass the values as arguments.",
      source="https://www.slf4j.org/faq.html#logging_performance",
      re=r'\b(log|logger|LOG|LOGGER)\.(trace|debug|info|warn|error)\s*\(\s*"[^"]*"\s*\+',
      nc='log.info("user " + name + " logged in");', c='log.info("user {} logged in", name);'),
    r(id="java-decimalformat-static", type="bug", qual="rel", sev="medium",
      title="Static DecimalFormat", desc="DecimalFormat is not thread-safe; a shared static instance corrupts output under concurrency.",
      rationale="DecimalFormat holds mutable parsing state, so a static instance produces wrong results when used from multiple threads.",
      remediation="Create a DecimalFormat per use, or guard it with a ThreadLocal.",
      source="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/text/DecimalFormat.html",
      re=r"static\s+(final\s+)?DecimalFormat\b", nc='static final DecimalFormat FMT = new DecimalFormat("#.##");', c='DecimalFormat fmt = new DecimalFormat("#.##"); // per call'),
    r(id="java-spring-redirect-view-concat", type="hotspot", qual="sec", sev="medium", cwe="CWE-601", owasp="A01:2021",
      title="Concatenated Spring redirect view", desc="Concatenating input into a \"redirect:\" view name enables open redirect.",
      rationale="A redirect view name built from request input lets an attacker choose the destination.",
      remediation="Redirect only to a fixed allow-list of view names/paths.",
      source="https://cwe.mitre.org/data/definitions/601.html",
      re=r'return\s+"redirect:"\s*\+', nc='return "redirect:" + target;', c='return "redirect:/dashboard";'),
]
