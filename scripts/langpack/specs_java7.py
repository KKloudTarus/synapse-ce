CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","java");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","java"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="java-double-brace-init",type="smell",qual="maint",sev="low",cwe="",title="Double-brace initialization",
   desc="`new X() {{ ... }}` creates an anonymous subclass and holds an outer reference.",
   rationale="Double-brace init spawns a hidden anonymous class per use, adds a reference to the enclosing instance, and can leak memory.",
   remediation="Build and populate the collection with ordinary statements or a factory (List.of, Map.of).",
   source="https://pmd.github.io/pmd/pmd_rules_java_errorprone.html",
   re=r"\(\s*\)\s*\{\{",nc="Map<String,Integer> m = new HashMap<>() {{ put(\"a\", 1); }};",c="Map<String,Integer> m = Map.of(\"a\", 1);"),
 r(id="java-format-newline",type="smell",qual="maint",sev="low",cwe="",title="Literal \\n in String.format",
   desc="A literal newline in a format string is not platform-independent; use %n.",
   rationale="\\n is always a line feed, whereas %n emits the platform line separator, which format is designed to use.",
   remediation="Use %n in the format string.",
   source="https://docs.oracle.com/javase/8/docs/api/java/util/Formatter.html",
   re=r'String\.format\s*\([^)]*\\n',nc='String s = String.format("%s\\n", name);',c='String s = String.format("%s%n", name);'),
]
