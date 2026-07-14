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


# Java quality pack: PMD / Error-Prone idioms.
RULES = [
    r(id="java-for-empty-init-while", title="for(;cond;) instead of while", desc="A for loop with an empty init and update is a while loop.",
      rationale="An empty init and update make a for loop a disguised while (PMD ForLoopShouldBeWhileLoop).",
      remediation="Use a while loop.", source="https://pmd.github.io/pmd/pmd_rules_java_codestyle.html",
      re=r"for\s*\(\s*;", nc="for (; i < n;) { step(); }", c="while (i < n) { step(); }"),
    r(id="java-double-tostring", title="Redundant toString().toString()", desc="Calling toString on a String result is redundant.",
      rationale="Chaining toString twice is a no-op on the second call.",
      remediation="Call toString once.", source="https://pmd.github.io/pmd/pmd_rules_java_errorprone.html",
      re=r"\.toString\s*\(\s*\)\s*\.\s*toString\s*\(", nc="String s = value.toString().toString();", c="String s = value.toString();"),
    r(id="java-unnecessary-temporary-conversion", title="new Wrapper(x).toString()", desc="Creating a wrapper just to call toString is wasteful.",
      rationale="new Integer(x).toString() allocates needlessly; use the static toString (PMD UnnecessaryConversionTemporary).",
      remediation="Use Integer.toString(x) / String.valueOf(x).", source="https://pmd.github.io/pmd/pmd_rules_java_performance.html",
      re=r"new\s+(Integer|Long|Double|Float|Boolean)\s*\([^)]*\)\.toString\s*\(", nc="String s = new Integer(count).toString();", c="String s = Integer.toString(count);"),
    r(id="java-append-char-with-string", title="Single-character String append", desc="Appending a one-char String is slower than a char.",
      rationale="StringBuilder.append('x') is faster than append(\"x\") (PMD AppendCharacterWithChar).",
      remediation="Append a char literal: append('x').", source="https://pmd.github.io/pmd/pmd_rules_java_performance.html",
      re=r'\.append\s*\(\s*"[^"\\]"\s*\)', nc='sb.append("/");', c="sb.append('/');"),
    r(id="java-literals-first-equalsignorecase", type="bug", qual="rel", sev="low", title="Literal not first in equalsIgnoreCase",
      desc="var.equalsIgnoreCase(\"literal\") throws NPE when var is null.",
      rationale="Calling equalsIgnoreCase on a possibly-null variable risks NPE; put the literal first.",
      remediation='Write "literal".equalsIgnoreCase(var).', source="https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html",
      re=r'\b\w+\.equalsIgnoreCase\s*\(\s*"', nc='if (role.equalsIgnoreCase("admin")) {', c='if ("admin".equalsIgnoreCase(role)) {'),
    r(id="java-unnecessary-unboxing", title="valueOf(...).xxxValue()", desc="Boxing then immediately unboxing is wasteful.",
      rationale="Integer.valueOf(s).intValue() boxes then unboxes; parse directly (PMD UnnecessaryWrapperObjectCreation).",
      remediation="Use the primitive parse (Integer.parseInt, etc).", source="https://pmd.github.io/pmd/pmd_rules_java_performance.html",
      re=r"\.valueOf\s*\([^)]*\)\.(intValue|longValue|doubleValue|floatValue|booleanValue|shortValue|byteValue)\s*\(",
      nc="int n = Integer.valueOf(s).intValue();", c="int n = Integer.parseInt(s);"),
    r(id="java-boolean-valueof-literal", title="Boolean.valueOf(\"true\")", desc="Parsing a boolean literal is wasteful.",
      rationale="Boolean.valueOf(\"true\") should be Boolean.TRUE.", remediation="Use Boolean.TRUE / Boolean.FALSE.",
      source="https://pmd.github.io/pmd/pmd_rules_java_performance.html", re=r'Boolean\.valueOf\s*\(\s*"(true|false)"', nc='Boolean b = Boolean.valueOf("true");', c="Boolean b = Boolean.TRUE;"),
    r(id="java-string-valueof-literal", title="String.valueOf(\"literal\")", desc="String.valueOf on a String literal is redundant.",
      rationale="String.valueOf of a string literal returns the same string.", remediation="Use the string literal directly.",
      source="https://pmd.github.io/pmd/pmd_rules_java_errorprone.html", re=r'String\.valueOf\s*\(\s*"', nc='String s = String.valueOf("ready");', c='String s = "ready";'),
    r(id="java-explicit-boolean-compare-tostring", title="\"\" + boolean concatenation", desc="Concatenating with an empty string to stringify is obscure.",
      rationale="\"\" + value coerces to String obscurely; String.valueOf is clearer.", remediation="Use String.valueOf(value).",
      source="https://pmd.github.io/pmd/pmd_rules_java_performance.html", re=r'""\s*\+\s*\w', nc='String s = "" + count;', c="String s = String.valueOf(count);"),
]
