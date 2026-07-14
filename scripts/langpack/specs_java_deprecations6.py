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


JD = "https://docs.oracle.com/javase/8/docs/api/"

# Java quality pack: deprecated JDBC / Thread / Character methods.
RULES = [
    r(id="java-jdbc-get-unicode-stream", title="ResultSet.getUnicodeStream()", desc="getUnicodeStream is deprecated.",
      rationale="ResultSet.getUnicodeStream is deprecated in favor of getCharacterStream.", remediation="Use getCharacterStream().",
      source=JD, re=r"\.getUnicodeStream\s*\(", nc="InputStream s = rs.getUnicodeStream(1);", c="Reader s = rs.getCharacterStream(1);"),
    r(id="java-thread-countstackframes", type="bug", qual="rel", sev="medium", title="Thread.countStackFrames()", desc="countStackFrames was removed.",
      rationale="Thread.countStackFrames was deprecated and removed.", remediation="Use Thread.getStackTrace().length if a count is needed.",
      source=JD, re=r"\.countStackFrames\s*\(", nc="int n = thread.countStackFrames();", c="int n = thread.getStackTrace().length;"),
    r(id="java-character-isjavaletterordigit", title="Character.isJavaLetterOrDigit()", desc="This method is deprecated.",
      rationale="Character.isJavaLetterOrDigit is deprecated in favor of isJavaIdentifierPart.", remediation="Use Character.isJavaIdentifierPart.",
      source=JD, re=r"\bCharacter\.isJavaLetterOrDigit\b", nc="if (Character.isJavaLetterOrDigit(c)) {", c="if (Character.isJavaIdentifierPart(c)) {"),
    r(id="java-character-isspace", title="Character.isSpace()", desc="Character.isSpace is deprecated.",
      rationale="Character.isSpace is deprecated in favor of isWhitespace.", remediation="Use Character.isWhitespace.",
      source=JD, re=r"\bCharacter\.isSpace\s*\(", nc="if (Character.isSpace(c)) {", c="if (Character.isWhitespace(c)) {"),
]
