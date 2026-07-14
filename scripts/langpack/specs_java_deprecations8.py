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
    r(id="java-gson-jsonparser-instance", title="new JsonParser().parse()", desc="Instance JsonParser.parse is deprecated.",
      rationale="Gson deprecated the instance JsonParser in favor of the static JsonParser.parseString.", remediation="Use JsonParser.parseString(json).",
      source="https://github.com/google/gson", re=r"new\s+JsonParser\s*\(\s*\)", nc="JsonElement e = new JsonParser().parse(json);", c="JsonElement e = JsonParser.parseString(json);"),
    r(id="java-mockito-verify-zero-interactions", title="verifyZeroInteractions()", desc="verifyZeroInteractions is deprecated.",
      rationale="Mockito deprecated verifyZeroInteractions in favor of verifyNoInteractions.", remediation="Use verifyNoInteractions(...).",
      source="https://javadoc.io/doc/org.mockito/mockito-core/latest/org/mockito/Mockito.html", re=r"verifyZeroInteractions\s*\(", nc="verifyZeroInteractions(repo);", c="verifyNoInteractions(repo);"),
]
