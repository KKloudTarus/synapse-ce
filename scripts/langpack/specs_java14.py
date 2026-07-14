CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: XXE-prone parsers, JNDI injection, SSRF, fastjson deserialization.
RULES = [
    r(id="java-xxe-saxreader", type="hotspot", qual="sec", sev="medium", cwe="CWE-611", owasp="A05:2021",
      title="dom4j SAXReader XXE", desc="A default dom4j SAXReader resolves external entities.",
      rationale="SAXReader does not disable external entities by default, allowing XXE on untrusted XML.",
      remediation="Disable DOCTYPE/external entities via setFeature before reading.", source="https://cwe.mitre.org/data/definitions/611.html",
      re=r"new\s+SAXReader\s*\(", nc="Document d = new SAXReader().read(input);", c="Document d = hardenedReader().read(input);"),
    r(id="java-xxe-saxbuilder", type="hotspot", qual="sec", sev="medium", cwe="CWE-611", owasp="A05:2021",
      title="JDOM SAXBuilder XXE", desc="A default JDOM SAXBuilder resolves external entities.",
      rationale="SAXBuilder does not disable external entities by default, allowing XXE.",
      remediation="Set the disallow-doctype and external-entity features before building.", source="https://cwe.mitre.org/data/definitions/611.html",
      re=r"new\s+SAXBuilder\s*\(", nc="Document d = new SAXBuilder().build(input);", c="Document d = hardenedBuilder().build(input);"),
    r(id="java-xxe-xmlreaderfactory", type="hotspot", qual="sec", sev="medium", cwe="CWE-611", owasp="A05:2021",
      title="XMLReaderFactory XXE", desc="XMLReaderFactory.createXMLReader resolves external entities by default.",
      rationale="A reader from XMLReaderFactory does not disable external entities by default.",
      remediation="Disable external entities via setFeature, or use a hardened parser.", source="https://cwe.mitre.org/data/definitions/611.html",
      re=r"XMLReaderFactory\.createXMLReader\s*\(", nc="XMLReader r = XMLReaderFactory.createXMLReader();", c="SAXParserFactory f = hardenedSaxFactory();"),
    r(id="java-jndi-injection", type="hotspot", qual="sec", sev="high", cwe="CWE-74", owasp="A03:2021",
      title="JNDI lookup from request", desc="A JNDI name taken from the request enables JNDI injection.",
      rationale="Looking up an attacker-controlled JNDI name can load a remote object (RCE, Log4Shell-style).",
      remediation="Never build a JNDI name from untrusted input; use a fixed allowlist.", source="https://cwe.mitre.org/data/definitions/74.html",
      re=r"\.lookup\s*\([^)]*getParameter", nc='Object o = ctx.lookup(request.getParameter("name"));', c="Object o = ctx.lookup(allowlist.resolve(key));"),
    r(id="java-ssrf-url-param", type="hotspot", qual="sec", sev="high", cwe="CWE-918", owasp="A10:2021",
      title="URL from request parameter (SSRF)", desc="Opening a URL taken from the request enables SSRF.",
      rationale="A server-side request to a request-controlled URL can reach internal services (SSRF).",
      remediation="Validate the host against an allowlist before connecting.", source="https://cwe.mitre.org/data/definitions/918.html",
      re=r"new\s+URL\s*\([^)]*getParameter", nc='InputStream in = new URL(request.getParameter("u")).openStream();', c="URL u = new URL(allowlist.resolve(key));"),
    r(id="java-fastjson-parseobject", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="fastjson parseObject", desc="fastjson auto-type deserialization has known RCE gadgets.",
      rationale="fastjson can instantiate arbitrary types via auto-type, a known RCE vector on untrusted JSON.",
      remediation="Keep auto-type disabled, or use a safer JSON library with explicit binding.", source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"\bJSON\.parseObject\s*\(", nc="User u = JSON.parseObject(json, User.class);", c="User u = safeMapper.readValue(json, User.class);"),
]
