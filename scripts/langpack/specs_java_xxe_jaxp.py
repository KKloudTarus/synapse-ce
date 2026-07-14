CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "A05:2021")
    k.setdefault("effort", 30)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "hotspot")
    k.setdefault("qual", "sec")
    k.setdefault("sev", "medium")
    k.setdefault("cwe", "CWE-611")
    return k


XXE = "https://cwe.mitre.org/data/definitions/611.html"


def factory(name, cls, sample):
    return r(id="java-xxe-" + name,
             title=cls + " without XXE hardening",
             desc="A " + cls + " parses XML with external entities enabled unless explicitly disabled.",
             rationale="JAXP factories resolve external entities/DTDs by default, exposing XXE and SSRF.",
             remediation="Call setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) and disallow DOCTYPE/external DTDs.",
             source=XXE, re=cls + r"\.newInstance\s*\(",
             nc=sample + " = " + cls + ".newInstance();",
             c="var f = hardened" + cls + "(); // shared factory with FEATURE_SECURE_PROCESSING and DOCTYPE disabled")


# Java security pack: JAXP parser factories that need explicit XXE hardening (review hotspots).
RULES = [
    factory("documentbuilder-factory", "DocumentBuilderFactory", "DocumentBuilderFactory f"),
    factory("saxparser-factory", "SAXParserFactory", "SAXParserFactory f"),
    factory("transformer-factory", "TransformerFactory", "TransformerFactory f"),
    factory("xmlinput-factory", "XMLInputFactory", "XMLInputFactory f"),
    factory("schema-factory", "SchemaFactory", "SchemaFactory f"),
]
