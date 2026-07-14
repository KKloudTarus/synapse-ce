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
    r(id="java-loose-coupling-collection", type="smell", qual="maint", sev="low", cwe="", title="Field typed as a concrete collection",
      desc="Declaring a field as ArrayList/HashMap couples to the implementation.",
      rationale="Declaring the interface type (List/Map/Set) keeps the implementation swappable (PMD LooseCoupling).",
      remediation="Declare the interface type (List, Map, Set).", source="https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html",
      re=r"\b(private|public|protected)\s+(final\s+)?(ArrayList|HashMap|HashSet|LinkedList|Vector|Hashtable|TreeMap|TreeSet)\b",
      nc="private ArrayList<String> items;", c="private List<String> items;"),
]
