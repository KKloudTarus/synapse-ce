CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="js-shadow-restricted-name", type="bug", qual="rel", sev="medium", cwe="",
      title="Shadowing a restricted name", desc="Declaring undefined/NaN/Infinity as a variable shadows the global.",
      rationale="Rebinding undefined/NaN/Infinity is confusing and can break comparisons that assume the global.",
      remediation="Rename the variable so it does not shadow a built-in value.",
      source="https://eslint.org/docs/latest/rules/no-shadow-restricted-names",
      re=r"\b(let|const|var)\s+(undefined|NaN|Infinity)\b", nc="let undefined = getValue();", c="let value = getValue();"),
]
