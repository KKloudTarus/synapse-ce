CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","javascript"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="js-yoda-condition",type="smell",qual="maint",sev="low",cwe="",title="Yoda condition",
   desc="A literal on the left of a comparison reads awkwardly.",
   rationale="Placing the literal first (\"admin\" === role) is harder to read than variable-first; modern engines make the safety motivation obsolete.",
   remediation="Put the variable on the left of the comparison.",
   source="https://eslint.org/docs/latest/rules/yoda",
   re=r"\(\s*['\"][^'\"]*['\"]\s*===",nc='if ("admin" === role) grant();',c='if (role === "admin") grant();'),
 r(id="js-no-useless-computed-key",type="smell",qual="maint",sev="low",cwe="",title="Unnecessary computed key",
   desc="A computed key that is a constant identifier string is just a normal key.",
   rationale="{ [\"name\"]: v } is equivalent to { name: v }; the computed syntax adds noise.",
   remediation="Use a plain property key.",
   source="https://eslint.org/docs/latest/rules/no-useless-computed-key",
   re=r"\{\s*\[\s*['\"][A-Za-z_$][\w$]*['\"]\s*\]\s*:",nc='const o = { ["id"]: 1 };',c="const o = { id: 1 };"),
 r(id="js-no-loss-of-precision",type="bug",qual="rel",sev="medium",cwe="",title="Integer literal beyond safe range",
   desc="An integer literal with 16+ digits exceeds Number.MAX_SAFE_INTEGER and loses precision.",
   rationale="JavaScript numbers are IEEE-754 doubles; integer literals above 2^53 silently lose precision.",
   remediation="Use a BigInt literal (123n) or a string for large identifiers.",
   source="https://eslint.org/docs/latest/rules/no-loss-of-precision",
   re=r"[^.\dn]\d{16,}\b",nc="const id = x + 90071992547409910;",c="const id = 90071992547409910n;"),
 r(id="js-no-empty-pattern",type="bug",qual="rel",sev="low",cwe="",title="Empty destructuring pattern",
   desc="`const {} = x` binds nothing and only asserts x is not null/undefined.",
   rationale="An empty destructuring pattern extracts no values and is almost always an editing mistake.",
   remediation="Destructure the properties you need, or remove the pattern.",
   source="https://eslint.org/docs/latest/rules/no-empty-pattern",
   re=r"\{\s*\}\s*=",nc="const {} = props;",c="const { id } = props;"),
 r(id="ts-ban-boxed-types",type="smell",qual="maint",sev="low",cwe="",title="Boxed primitive type annotation",
   desc="Type annotations Object/String/Number/Boolean/Function are the boxed wrappers, not primitives.",
   rationale="The capitalized types refer to wrapper objects and are broader/less safe than the primitive types (string, number, ...).",
   remediation="Use the lowercase primitive type (string, number, boolean, object).",
   source="https://typescript-eslint.io/rules/no-restricted-types/",
   re=r":\s*(Object|String|Number|Boolean|Function)\b",nc="let v: Object = getIt();",c="let v: object = getIt();",tags=["sast","typescript"]),
]
