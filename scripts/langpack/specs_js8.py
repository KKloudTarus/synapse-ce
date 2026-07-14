CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","javascript"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="js-no-floating-decimal",type="smell",qual="maint",sev="low",cwe="",title="Leading/trailing decimal point",
   desc="A number like .5 or 5. is easy to misread; add the leading/trailing zero.",
   rationale="Omitting the digit around the decimal point (.5, 5.) is easy to miss during review.",
   remediation="Write 0.5 / 5.0.",
   source="https://eslint.org/docs/latest/rules/no-floating-decimal",
   re=r"(^|[^\w.])\.[0-9]",nc="const ratio = .5;",c="const ratio = 0.5;"),
 r(id="js-no-undef-init",type="smell",qual="maint",sev="low",cwe="",title="Initializing a variable to undefined",
   desc="`let x = undefined` is redundant; an uninitialized let is already undefined.",
   rationale="Explicitly assigning undefined is noise and can defeat some engine optimizations.",
   remediation="Declare the variable without an initializer.",
   source="https://eslint.org/docs/latest/rules/no-undef-init",
   re=r"\b(let|var)\s+[A-Za-z_$][\w$]*\s*=\s*undefined\b",nc="let cfg = undefined;",c="let cfg;"),
 r(id="js-prefer-promise-reject-errors",type="bug",qual="rel",sev="low",cwe="",title="Promise rejected with a non-Error",
   desc="Rejecting with a string loses the stack trace and Error semantics.",
   rationale="A rejection value that is not an Error gives no stack trace and breaks instanceof Error checks downstream.",
   remediation="Reject with an Error instance.",
   source="https://eslint.org/docs/latest/rules/prefer-promise-reject-errors",
   re=r"\breject\s*\(\s*['\"]",nc='reject("timed out");',c='reject(new Error("timed out"));'),
 r(id="node-path-concat",type="hotspot",qual="sec",sev="low",cwe="CWE-22",owasp="A01:2021",title="Path built by string concatenation",
   desc="Concatenating __dirname/__filename with strings is platform-fragile and traversal-prone.",
   rationale="String path building ignores OS separators and can be steered with ../ if any segment is input-derived.",
   remediation="Use path.join / path.resolve.",
   source="https://cwe.mitre.org/data/definitions/22.html",
   re=r"(__dirname|__filename)\s*\+",nc='const p = __dirname + "/" + name;',c="const p = path.join(__dirname, name);",tags=["sast","node"]),
]
