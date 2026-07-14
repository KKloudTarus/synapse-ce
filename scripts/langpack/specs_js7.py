CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","javascript"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="js-prefer-includes",type="smell",qual="maint",sev="low",cwe="",title="indexOf comparison instead of includes",
   desc="`indexOf(x) !== -1` is clearer as `includes(x)`.",
   rationale="includes() expresses a membership test directly and avoids off-by-one mistakes with the -1 sentinel.",
   remediation="Use Array/String includes().",
   source="https://eslint.org/docs/latest/rules/no-restricted-syntax",
   re=r"\.indexOf\s*\([^)]*\)\s*(!==|===|>=|<)\s*-?\s*[01]",nc="if (roles.indexOf(role) !== -1) allow();",c="if (roles.includes(role)) allow();"),
 r(id="js-global-isnan",type="bug",qual="rel",sev="medium",cwe="",title="Global isNaN coerces its argument",
   desc="Global isNaN() coerces to number first, so isNaN('x') is true; use Number.isNaN.",
   rationale="Global isNaN converts the argument to a number before testing, giving surprising results for non-numbers.",
   remediation="Use Number.isNaN(x), which does not coerce.",
   source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/isNaN",
   re=r"(^|[^.\w])isNaN\s*\(",nc="if (isNaN(value)) reject();",c="if (Number.isNaN(value)) reject();"),
]
