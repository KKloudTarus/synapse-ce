CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","javascript"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="js-symbol-no-description",type="smell",qual="maint",sev="info",cwe="",title="Symbol without a description",
   desc="Symbol() with no description is hard to debug.",
   rationale="A description makes the symbol identifiable in logs and devtools; omitting it hinders debugging.",
   remediation="Pass a description string to Symbol().",
   source="https://eslint.org/docs/latest/rules/symbol-description",
   re=r"\bSymbol\s*\(\s*\)",nc="const key = Symbol();",c='const key = Symbol("cache");'),
 r(id="js-array-sort-no-compare",type="bug",qual="rel",sev="medium",cwe="",title="Array.sort without a comparator",
   desc="Default sort converts elements to strings, so numbers sort lexicographically.",
   rationale="Array.prototype.sort() without a comparator sorts by UTF-16 string order, so [10, 2] becomes [10, 2] → wrong for numbers.",
   remediation="Pass a comparator, e.g. sort((a, b) => a - b).",
   source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort",
   re=r"\b[A-Za-z_$][\w$.]*\.sort\s*\(\s*\)",nc="scores.sort();",c="scores.sort((a, b) => a - b);"),
 r(id="js-no-array-delete",type="bug",qual="rel",sev="low",cwe="",title="delete on an array element",
   desc="`delete arr[i]` leaves a hole and does not shift or shorten the array.",
   rationale="delete removes the value but keeps the index, producing a sparse array with a length that no longer matches its contents.",
   remediation="Use splice(i, 1) to remove and shift elements.",
   source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/delete",
   re=r"\bdelete\s+[A-Za-z_$][\w$.]*\[",nc="delete items[2];",c="items.splice(2, 1);"),
 r(id="js-prefer-spread",type="smell",qual="maint",sev="low",cwe="",title="Function.apply for argument spreading",
   desc="fn.apply(null, args) is clearer as fn(...args).",
   rationale="The spread operator conveys argument forwarding more directly than apply with a null/this receiver.",
   remediation="Use the spread syntax: fn(...args).",
   source="https://eslint.org/docs/latest/rules/prefer-spread",
   re=r"\.apply\s*\(\s*(null|this)\s*,",nc="render.apply(null, parts);",c="render(...parts);"),
]
