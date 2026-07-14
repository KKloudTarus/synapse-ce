CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


# JS/TS quality pack, batch 7: unicorn modern-API idioms + TypeScript-specific patterns.
RULES = [
    r(id="js-charat-startswith", title="charAt(0) === comparison", desc="Comparing charAt(0) to a character is a prefix check.",
      rationale="startsWith states the intent of a prefix test more clearly (unicorn prefer-string-starts-ends-with).",
      remediation="Use startsWith(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r'''\.charAt\s*\(\s*0\s*\)\s*===''', nc='if (path.charAt(0) === "/") {', c='if (path.startsWith("/")) {'),
    r(id="js-charcodeat", title="charCodeAt()", desc="charCodeAt returns a UTF-16 code unit, not a code point.",
      rationale="codePointAt handles astral characters correctly (unicorn prefer-code-point).",
      remediation="Use codePointAt(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.charCodeAt\s*\(", nc="const code = ch.charCodeAt(0);", c="const code = ch.codePointAt(0);"),
    r(id="js-parentnode-removechild", title="parentNode.removeChild()", desc="Element.remove() is simpler than parentNode.removeChild.",
      rationale="node.remove() avoids the parent lookup and the reference dance (unicorn prefer-dom-node-remove).",
      remediation="Use node.remove().", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.parentNode\s*\.\s*removeChild\s*\(", nc="node.parentNode.removeChild(node);", c="node.remove();"),
    r(id="js-indexof-minus-one", title="indexOf(...) compared to -1", desc="indexOf() !== -1 is a membership test.",
      rationale="includes() states the intent of a membership test more clearly (unicorn/eslint prefer-includes).",
      remediation="Use includes(...) (negate for the -1 case).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.indexOf\s*\([^)]*\)\s*(===?|!==?)\s*-1", nc="if (list.indexOf(x) === -1) {", c="if (!list.includes(x)) {"),
    r(id="ts-no-this-alias", title="Aliasing this to a variable", desc="const self = this is unnecessary with arrow functions.",
      rationale="Arrow functions keep the lexical this, so aliasing it is a legacy workaround (typescript-eslint no-this-alias).",
      remediation="Use an arrow function to keep this, instead of aliasing it.", source="https://typescript-eslint.io/rules/no-this-alias/",
      re=r"\b(const|let|var)\s+\w+\s*=\s*this\s*;", nc="const self = this;", c="const name = this.name;"),
    r(id="ts-ban-tslint-comment", title="tslint control comment", desc="tslint is deprecated in favor of typescript-eslint.",
      rationale="tslint disable comments no longer have any effect (typescript-eslint ban-tslint-comment).",
      remediation="Remove the tslint comment (use eslint-disable if needed).", source="https://typescript-eslint.io/rules/ban-tslint-comment/",
      re=r"//\s*tslint:", nc="// tslint:disable-next-line", c="const x = 1;", skip=""),
]
