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


# JS/TS quality pack, batch A: unicorn DOM/modern-API idioms + TypeScript-specific patterns.
RULES = [
    r(id="js-reflect-apply", title="fn.apply(null, ...)", desc="Function.prototype.apply with null is fragile.",
      rationale="Reflect.apply or spread is clearer and cannot be shadowed (unicorn prefer-reflect-apply).",
      remediation="Use spread: fn(...args), or Reflect.apply.", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.apply\s*\(\s*(null|undefined)\s*,", nc="fn.apply(null, args);", c="fn(...args);"),
    r(id="js-structured-clone", title="JSON.parse(JSON.stringify(...))", desc="This is a lossy, slow deep clone.",
      rationale="structuredClone deep-clones correctly (dates, maps) and is faster (unicorn prefer-structured-clone).",
      remediation="Use structuredClone(value).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"JSON\.parse\s*\(\s*JSON\.stringify\s*\(", nc="const copy = JSON.parse(JSON.stringify(state));", c="const copy = structuredClone(state);"),
    r(id="js-prefer-add-event-listener", title="onX event handler assignment", desc="Assigning to onclick overwrites any prior handler.",
      rationale="addEventListener allows multiple listeners and explicit removal (unicorn prefer-add-event-listener).",
      remediation="Use addEventListener(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.on(click|load|error|change|submit|keydown|keyup|mouseover|mouseout|focus|blur|input|scroll)\s*=",
      nc="button.onclick = handleClick;", c='button.addEventListener("click", handleClick);'),
    r(id="js-prefer-dom-append", title="appendChild()", desc="Node.append() is more flexible than appendChild.",
      rationale="append accepts strings and multiple nodes and returns nothing to misuse (unicorn prefer-dom-node-append).",
      remediation="Use parent.append(child).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.appendChild\s*\(", nc="container.appendChild(node);", c="container.append(node);"),
    r(id="js-prefer-dataset", title="setAttribute('data-...')", desc="Data attributes are better accessed via dataset.",
      rationale="element.dataset is the idiomatic API for data-* attributes (unicorn prefer-dom-node-dataset).",
      remediation="Use element.dataset.name = value.", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r'''\.setAttribute\s*\(\s*["']data-''', nc='el.setAttribute("data-id", id);', c="el.dataset.id = id;"),
    r(id="ts-non-null-optional-chain", title="Non-null assertion after optional chain", desc="a?.b! defeats the optional chain.",
      rationale="Asserting non-null right after ?. contradicts the optional access and can crash (typescript-eslint no-non-null-asserted-optional-chain).",
      remediation="Handle the undefined case (?? or a guard) instead of asserting.", source="https://typescript-eslint.io/rules/no-non-null-asserted-optional-chain/",
      re=r"\?\.\w+!", nc="const v = user?.profile!;", c="const v = user?.profile ?? defaults;"),
    r(id="ts-extra-non-null", title="Extra non-null assertion", desc="a!! is a redundant double assertion.",
      rationale="Repeating the non-null assertion has no additional effect (typescript-eslint no-extra-non-null-assertion).",
      remediation="Use a single ! (or none).", source="https://typescript-eslint.io/rules/no-extra-non-null-assertion/",
      re=r"\w+!\s*!", nc="const v = value!!;", c="const v = value!;"),
    r(id="ts-unsafe-function-type", title="The Function type", desc="Function accepts any callable and returns any.",
      rationale="The broad Function type disables argument and return checking (typescript-eslint no-unsafe-function-type).",
      remediation="Use a specific signature, e.g. () => void.", source="https://typescript-eslint.io/rules/no-unsafe-function-type/",
      re=r":\s*Function\b", nc="let handler: Function;", c="let handler: () => void;"),
]
