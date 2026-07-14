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


# JS/TS quality pack: TypeScript + Angular deprecations, and a legacy accessor.
RULES = [
    r(id="ts-unnecessary-type-constraint", title="Type parameter extends any", desc="<T extends any> is the same as <T>.",
      rationale="Constraining a type parameter to any adds nothing (typescript-eslint no-unnecessary-type-constraint).",
      remediation="Drop the extends any constraint.", source="https://typescript-eslint.io/rules/no-unnecessary-type-constraint/",
      re=r"<\s*\w+\s+extends\s+any\s*>", nc="function first<T extends any>(xs: T[]) {}", c="function first<T>(xs: T[]) {}"),
    r(id="js-angular-renderer-v1", type="bug", qual="rel", sev="medium", title="Angular Renderer (v1)", desc="The original Renderer was removed.",
      rationale="Angular removed the v1 Renderer in favor of Renderer2.", remediation="Use Renderer2.",
      source="https://angular.io/api/core/Renderer2", re=r":\s*Renderer\b", nc="constructor(private r: Renderer) {}", c="constructor(private r: Renderer2) {}"),
    r(id="js-angular-reflective-injector", type="bug", qual="rel", sev="medium", title="Angular ReflectiveInjector", desc="ReflectiveInjector was removed.",
      rationale="ReflectiveInjector was removed in favor of the static Injector.create.", remediation="Use Injector.create({ providers }).",
      source="https://angular.io/api/core/Injector", re=r"\bReflectiveInjector\b", nc="const inj = ReflectiveInjector.resolveAndCreate(providers);", c="const inj = Injector.create({ providers });"),
    r(id="js-angular-class-guard", title="Class-based Angular route guard", desc="Class guards are deprecated in Angular 15+.",
      rationale="CanActivate class guards are deprecated in favor of functional guards.", remediation="Use a functional guard (CanActivateFn).",
      source="https://angular.io/api/router/CanActivate", re=r"implements\s+CanActivate\b", nc="class AuthGuard implements CanActivate {", c="const authGuard: CanActivateFn = () => true;"),
    r(id="js-lookup-getter-setter", title="__lookupGetter__ / __lookupSetter__", desc="These legacy accessors are deprecated.",
      rationale="__lookupGetter__/__lookupSetter__ are deprecated in favor of Object.getOwnPropertyDescriptor.",
      remediation="Use Object.getOwnPropertyDescriptor.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/__lookupGetter__",
      re=r"\.__lookup(Getter|Setter)__\s*\(", nc='const g = obj.__lookupGetter__("x");', c='const g = Object.getOwnPropertyDescriptor(obj, "x");'),
]
