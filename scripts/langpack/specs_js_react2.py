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


# JS/TS quality pack: more React anti-patterns + an Angular deprecation.
RULES = [
    r(id="js-react-unsafe-lifecycle", title="UNSAFE_ React lifecycle", desc="UNSAFE_ lifecycle methods are legacy escape hatches.",
      rationale="The UNSAFE_ prefixed lifecycles are deprecated; prefer hooks or safe lifecycles (eslint-plugin-react).",
      remediation="Use getDerivedStateFromProps / componentDidUpdate / hooks.", source="https://react.dev/reference/react/Component",
      re=r"\bUNSAFE_component(WillMount|WillReceiveProps|WillUpdate)\b", nc="UNSAFE_componentWillMount() {", c="componentDidMount() {"),
    r(id="js-react-is-mounted", type="bug", qual="rel", sev="medium", title="isMounted()", desc="isMounted is deprecated and anti-pattern.",
      rationale="isMounted encourages leaks and is deprecated (eslint-plugin-react no-is-mounted).",
      remediation="Track mounted state with a ref, or cancel work in cleanup.", source="https://react.dev/reference/react/Component",
      re=r"\.isMounted\s*\(", nc="if (this.isMounted()) {", c="if (this.mountedRef.current) {"),
    r(id="js-react-style-string", title="style attribute as a string", desc="In JSX, style must be an object.",
      rationale="A string style is invalid in React JSX; it must be an object (eslint-plugin-react style-prop-object).",
      remediation="Pass a style object: style={{ ... }}.", source="https://react.dev/reference/react-dom/components/common#applying-css-styles",
      re=r'''\bstyle\s*=\s*["']''', nc='<div style="color: red">', c='<div style={{ color: "red" }}>'),
    r(id="js-react-jsx-class-attribute", title="class attribute in JSX", desc="JSX uses className, not class.",
      rationale="The class attribute is ignored by React; the prop is className (eslint-plugin-react no-unknown-property).",
      remediation="Use className.", source="https://react.dev/learn/writing-markup-with-jsx",
      re=r'''\bclass\s*=\s*["']''', nc='<div class="box">', c='<div className="box">'),
    r(id="js-angular-testbed-get", title="Angular TestBed.get()", desc="TestBed.get was deprecated in favor of inject.",
      rationale="TestBed.get is deprecated; TestBed.inject is type-safe.", remediation="Use TestBed.inject(Token).",
      source="https://angular.io/api/core/testing/TestBed", re=r"TestBed\.get\s*\(",
      nc="const service = TestBed.get(DataService);", c="const service = TestBed.inject(DataService);"),
]
