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


# JS/TS quality pack: framework deprecations and anti-patterns (React, Vue, Node).
RULES = [
    # --- React ---
    r(id="js-react-string-ref", title="React string ref", desc="String refs are deprecated.",
      rationale="String refs (ref=\"name\") are legacy and slated for removal; use a callback or createRef (eslint-plugin-react no-string-refs).",
      remediation="Use a ref object or callback ref.", source="https://react.dev/reference/react-dom/components/common#ref-callback",
      re=r'''\bref\s*=\s*["']''', nc='<input ref="username" />', c="<input ref={usernameRef} />"),
    r(id="js-react-finddomnode", title="ReactDOM.findDOMNode", desc="findDOMNode is deprecated in StrictMode.",
      rationale="findDOMNode breaks abstraction and is deprecated; use a ref (eslint-plugin-react no-find-dom-node).",
      remediation="Attach a ref to the node instead.", source="https://react.dev/reference/react-dom/findDOMNode",
      re=r"\bfindDOMNode\s*\(", nc="const node = findDOMNode(this);", c="const node = this.nodeRef.current;"),
    r(id="js-react-deprecated-lifecycle", title="Deprecated React lifecycle method", desc="componentWillMount/ReceiveProps/Update are deprecated.",
      rationale="These unsafe lifecycle methods are deprecated in favor of the UNSAFE_ prefixes or hooks (eslint-plugin-react no-deprecated).",
      remediation="Use componentDidMount / getDerivedStateFromProps / hooks.", source="https://react.dev/reference/react/Component",
      re=r"\b(componentWillMount|componentWillReceiveProps|componentWillUpdate)\s*\(", nc="componentWillMount() {", c="componentDidMount() {"),
    r(id="js-react-children-prop", title="children passed as a prop", desc="Passing children as an explicit prop is unidiomatic.",
      rationale="JSX children should be nested, not passed via a children prop (eslint-plugin-react no-children-prop).",
      remediation="Nest the children between the tags.", source="https://react.dev/learn/passing-props-to-a-component",
      re=r"\bchildren\s*=\s*\{", nc="<List children={items} />", c="<List>{items}</List>"),
    r(id="js-react-createclass", type="bug", qual="rel", sev="medium", title="React.createClass removed",
      desc="React.createClass was removed in React 16.", rationale="React.createClass no longer exists; use an ES class or a function component.",
      remediation="Use a class or function component.", source="https://react.dev/reference/react/Component",
      re=r"React\.createClass\s*\(", nc="const C = React.createClass({", c="class C extends React.Component {"),
    r(id="js-react-proptypes", type="bug", qual="rel", sev="medium", title="React.PropTypes removed",
      desc="React.PropTypes was moved to the prop-types package.", rationale="React.PropTypes was removed in React 15.5 and throws when accessed.",
      remediation="Import PropTypes from the prop-types package.", source="https://react.dev/reference/react/Component",
      re=r"React\.PropTypes\b", nc="static propTypes = { name: React.PropTypes.string };", c="static propTypes = { name: PropTypes.string };"),
    r(id="js-react-dom-render", title="ReactDOM.render (legacy)", desc="ReactDOM.render is deprecated in React 18.",
      rationale="ReactDOM.render is replaced by createRoot(...).render(...) in React 18.",
      remediation="Use createRoot(container).render(...).", source="https://react.dev/reference/react-dom/render",
      re=r"ReactDOM\.render\s*\(", nc="ReactDOM.render(<App />, container);", c="createRoot(container).render(<App />);"),
    # --- Vue ---
    r(id="js-vue-slot-attribute", title="Vue 2 slot attribute", desc="The slot attribute was removed in Vue 3.",
      rationale="Named slots use v-slot in Vue 3; the slot attribute is removed.",
      remediation="Use v-slot:name.", source="https://v3-migration.vuejs.org/breaking-changes/slots-unification.html",
      re=r'''\bslot\s*=\s*["']''', nc='<template slot="header">', c="<template v-slot:header>"),
    r(id="js-vue-dollar-listeners", title="Vue 2 $listeners", desc="$listeners was removed in Vue 3.",
      rationale="$listeners was merged into $attrs in Vue 3.", remediation="Use $attrs (or useAttrs()).",
      source="https://v3-migration.vuejs.org/breaking-changes/listeners-removed.html",
      re=r"\$listeners\b", nc='v-on="$listeners"', c='v-bind="$attrs"'),
    r(id="js-vue-dollar-scopedslots", title="Vue 2 $scopedSlots", desc="$scopedSlots was removed in Vue 3.",
      rationale="$scopedSlots was merged into $slots in Vue 3.", remediation="Use $slots.",
      source="https://v3-migration.vuejs.org/breaking-changes/slots-unification.html",
      re=r"\$scopedSlots\b", nc="return this.$scopedSlots.default();", c="return this.$slots.default();"),
    r(id="js-vue-events-api", title="Vue 2 instance events API", desc="$on/$off/$once were removed in Vue 3.",
      rationale="The instance event emitter API was removed in Vue 3; use an external emitter.",
      remediation="Use an external event emitter (e.g. mitt).", source="https://v3-migration.vuejs.org/breaking-changes/events-api.html",
      re=r"\.\$(on|off|once)\s*\(", nc='this.$on("refresh", handler);', c='emitter.on("refresh", handler);'),
    # --- Node ---
    r(id="js-node-fs-exists", title="fs.exists() deprecated", desc="fs.exists is deprecated due to a race condition.",
      rationale="fs.exists is deprecated; its callback signature invites time-of-check/time-of-use bugs.",
      remediation="Use fs.access or fs.stat (or their sync/promise forms).", source="https://nodejs.org/api/fs.html#fsexistspath-callback",
      re=r"\bfs\.exists\s*\(", nc="fs.exists(path, (ok) => {});", c="fs.access(path, (err) => {});"),
    r(id="js-node-url-parse", title="Legacy url.parse()", desc="The legacy url.parse API is deprecated.",
      rationale="url.parse is deprecated in favor of the WHATWG URL class.",
      remediation="Use new URL(...).", source="https://nodejs.org/api/url.html#urlparseurlstring-parsequerystring-slashesdenotehost",
      re=r"\burl\.parse\s*\(", nc="const parts = url.parse(input);", c="const parts = new URL(input);"),
    r(id="js-node-domain-module", title="Deprecated domain module", desc="The domain module is deprecated.",
      rationale="The domain module is deprecated and pending removal.",
      remediation="Use async_hooks or structured error handling.", source="https://nodejs.org/api/domain.html",
      re=r'''require\s*\(\s*["']domain["']\s*\)''', nc='const domain = require("domain");', c='const hooks = require("node:async_hooks");'),
]
