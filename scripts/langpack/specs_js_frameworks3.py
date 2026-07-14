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


# JS/TS quality pack: more Vue 3 removals + React legacy context / mixins.
RULES = [
    r(id="js-vue-children", type="bug", qual="rel", sev="medium", title="Vue 2 $children", desc="$children was removed in Vue 3.",
      rationale="$children was removed in Vue 3; use refs or provide/inject.", remediation="Use template refs or provide/inject.",
      source="https://v3-migration.vuejs.org/breaking-changes/children.html", re=r"\.\$children\b",
      nc="this.$children.forEach(update);", c="this.itemRefs.forEach(update);"),
    r(id="js-vue-destroy", type="bug", qual="rel", sev="medium", title="Vue 2 $destroy()", desc="$destroy was removed in Vue 3.",
      rationale="$destroy was removed in Vue 3; unmount the app instead.", remediation="Use app.unmount().",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\.\$destroy\s*\(",
      nc="vm.$destroy();", c="app.unmount();"),
    r(id="js-vue-global-nexttick", title="Vue.nextTick", desc="The global Vue.nextTick moved to a named import.",
      rationale="Vue 3 exposes nextTick as a named import, not on the Vue global.", remediation="Import nextTick from vue.",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\bVue\.nextTick\b",
      nc="Vue.nextTick(() => update());", c="nextTick(() => update());"),
    r(id="js-vue-use", title="Vue.use()", desc="Global Vue.use was replaced by app.use in Vue 3.",
      rationale="Vue 3 installs plugins per-app via app.use.", remediation="Use app.use(plugin).",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\bVue\.use\s*\(",
      nc="Vue.use(Vuex);", c="app.use(store);"),
    r(id="js-vue-prototype", title="Vue.prototype", desc="Vue.prototype was replaced by globalProperties in Vue 3.",
      rationale="Adding to Vue.prototype no longer works in Vue 3.", remediation="Use app.config.globalProperties.",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api-treeshaking.html", re=r"\bVue\.prototype\.",
      nc="Vue.prototype.$http = axios;", c="app.config.globalProperties.$http = axios;"),
    r(id="js-react-context-types", title="React contextTypes", desc="Legacy contextTypes was removed.",
      rationale="The legacy context API (contextTypes) was removed.", remediation="Use React.createContext.",
      source="https://react.dev/reference/react/createContext", re=r"\.contextTypes\b",
      nc="Comp.contextTypes = { theme: PropTypes.string };", c="const ThemeContext = createContext();"),
    r(id="js-react-child-context-types", title="React childContextTypes", desc="Legacy childContextTypes was removed.",
      rationale="The legacy context provider API was removed.", remediation="Use a Context Provider.",
      source="https://react.dev/reference/react/createContext", re=r"\.childContextTypes\b",
      nc="Comp.childContextTypes = { theme: PropTypes.string };", c="<ThemeContext.Provider value={theme}>"),
    r(id="js-react-get-child-context", title="React getChildContext()", desc="Legacy getChildContext was removed.",
      rationale="getChildContext was part of the removed legacy context API.", remediation="Provide context via a Context Provider.",
      source="https://react.dev/reference/react/createContext", re=r"\bgetChildContext\s*\(",
      nc="getChildContext() { return { theme }; }", c="<ThemeContext.Provider value={theme}>"),
    r(id="js-react-mixins", title="React mixins", desc="React mixins are removed.",
      rationale="Mixins were removed with createClass; use hooks or HOCs.", remediation="Use hooks or higher-order components.",
      source="https://react.dev/reference/react/Component", re=r"\bmixins\s*:\s*\[",
      nc="mixins: [LoggerMixin],", c="// compose behavior with a custom hook"),
]
