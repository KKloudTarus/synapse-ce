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


# JS/TS quality pack: more React 18 and Vue 3 migration removals/renames.
RULES = [
    r(id="js-react-unmount-component", title="ReactDOM.unmountComponentAtNode", desc="Replaced by root.unmount() in React 18.",
      rationale="unmountComponentAtNode is deprecated with the legacy render API.", remediation="Use root.unmount().",
      source="https://react.dev/reference/react-dom/unmountComponentAtNode", re=r"\bReactDOM\.unmountComponentAtNode\s*\(",
      nc="ReactDOM.unmountComponentAtNode(container);", c="root.unmount();"),
    r(id="js-react-hydrate", title="ReactDOM.hydrate", desc="Replaced by hydrateRoot() in React 18.",
      rationale="ReactDOM.hydrate is deprecated in favor of hydrateRoot.", remediation="Use hydrateRoot(container, element).",
      source="https://react.dev/reference/react-dom/hydrate", re=r"\bReactDOM\.hydrate\s*\(",
      nc="ReactDOM.hydrate(<App />, container);", c="hydrateRoot(container, <App />);"),
    r(id="js-react-create-factory", type="bug", qual="rel", sev="medium", title="React.createFactory", desc="React.createFactory was removed.",
      rationale="React.createFactory was deprecated and removed in React 19.", remediation="Use JSX or React.createElement.",
      source="https://react.dev/reference/react/createFactory", re=r"\bReact\.createFactory\s*\(",
      nc='const button = React.createFactory("button");', c="const button = (props) => <button {...props} />;"),
    r(id="js-vue-extend", title="Vue.extend()", desc="Vue.extend was removed in Vue 3.",
      rationale="Vue 3 replaced Vue.extend with defineComponent.", remediation="Use defineComponent(...).",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\bVue\.extend\s*\(",
      nc="const Comp = Vue.extend({});", c="const Comp = defineComponent({});"),
    r(id="js-vue-filter", type="bug", qual="rel", sev="medium", title="Vue.filter()", desc="Filters were removed in Vue 3.",
      rationale="Vue 3 removed filters; use methods or computed properties.", remediation="Use a method or computed property.",
      source="https://v3-migration.vuejs.org/breaking-changes/filters.html", re=r"\bVue\.filter\s*\(",
      nc='Vue.filter("capitalize", fn);', c="// use a computed property or method"),
    r(id="js-vue-observable", title="Vue.observable()", desc="Vue.observable was replaced in Vue 3.",
      rationale="Vue 3 uses reactive() from the composition API.", remediation="Use reactive(...).",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\bVue\.observable\s*\(",
      nc="const state = Vue.observable({ count: 0 });", c="const state = reactive({ count: 0 });"),
    r(id="js-vue-new-instance", title="new Vue()", desc="The Vue 2 constructor was replaced by createApp.",
      rationale="Vue 3 bootstraps with createApp instead of new Vue.", remediation="Use createApp(App).mount(...).",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\bnew\s+Vue\s*\(",
      nc='new Vue({ el: "#app", render });', c='createApp(App).mount("#app");'),
    r(id="js-vue-mount-method", title="vm.$mount()", desc="The $mount instance method is a Vue 2 pattern.",
      rationale="Vue 3 mounts via app.mount(); $mount is legacy.", remediation="Use app.mount(selector).",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\.\$mount\s*\(",
      nc='vm.$mount("#app");', c='app.mount("#app");'),
]
