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


# JS/TS quality pack: Vue 2 -> 3 removed/renamed APIs.
RULES = [
    r(id="js-vue-destroyed-lifecycle", title="Vue 2 destroyed lifecycle", desc="beforeDestroy/destroyed were renamed in Vue 3.",
      rationale="Vue 3 renamed these hooks to beforeUnmount/unmounted.", remediation="Use beforeUnmount / unmounted.",
      source="https://v3-migration.vuejs.org/breaking-changes/", re=r"\b(beforeDestroy|destroyed)\s*[(:]",
      nc="beforeDestroy() {", c="beforeUnmount() {"),
    r(id="js-vue-v-on-native", title="Vue 2 .native modifier", desc="The .native event modifier was removed in Vue 3.",
      rationale="Vue 3 removed v-on's .native modifier; use emits/attrs.", remediation="Declare the event in emits, or use $attrs.",
      source="https://v3-migration.vuejs.org/breaking-changes/v-on-native-modifier-removed.html", re=r"\.native\b",
      nc='<Child @click.native="onClick" />', c='<Child @click="onClick" />'),
    r(id="js-vue-v-bind-sync", title="Vue 2 .sync modifier", desc="The .sync modifier was removed in Vue 3.",
      rationale="Vue 3 replaced .sync with v-model arguments.", remediation="Use v-model:prop.",
      source="https://v3-migration.vuejs.org/breaking-changes/v-model.html", re=r"\.sync\b",
      nc='<Child :title.sync="title" />', c='<Child v-model:title="title" />'),
    r(id="js-vue-inline-template", title="Vue 2 inline-template", desc="inline-template was removed in Vue 3.",
      rationale="Vue 3 removed the inline-template attribute.", remediation="Use a normal template or a render function.",
      source="https://v3-migration.vuejs.org/breaking-changes/inline-template-attribute.html", re=r"\binline-template\b",
      nc="<my-comp inline-template>", c="<my-comp>"),
    r(id="js-vue-config-keycodes", type="bug", qual="rel", sev="medium", title="Vue.config.keyCodes", desc="Vue.config.keyCodes was removed in Vue 3.",
      rationale="Custom key-code aliases were removed in Vue 3.", remediation="Use kebab-case key names in v-on (e.g. @keyup.enter).",
      source="https://v3-migration.vuejs.org/breaking-changes/keycode-modifiers.html", re=r"Vue\.config\.keyCodes\b",
      nc="Vue.config.keyCodes.enter = 13;", c='<input @keyup.enter="submit" />'),
    r(id="js-vue-config-productiontip", title="Vue.config.productionTip", desc="productionTip was removed in Vue 3.",
      rationale="Vue.config.productionTip no longer exists in Vue 3.", remediation="Remove the productionTip setting.",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"Vue\.config\.productionTip\b",
      nc="Vue.config.productionTip = false;", c="const app = createApp(App);"),
    r(id="js-vue-set-delete", type="bug", qual="rel", sev="medium", title="Vue.set / Vue.delete", desc="Vue.set and Vue.delete were removed in Vue 3.",
      rationale="Vue 3 reactivity is automatic, so Vue.set/Vue.delete were removed.", remediation="Assign/delete the property directly.",
      source="https://v3-migration.vuejs.org/breaking-changes/global-api.html", re=r"\bVue\.(set|delete)\s*\(",
      nc='Vue.set(obj, "key", value);', c="obj.key = value;"),
]
