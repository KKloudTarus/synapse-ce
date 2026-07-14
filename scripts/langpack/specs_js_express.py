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


# JS/TS quality pack: Express 3->4 and lodash 3->4 removed/deprecated APIs.
RULES = [
    r(id="js-express-app-del", type="bug", qual="rel", sev="medium", title="Express app.del()",
      desc="app.del was removed in Express 4.", rationale="app.del no longer exists; the method is app.delete.",
      remediation="Use app.delete(...).", source="https://expressjs.com/en/guide/migrating-4.html",
      re=r"\bapp\.del\s*\(", nc='app.del("/items/:id", remove);', c='app.delete("/items/:id", remove);'),
    r(id="js-express-res-send-status", title="res.send(status)", desc="res.send(number) as a status code is deprecated.",
      rationale="Passing a number to res.send is deprecated; use res.sendStatus (Express 4).",
      remediation="Use res.sendStatus(code).", source="https://expressjs.com/en/guide/migrating-4.html",
      re=r"\bres\.send\s*\(\s*\d+\s*\)", nc="res.send(404);", c="res.sendStatus(404);"),
    r(id="js-express-res-sendfile", title="res.sendfile()", desc="res.sendfile was renamed res.sendFile.",
      rationale="The lowercase res.sendfile is deprecated in Express 4.",
      remediation="Use res.sendFile(...).", source="https://expressjs.com/en/guide/migrating-4.html",
      re=r"\bres\.sendfile\s*\(", nc="res.sendfile(path);", c="res.sendFile(path);"),
    r(id="js-express-req-param", title="req.param()", desc="req.param() is deprecated.",
      rationale="req.param mixes route, query and body sources ambiguously; access the specific source (Express 4).",
      remediation="Use req.params / req.query / req.body directly.", source="https://expressjs.com/en/guide/migrating-4.html",
      re=r"\breq\.param\s*\(", nc='const id = req.param("id");', c="const id = req.params.id;"),
    r(id="js-express-bodyparser", type="bug", qual="rel", sev="medium", title="express.bodyParser()",
      desc="express.bodyParser was removed in Express 4.", rationale="The bundled bodyParser was removed; use the body-parser package or express.json/urlencoded.",
      remediation="Use express.json() / express.urlencoded().", source="https://expressjs.com/en/guide/migrating-4.html",
      re=r"\bexpress\.bodyParser\s*\(", nc="app.use(express.bodyParser());", c="app.use(express.json());"),
    r(id="js-express-configure", type="bug", qual="rel", sev="medium", title="app.configure()",
      desc="app.configure was removed in Express 4.", rationale="app.configure no longer exists; use plain environment checks.",
      remediation="Check process.env.NODE_ENV directly.", source="https://expressjs.com/en/guide/migrating-4.html",
      re=r"\bapp\.configure\s*\(", nc="app.configure(function () {});", c='if (process.env.NODE_ENV === "production") {}'),
    r(id="js-express-logger", type="bug", qual="rel", sev="medium", title="express.logger()",
      desc="express.logger was removed in Express 4.", rationale="The bundled logger was removed; use the morgan package.",
      remediation="Use morgan(...).", source="https://expressjs.com/en/guide/migrating-4.html",
      re=r"\bexpress\.logger\b", nc="app.use(express.logger());", c='app.use(morgan("combined"));'),
    r(id="js-lodash-removed-methods", type="bug", qual="rel", sev="medium", title="Removed lodash method",
      desc="pluck/first/contains/etc were removed or renamed in lodash 4.", rationale="These lodash 3 methods no longer exist in lodash 4.",
      remediation="Use the lodash 4 equivalent (map/head/includes/...).", source="https://github.com/lodash/lodash/wiki/Changelog",
      re=r"\b_\.(pluck|contains|findWhere|where|indexBy|invoke|all|any|collect|detect|foldl|foldr|include|select|unique)\b",
      nc='const names = _.pluck(users, "name");', c='const names = _.map(users, "name");'),
]
