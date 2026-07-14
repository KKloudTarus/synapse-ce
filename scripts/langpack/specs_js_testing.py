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


# JS/TS quality pack: test-suite hygiene (jest/jasmine/mocha), RxJS, more unicorn idioms.
RULES = [
    r(id="js-test-focused", type="bug", qual="rel", sev="medium", title="Focused test left in the suite",
      desc="fit/fdescribe/.only run only a subset of tests.", rationale="A committed focused test makes CI silently skip the rest of the suite (eslint-plugin-jest no-focused-tests).",
      remediation="Remove the .only / fit / fdescribe focus.", source="https://github.com/jest-community/eslint-plugin-jest",
      re=r"\b(fit|fdescribe|it\.only|describe\.only|test\.only)\s*\(", nc='it.only("focused", () => {});', c='it("runs", () => {});'),
    r(id="js-test-disabled", title="Disabled test left in the suite", desc="xit/xdescribe/.skip permanently skip a test.",
      rationale="A committed skipped test is dead coverage that tends to rot (eslint-plugin-jest no-disabled-tests).",
      remediation="Re-enable the test or remove it.", source="https://github.com/jest-community/eslint-plugin-jest",
      re=r"\b(xit|xdescribe|it\.skip|describe\.skip|test\.skip)\s*\(", nc='xit("later", () => {});', c='it("now", () => {});'),
    r(id="js-jest-alias-methods", title="Deprecated jest alias matcher", desc="toBeCalled/toReturn are deprecated aliases.",
      rationale="These matcher aliases are deprecated in favor of the toHaveBeen* forms (eslint-plugin-jest no-alias-methods).",
      remediation="Use toHaveBeenCalled / toHaveReturned etc.", source="https://github.com/jest-community/eslint-plugin-jest",
      re=r"\.(toBeCalled|toBeCalledWith|toBeCalledTimes|lastCalledWith|toReturn|toReturnWith|nthReturnedWith)\b",
      nc="expect(fn).toBeCalled();", c="expect(fn).toHaveBeenCalled();"),
    r(id="js-jasmine-globals", title="Jasmine globals in a Jest suite", desc="jasmine.* globals are discouraged under Jest.",
      rationale="Jest provides its own equivalents; jasmine globals are legacy and partially removed (eslint-plugin-jest no-jasmine-globals).",
      remediation="Use the jest.* equivalents (jest.fn, jest.spyOn, ...).", source="https://github.com/jest-community/eslint-plugin-jest",
      re=r"\bjasmine\.", nc='const spy = jasmine.createSpy("cb");', c="const spy = jest.fn();"),
    r(id="js-rxjs-topromise", title="RxJS toPromise()", desc="Observable.toPromise() is deprecated.",
      rationale="toPromise is deprecated in RxJS 7 in favor of firstValueFrom/lastValueFrom.",
      remediation="Use firstValueFrom(obs) or lastValueFrom(obs).", source="https://rxjs.dev/deprecations/to-promise",
      re=r"\.toPromise\s*\(\s*\)", nc="const value = await source$.toPromise();", c="const value = await firstValueFrom(source$);"),
    r(id="js-error-no-message", title="Error thrown without a message", desc="new Error() with no message loses context.",
      rationale="An error with no message is hard to diagnose (unicorn error-message).",
      remediation="Pass a descriptive message to the error constructor.", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"new\s+(Error|TypeError|RangeError|SyntaxError)\s*\(\s*\)", nc="throw new Error();", c='throw new Error("connection closed");'),
    r(id="js-join-no-separator", title="join() without a separator", desc="Array.join() defaults to a comma.",
      rationale="Omitting the separator hides intent; state it explicitly (unicorn require-array-join-separator).",
      remediation="Pass the separator, e.g. join(\",\").", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.join\s*\(\s*\)", nc="const csv = fields.join();", c='const csv = fields.join(",");'),
]
