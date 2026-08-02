//go:build cgo

package astwalk

import (
	"context"
	"strings"
	"testing"
)

type swiftGoldenFixture struct {
	key, noncompliant, compliant string
}

func TestSwiftRuntimeGoldenFixtures(t *testing.T) {
	fixtures := []swiftGoldenFixture{
		{"force-unwrap", `func f(_ value: Int?) { let result = value! }`, `func f() {}`},
		{"force-try", `func f() { let value = try! decode() }`, `func f() {}`},
		{"force-cast", `func f(_ value: Any) { let name = value as! String }`, `func f() {}`},
		{"array-index-literal", `func f(_ items: [Int]) { let first = items[0] }`, `func f() {}`},
		{"dictionary-force-lookup", `func f(_ headers: [String: String]) { let token = headers["Authorization"]! }`, `func f() {}`},
		{"fatal-error", `func f() { fatalError("stop") }`, `func f() {}`},
		{"precondition-failure", `func f() { preconditionFailure("stop") }`, `func f() {}`},
		{"try-optional-discard", `func f() { try? save() }`, `func f() {}`},
		{"empty-switch-case", `func f(_ value: Int) { switch value { case 0: break; default: return } }`, `func f() {}`},
		{"constant-condition", `func f() { if true { run() } }`, `func f() {}`},
		{"duplicate-switch-case", `func f(_ value: Int) { switch value { case 0: run(); case 0: again(); default: return } }`, `func f() {}`},
		{"self-assignment", `func f() { var value = 1; value = value }`, `func f() {}`},
		{"comparison-self", `func f(_ value: Int) { if value == value { run() } }`, `func f() {}`},
		{"invalid-range", `func f() { for value in 3...0 { use(value) } }`, `func f() {}`},
		{"integer-division", `func f(_ done: Int, _ total: Int) { let ratio = Double(done / total) }`, `func f() {}`},
		{"nil-coalescing-self", `func f(_ value: String?) { let result = value ?? value }`, `func f() {}`},
		{"redundant-optional-bind", `func f(_ value: String?) { if let _ = value { run() } }`, `func f() {}`},
		{"unreachable-after-return", `func f() { return; run() }`, `func f() {}`},
		{"empty-catch", `func f() { do { try save() } catch { } }`, `func f() {}`},
		{"return-in-defer", `func f() { defer { return }; run() }`, `func f() {}`},
		{"assert-production", `func f(_ ready: Bool) { assert(ready) }`, `func f() {}`},
		{"implicitly-unwrapped-local", `func f() { var token: String! }`, `func f() {}`},
		{"optional-equality-nil", `func f(_ value: String?) { if value == Optional.none { run() } }`, `func f() {}`},
		{"guard-without-exit", `func f(_ ready: Bool) { guard ready else { run() }; run() }`, `func f() {}`},
		{"duplicate-dictionary-key", `func f() { let flags = ["debug": false, "debug": true] }`, `func f() {}`},
		{"broad-catch", `func f() { do { try save() } catch { recover() } }`, `func f() {}`},
		{"error-discarded", `func f() { _ = try? save() }`, `func f() {}`},
		{"empty-defer", `func f() { defer { } }`, `func f() {}`},
		{"throw-generic-error", `func f() throws { throw NSError(domain: "App", code: 1) }`, `func f() {}`},
		{"catch-print-only", `func f() { do { try save() } catch { print(error) } }`, `func f() {}`},
		{"error-message-lost", `func f() throws { do { try save() } catch { throw AppError.failed } }`, `func f() {}`},
		{"retain-cycle-self", `class Owner { var handler: (() -> Void)?; func f() { self.handler = { self.refresh() } }; func refresh() {} }`, `func f() {}`},
		{"implicitly-unwrapped-optional", `class Owner { var token: String! }`, `func f() {}`},
		{"notification-observer-unremoved", `class Owner { @objc func run() {}; func f() { NotificationCenter.default.addObserver(self, selector: #selector(run), name: nil, object: nil) } }`, `func f() {}`},
		{"timer-retain-cycle", `class Owner { func f() { Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in self.tick() } }; func tick() {} }`, `func f() {}`},
		{"file-handle-unclosed", `func f(_ url: URL) { let handle = try! FileHandle(forReadingFrom: url) }`, `func f() {}`},
		{"dispatch-source-unbalanced", `func f() { let source = DispatchSource.makeTimerSource() }`, `func f() {}`},
		{"autoreleasepool-missing", `func f(_ items: [String]) { for item in items { process(item as NSString) } }`, `func f() {}`},
		{"unsafe-pointer-escape", `func f(_ value: Int) -> UnsafePointer<Int> { return UnsafePointer(&value) }`, `func f() {}`},
		{"task-unstructured", `func f() { Task { await refresh() } }`, `func f() {}`},
		{"task-sleep-error-discarded", `func f() async { try? await Task.sleep(nanoseconds: 1) }`, `func f() {}`},
		{"main-queue-sync", `func f() { DispatchQueue.main.sync { updateUI() } }`, `func f() {}`},
		{"semaphore-wait-main", `func f(_ semaphore: DispatchSemaphore) { semaphore.wait() }`, `func f() {}`},
		{"continuation-resume-missing", `func f() async { await withCheckedContinuation { continuation in startWork() } }`, `func f() async { await withCheckedContinuation { continuation in continuation.resume(returning: 1) } }`},
		{"detached-task-self", `class Owner { func f() { Task.detached { self.refresh() } }; func refresh() {} }`, `func f() {}`},
		{"actor-blocking-call", `actor Owner { func f(_ lock: NSLock) { lock.lock() } }`, `func f() {}`},
		{"lock-with-await", `func f(_ lock: NSLock) async { lock.lock(); await refresh(); lock.unlock() }`, `func f() {}`},
		{"dispatch-group-wait", `func f(_ group: DispatchGroup) { group.wait() }`, `func f() {}`},
		{"operation-queue-main-block", `func f(_ queue: OperationQueue) { queue.waitUntilAllOperationsAreFinished() }`, `func f() {}`},
		{"sql-concat", `func f(_ id: String) { query("SELECT * FROM users WHERE id = \(id)") }`, `func f() {}`},
		{"command-shell", `func f(_ input: String) { let command = input; let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/sh"); process.arguments = ["-c", command] }`, `func f() {}`},
		{"path-concat", `func f(_ base: String, _ name: String) { var path = base; path = base + "/" + name }`, `func f() {}`},
		{"url-interpolation", `func f(_ path: String) { let url = URL(string: "https://api.example/\(path)") }`, `func f() {}`},
		{"predicate-format", `func f(_ name: String) { let predicate = NSPredicate(format: "name == \(name)") }`, `func f() {}`},
		{"html-string", `func f(_ name: String) { webView.loadHTMLString("<p>\(name)</p>", baseURL: nil) }`, `func f() {}`},
		{"unsafe-deserialization", `func f(_ data: Data) { NSKeyedUnarchiver.unarchiveObject(with: data) }`, `func f() {}`},
		{"regex-from-input", `func f(_ pattern: String) { let regex = try! NSRegularExpression(pattern: pattern) }`, `func f() {}`},
		{"weak-hash", `func f(_ data: Data) { let digest = Insecure.MD5.hash(data: data) }`, `func f() {}`},
		{"insecure-random", `func f() { let sessionToken = random() }`, `func f() { let sessionToken = arc4random() }`},
		{"ecb-mode", `func f() { cipher(options: .ecbMode) }`, `func f() {}`},
		{"hardcoded-key", `func f() { let apiKey = "0123456789abcdef" }`, `func f() {}`},
		{"static-iv", `func f() { let iv = Data(repeating: 0, count: 16) }`, `func f() {}`},
		{"tls-trust-all", `func receive(_ challenge: URLAuthenticationChallenge) { completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!)) }`, `func f() {}`},
		{"http-url", `func f() { let url = URL(string: "http://example.com") }`, `func f() {}`},
		{"webview-javascript", `func f(_ script: String) { webView.evaluateJavaScript(script) }`, `func f() {}`},
		{"pasteboard-sensitive", `func f(_ password: String) { pasteboard.string = password }`, `func f() {}`},
		{"keychain-accessible-always", `func f() { options[kSecAttrAccessible] = kSecAttrAccessibleAlways }`, `func f() {}`},
		{"biometric-fallback", `func f() { let context = LAContext(); context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock") }`, `func f() {}`},
		{"debug-server", `func f() { server.enabled = true }`, `func f() {}`},
		{"sensitive-log", `func f(_ token: String) { logger.info("token: \(token)") }`, `func f() {}`},
		{"print-logging", `func f() { print("started") }`, `func f() {}`},
		{"nsurl-legacy", `func f(_ value: String) { let url = NSURL(string: value) }`, `func f() {}`},
		{"nsdata-legacy", `func f() { let data = NSData() }`, `func f() {}`},
		{"nsstring-legacy", `func f(_ value: String) { let name = NSString(string: value) }`, `func f() {}`},
		{"dispatch-once", `func f() { dispatch_once(&token) { setup() } }`, `func f() {}`},
		{"uiapplication-openurl", `func f(_ url: URL) { UIApplication.shared.openURL(url) }`, `func f() {}`},
		{"string-size", `func f(_ text: String) { let count = (text as NSString).length }`, `func f() {}`},
		{"selector-string", `func f(_ name: String) { let selector = NSSelectorFromString(name) }`, `func f() {}`},
		{"perform-selector", `func f(_ target: NSObject, _ selector: Selector) { target.perform(selector) }`, `func f() {}`},
		{"kvc-string", `func f(_ model: NSObject, _ value: String, _ key: String) { model.setValue(value, forKey: key) }`, `func f() {}`},
		{"notification-string-name", `func f() { let name = Notification.Name("didRefresh") }`, `func f() {}`},
		{"userdefaults-sensitive", `func f(_ password: String) { UserDefaults.standard.set(password, forKey: "password") }`, `func f() {}`},
		{"bundle-path", `func f() { let path = Bundle.main.path(forResource: "Config", ofType: "json") }`, `func f() {}`},
		{"foundation-date-formatter", `func f() { let formatter = DateFormatter() }`, `func f() {}`},
		{"deprecated-availability", `@available(iOS, deprecated: 12) func f() {}`, `func f() {}`},
		{"any-without-protocol", `func f(_ value: Any) { use(value) }`, `func f() {}`},
		{"anyobject-cast", `func f(_ value: AnyObject) { let view = value as! UIView }`, `func f() {}`},
		{"implicitly-unwrapped-parameter", `func f(_ title: String!) {}`, `func f() {}`},
		{"raw-value-enum-string", `func f() { let method = HTTPMethod(rawValue: "POST")! }`, `func f() {}`},
		{"tuple-return-many", `func f() -> (Int, String, Bool, Date) { return (0, "", false, Date()) }`, `func f() {}`},
		{"optional-boolean", `class Owner { var isEnabled: Bool? }`, `func f() {}`},
		{"stringly-typed-key", `func f(_ value: String) { settings["theme"] = value }`, `func f() {}`},
		{"type-erasure-cast", `func f(_ value: Any) { let view = value as! View }`, `func f() {}`},
		{"objc-dynamic", `class Owner { @objc dynamic var value = 0 }`, `func f() {}`},
		{"inout-escaping", `func f(_ value: inout Int, done: @escaping () -> Void) { done = { use(value) } }`, `func f() {}`},
		{"protocol-composition-long", `func f(_ value: A & B & C & D) { use(value) }`, `func f() {}`},
		{"metatype-cast", `func f(_ value: Any) { let type = value as! Service.Type }`, `func f() {}`},
		{"optional-collection", `class Owner { var items: [Item]? }`, `func f() {}`},
		{"existential-any", `func f(_ value: any Renderable) { use(value) }`, `func f() {}`},
		{"opaque-result-erased", `func f() -> Any { return Text("Hi") }`, `func f() {}`},
		{"array-contains-loop", `func f(_ input: [Int]) { for item in input { let items = [1]; if items.contains(item) { run() } } }`, `func f() {}`},
		{"string-concat-loop", `func f(_ items: [String]) { var text = ""; for item in items { text += item } }`, `func f() {}`},
		{"map-filter-chain", `func f(_ items: [Int]) { let values = items.filter(valid).map(transform) }`, `func f() {}`},
		{"sort-first", `func f(_ items: [Int]) { let first = items.sorted().first }`, `func f() {}`},
		{"count-zero", `func f(_ items: [Int]) { if items.count == 0 { return } }`, `func f() {}`},
		{"repeated-dateformatter", `func f() { let formatter = DateFormatter() }`, `struct Cache { static let formatter = DateFormatter() }`},
		{"data-copy", `func f(_ data: Data) { consume(Data(data)) }`, `func f() {}`},
		{"main-thread-heavy-loop", `func f(_ items: [Int]) { DispatchQueue.main.async { for item in items { process(item) } } }`, `func f() {}`},
		{"long-function", swiftLongFunctionFixture(), swiftLongFunctionBoundaryFixture()},
		{"large-type", swiftLargeTypeFixture(), swiftLargeTypeBoundaryFixture()},
		{"deep-nesting", `func f(_ a: Bool, _ b: Bool, _ c: Bool, _ d: Bool, _ e: Bool) { if a { if b { if c { if d { if e { run() } } } } } }`, `func f(_ a: Bool, _ b: Bool, _ c: Bool, _ d: Bool) { if a { if b { if c { if d { run() } } } } }`},
		{"too-many-parameters", `func f(a: String, b: String, c: String, d: String, e: String, f: String, g: String, h: String) {}`, `func f() {}`},
		{"todo-comment", "func f() { // TODO: replace this\n }", `func f() {}`},
		{"commented-code", "func f() { // let legacy = oldValue\n }", `func f() {}`},
		{"magic-number", `func f(_ attempts: Int) { if attempts > 3 { stop() } }`, `func f() {}`},
		{"single-letter-name", `func f(_ userID: Int) { let x = userID }`, `func f() {}`},
		{"public-undocumented", `public func f() {}`, `func f() {}`},
		{"redundant-self", `class Owner { var value = 0; func f() { self.value = 1 } }`, `func f() {}`},
	}

	runtimeKeys := make(map[string]struct{}, len(swiftRuntimeRules))
	for key := range swiftRuntimeRules {
		runtimeKeys[key] = struct{}{}
	}
	fixtureKeys := make(map[string]struct{}, len(fixtures))
	for _, fixture := range fixtures {
		if _, duplicate := fixtureKeys[fixture.key]; duplicate {
			t.Fatalf("duplicate Swift golden fixture key %q", fixture.key)
		}
		fixtureKeys[fixture.key] = struct{}{}
	}
	if len(fixtures) != 118 || len(fixtureKeys) != len(runtimeKeys) {
		t.Fatalf("Swift golden fixtures = %d unique keys = %d, runtime keys = %d; want 118 each", len(fixtures), len(fixtureKeys), len(runtimeKeys))
	}
	for key := range runtimeKeys {
		if _, ok := fixtureKeys[key]; !ok {
			t.Errorf("missing Swift golden fixture for runtime rule %q", key)
		}
	}
	for key := range fixtureKeys {
		if _, ok := runtimeKeys[key]; !ok {
			t.Errorf("extra Swift golden fixture for non-runtime rule %q", key)
		}
	}

	for _, fixture := range fixtures {
		t.Run(fixture.key, func(t *testing.T) {
			want := "swift:" + fixture.key
			if !swiftHasRule(swiftCompleteFixtureFindings(t, fixture.noncompliant), want) {
				t.Fatalf("noncompliant fixture did not emit %s", want)
			}
			if swiftHasRule(swiftCompleteFixtureFindings(t, fixture.compliant), want) {
				t.Fatalf("compliant fixture emitted %s", want)
			}
		})
	}
}

func swiftCompleteFixtureFindings(t *testing.T, source string) []QualityFinding {
	t.Helper()
	root := parseRoot(context.Background(), specs["Swift"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatalf("Swift fixture is not syntactically complete: %q", source)
	}
	findings, _ := swiftFindings(root, []byte(source), "fixture.swift")
	return findings
}

func swiftHasRule(findings []QualityFinding, want string) bool {
	for _, finding := range findings {
		if finding.Rule == want {
			return true
		}
	}
	return false
}

func swiftLongFunctionFixture() string {
	return "func f() {\n" + strings.Repeat("work()\n", 51) + "}"
}

func swiftLongFunctionBoundaryFixture() string {
	return "func f() {\n" + strings.Repeat("work()\n", 50) + "}"
}

func swiftLargeTypeFixture() string {
	var source strings.Builder
	source.WriteString("struct Large {\n")
	for i := 0; i < 41; i++ {
		source.WriteString("var property")
		source.WriteString(string(rune('a' + i%26)))
		source.WriteString(" = 0\n")
	}
	source.WriteString("}")
	return source.String()
}

func swiftLargeTypeBoundaryFixture() string {
	var source strings.Builder
	source.WriteString("struct Large {\n")
	for i := 0; i < 40; i++ {
		source.WriteString("var property")
		source.WriteString(string(rune('a' + i%26)))
		source.WriteString(" = 0\n")
	}
	source.WriteString("}")
	return source.String()
}
