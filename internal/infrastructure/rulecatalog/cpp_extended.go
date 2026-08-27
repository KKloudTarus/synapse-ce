package rulecatalog

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type cppRuleSpec struct {
	family                                               string
	key, name, cwe, compliant, noncompliant, remediation string
	type_                                                rule.Type
	quality                                              rule.Quality
	severity                                             shared.Severity
	detection                                            rule.Detection
}

func cppRule(key, name, cwe, compliant, noncompliant, remediation string, typ rule.Type, quality rule.Quality, severity shared.Severity) cppRuleSpec {
	return cppRuleSpec{key: key, name: name, cwe: cwe, compliant: compliant, noncompliant: noncompliant, remediation: remediation, type_: typ, quality: quality, severity: severity, detection: rule.DetectionAST}
}

func cppExtendedRules() []rule.Rule {
	memory := []cppRuleSpec{
		cppRule("raw-new-delete", "Raw new and delete used", "CWE-401", "auto ptr = std::make_unique<Widget>();", "Widget *ptr = new Widget();\ndelete ptr;", "Use std::make_unique or std::make_shared instead of raw new and delete.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cppRule("rule-of-three-violation", "Rule of Three violation", "CWE-401", "class Buffer {\npublic:\n    ~Buffer();\n    Buffer(const Buffer&);\n    Buffer& operator=(const Buffer&);\n};", "class Buffer {\npublic:\n    ~Buffer();\n};", "Define or delete copy constructor and copy assignment operator when defining a custom destructor.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("rule-of-five-violation", "Rule of Five violation", "CWE-398", "class Resource {\npublic:\n    Resource(const Resource&);\n    Resource& operator=(const Resource&);\n    Resource(Resource&&) noexcept;\n    Resource& operator=(Resource&&) noexcept;\n    ~Resource();\n};", "class Resource {\npublic:\n    Resource(const Resource&);\n    Resource& operator=(const Resource&);\n};", "Define move constructor and move assignment operator when defining copy operations.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("owning-raw-pointer-member", "Owning raw pointer member", "CWE-401", "class Service {\nprivate:\n    std::unique_ptr<Worker> worker_;\n};", "class Service {\nprivate:\n    Worker *worker_;\n};", "Use smart pointers (std::unique_ptr, std::shared_ptr) for class members managing heap ownership.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium),
		cppRule("auto-ptr-deprecated", "Use of deprecated std::auto_ptr", "CWE-676", "std::unique_ptr<Widget> p = std::make_unique<Widget>();", "std::auto_ptr<Widget> p(new Widget());", "Replace deprecated std::auto_ptr with std::unique_ptr.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium),
		cppRule("unique-ptr-custom-deleter-mismatch", "std::unique_ptr array with scalar delete", "CWE-762", "std::unique_ptr<int[]> arr(new int[10]);", "std::unique_ptr<int> arr(new int[10]);", "Use std::unique_ptr<T[]> for dynamically allocated arrays.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("shared-ptr-from-this-in-constructor", "shared_from_this in constructor", "CWE-476", "class Service : public std::enable_shared_from_this<Service> {\npublic:\n    static std::shared_ptr<Service> create() {\n        auto s = std::make_shared<Service>();\n        s->init();\n        return s;\n    }\n};", "class Service : public std::enable_shared_from_this<Service> {\npublic:\n    Service() { auto self = shared_from_this(); }\n};", "Call shared_from_this() in factory methods or after the object is managed by a shared_ptr.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("destructor-throwing-exception", "Destructor throws an exception", "CWE-248", "class Worker {\npublic:\n    ~Worker() noexcept {\n        try { cleanup(); } catch (...) {}\n    }\n};", "class Worker {\npublic:\n    ~Worker() {\n        throw std::runtime_error(\"error\");\n    }\n};", "Never throw exceptions from destructors; catch and handle them internally.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
	}

	oop := []cppRuleSpec{
		cppRule("missing-virtual-destructor", "Polymorphic base missing virtual destructor", "CWE-401", "class Base {\npublic:\n    virtual void run() = 0;\n    virtual ~Base() = default;\n};", "class Base {\npublic:\n    virtual void run() = 0;\n    ~Base() = default;\n};", "Declare virtual destructor in base classes containing virtual functions.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("object-slicing-pass-by-value", "Polymorphic object passed by value", "CWE-843", "void process(const Base &b);", "void process(Base b);", "Pass polymorphic class objects by reference or pointer to prevent object slicing.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cppRule("virtual-call-in-constructor", "Virtual call in constructor", "CWE-670", "class Base {\npublic:\n    Base() {}\n    void init() { setup(); }\n    virtual void setup();\n};", "class Base {\npublic:\n    Base() { setup(); }\n    virtual void setup();\n};", "Avoid invoking virtual member functions inside constructors or destructors.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cppRule("missing-override-specifier", "Missing override specifier", "CWE-398", "class Derived : public Base {\npublic:\n    void handle() override;\n};", "class Derived : public Base {\npublic:\n    void handle();\n};", "Add override specifier to overriding member functions in derived classes.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("hidden-virtual-function", "Derived method hides virtual base", "CWE-398", "class Derived : public Base {\npublic:\n    using Base::render;\n    void render(int x);\n};", "class Derived : public Base {\npublic:\n    void render(int x);\n};", "Add a `using Base::func;` declaration in derived class to avoid hiding base overloads.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	exceptions := []cppRuleSpec{
		cppRule("exception-in-destructor", "Exception escaping destructor", "CWE-248", "~Service() noexcept { try { close(); } catch (...) {} }", "~Service() { throw std::runtime_error(\"failed\"); }", "Catch and handle all exceptions within destructor bodies.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("catch-by-value", "Exception caught by value", "CWE-390", "try { run(); } catch (const std::exception &e) { log(e.what()); }", "try { run(); } catch (std::exception e) { log(e.what()); }", "Catch exception objects by const reference to avoid slicing and copying overhead.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("throw-raw-pointer", "Throwing raw heap pointer", "CWE-398", "throw std::runtime_error(\"error\");", "throw new std::runtime_error(\"error\");", "Throw exception objects by value instead of throwing raw heap pointers.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cppRule("noexcept-function-throws", "noexcept function throws exception", "CWE-248", "void clean() noexcept { try { risky(); } catch (...) {} }", "void clean() noexcept { throw std::runtime_error(\"error\"); }", "Do not throw exceptions from functions declared noexcept.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("empty-catch-clause", "Empty catch block", "CWE-390", "try { parse(); } catch (const std::exception &e) { log_warning(e); }", "try { parse(); } catch (...) {}", "Log or handle caught exceptions instead of silently swallowing them.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("rethrow-sliced-exception", "Rethrowing sliced exception by name", "CWE-390", "try { run(); } catch (const std::exception &e) { log(e); throw; }", "try { run(); } catch (const std::exception &e) { log(e); throw e; }", "Use throw; without arguments to rethrow the original active exception.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	stl := []cppRuleSpec{
		cppRule("iterator-invalidation-loop", "Container modified during iteration", "CWE-416", "for (auto it = v.begin(); it != v.end(); ) { if (cond(*it)) it = v.erase(it); else ++it; }", "for (auto it = v.begin(); it != v.end(); ++it) { if (cond(*it)) v.erase(it); }", "Use the return iterator from erase() or std::erase_if to avoid invalidation.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("dangling-string-view-temporary", "string_view bound to temporary", "CWE-825", "std::string s = get_text();\nstd::string_view sv = s;", "std::string_view sv = get_text();", "Ensure temporary std::string objects outlive the std::string_view referencing them.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("std-move-on-const-object", "std::move called on const object", "CWE-398", "std::string name = get_name();\nstd::string dest = std::move(name);", "const std::string name = get_name();\nstd::string dest = std::move(name);", "Do not call std::move on const objects because move constructors require non-const references.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("container-access-empty", "front/back on potentially empty container", "CWE-125", "if (!v.empty()) { int first = v.front(); }", "int first = v.front();", "Check container .empty() before calling .front() or .back().", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("iterator-past-the-end-deref", "Dereferencing past-the-end iterator", "CWE-125", "auto it = v.find(key);\nif (it != v.end()) { use(*it); }", "auto it = v.find(key);\nuse(*it);", "Check that find() results do not equal end() before dereferencing iterators.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("map-operator-bracket-unwanted-insert", "operator[] lookup on std::map", "CWE-400", "auto it = map.find(key);\nif (it != map.end()) { int val = it->second; }", "int val = map[key];", "Use find() or at() for lookups when element insertion is not desired.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("algorithm-pass-by-value-functor", "Stateful functor passed by value", "CWE-398", "std::for_each(v.begin(), v.end(), std::ref(acc));", "std::for_each(v.begin(), v.end(), acc);", "Wrap stateful functors in std::ref when passing to STL algorithms.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cppRule("unnecessary-temporary-vector", "Temporary vector allocated", "CWE-400", "void process(std::span<const int> data);", "void process(const std::vector<int> &data);", "Use std::span to accept contiguous collections without constructing temporary vectors.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("dangling-reference-span", "std::span references temporary", "CWE-825", "auto data = get_data();\nstd::span<const int> sp(data);", "std::span<const int> sp(get_data());", "Ensure the underlying container outlives the std::span referencing it.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("find-on-associative-container", "std::find on associative container", "CWE-400", "auto it = set.find(val);", "auto it = std::find(set.begin(), set.end(), val);", "Use member find() for O(log N) lookups instead of std::find O(N).", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
	}

	concurrency := []cppRuleSpec{
		cppRule("manual-mutex-lock-unlock", "Manual mutex lock/unlock", "CWE-667", "std::lock_guard<std::mutex> lock(mtx);\nprocess();", "mtx.lock();\nprocess();\nmtx.unlock();", "Use std::lock_guard or std::unique_lock for RAII mutex management.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("condition-variable-spurious-wakeup", "condition_variable wait without predicate", "CWE-835", "cv.wait(lock, [&]() { return ready; });", "cv.wait(lock);", "Pass a predicate lambda to condition_variable::wait to guard against spurious wakeups.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cppRule("lock-inversion-deadlock", "Multiple locks without scoped_lock", "CWE-833", "std::scoped_lock lock(mtx_a, mtx_b);", "std::unique_lock<std::mutex> l1(mtx_a);\n    std::unique_lock<std::mutex> l2(mtx_b);", "Use std::scoped_lock to acquire multiple mutexes atomically and deadlock-free.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("shared-variable-no-synchronization", "Shared variable without synchronization", "CWE-362", "std::atomic<int> counter = 0;\ncounter++;", "int counter = 0;\n    // in thread:\n    counter++;", "Use std::atomic or mutex locking for variables accessed concurrently across threads.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("thread-joinable-destructor", "std::thread destroyed while joinable", "CWE-404", "std::jthread t([]() { work(); });", "std::thread t([]() { work(); });\n    // exits scope without join", "Use std::jthread or call join()/detach() before std::thread destruction.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("async-future-discarded", "std::async return value discarded", "CWE-400", "auto fut = std::async(std::launch::async, task);", "std::async(std::launch::async, task);", "Store the returned std::future or the task will block synchronously in the destructor.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cppRule("double-checked-locking-pattern", "Double-checked locking without call_once", "CWE-362", "std::call_once(flag, [&]() { instance = new Singleton(); });", "if (!instance) {\n        std::lock_guard<std::mutex> lock(mtx);\n        if (!instance) instance = new Singleton();\n    }", "Use std::call_once or C++11 magic statics for thread-safe lazy initialization.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	casts := []cppRuleSpec{
		cppRule("c-style-cast-in-cpp", "C-style cast in C++ code", "CWE-704", "Derived *d = static_cast<Derived *>(b);", "Derived *d = (Derived *)b;", "Use C++ explicit casts (static_cast, dynamic_cast, reinterpret_cast).", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("reinterpret-cast-pointer-to-int", "reinterpret_cast pointer to narrow int", "CWE-704", "uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);", "uint32_t addr = reinterpret_cast<uint32_t>(ptr);", "Cast pointers to uintptr_t to preserve full address widths.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("const-cast-removing-constness", "const_cast modifying const object", "CWE-704", "Widget &w_ref = get_mutable_widget();\nw_ref.set_id(1);", "const_cast<Widget&>(w).set_id(1);", "Do not use const_cast to mutate objects originally declared const.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("reinterpret-cast-unrelated-classes", "reinterpret_cast between unrelated classes", "CWE-843", "Derived *d = dynamic_cast<Derived*>(b);", "Derived *d = reinterpret_cast<Derived*>(b);", "Use static_cast or dynamic_cast for class hierarchy casts.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("type-punning-union-misuse", "Union used for type punning", "CWE-843", "float f = std::bit_cast<float>(i);", "union { int i; float f; } u;\nu.i = 1;\nfloat f = u.f;", "Use std::bit_cast or memcpy for type punning in C++.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	modern := []cppRuleSpec{
		cppRule("null-macro-instead-of-nullptr", "NULL instead of nullptr", "CWE-476", "int *ptr = nullptr;", "int *ptr = NULL;", "Use nullptr for null pointer constants in C++.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("typedef-instead-of-using", "typedef instead of using", "CWE-398", "using Callback = std::function<void()>;", "typedef void (*Callback)();", "Use `using` alias declarations instead of `typedef`.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("raw-loop-instead-of-range-for", "Index loop instead of range-for", "CWE-398", "for (const auto &item : items) { process(item); }", "for (size_t i = 0; i < items.size(); i++) { process(items[i]); }", "Use range-based for loops over indexed iterations when index is not needed.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("missing-constexpr-specifier", "Compile-time constant missing constexpr", "CWE-398", "constexpr int BufferSize = 1024;", "const int BufferSize = 1024;", "Declare compile-time constants with constexpr.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("auto-ptr-usage", "std::auto_ptr used", "CWE-676", "std::unique_ptr<Widget> w = std::make_unique<Widget>();", "std::auto_ptr<Widget> w(new Widget());", "Replace removed std::auto_ptr with std::unique_ptr.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("bind-instead-of-lambda", "std::bind instead of lambda", "CWE-398", "auto fn = [x](int y) { return compute(x, y); };", "auto fn = std::bind(compute, x, std::placeholders::_1);", "Use C++ lambda expressions instead of std::bind.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("explicit-constructor-missing", "Single-argument constructor not explicit", "CWE-398", "class Buffer {\npublic:\n    explicit Buffer(size_t size);\n};", "class Buffer {\npublic:\n    Buffer(size_t size);\n};", "Mark single-argument constructors explicit to prevent unintended implicit conversions.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("default-delete-special-members", "Empty constructor instead of = default", "CWE-398", "class Widget {\npublic:\n    Widget() = default;\n};", "class Widget {\npublic:\n    Widget() {}\n};", "Use = default to allow compiler optimizations on trivial constructors.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("enum-unscoped-in-header", "Unscoped enum in header", "CWE-398", "enum class Color { Red, Green, Blue };", "enum Color { Red, Green, Blue };", "Use `enum class` to scope enumerator names.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("unbounded-template-recursion", "Template recursion without base case", "CWE-835", "template<int N> struct Factorial { static constexpr int value = N * Factorial<N-1>::value; };\ntemplate<> struct Factorial<0> { static constexpr int value = 1; };", "template<int N> struct Factorial { static constexpr int value = N * Factorial<N-1>::value; };", "Define specialization base cases to terminate template metaprogramming recursion.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cppRule("missing-typename-dependent-type", "Dependent type missing typename", "CWE-398", "template<typename T> void f() { typename T::iterator it; }", "template<typename T> void f() { T::iterator it; }", "Prefix dependent nested type names with the typename keyword.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cppRule("export-template-obsolete", "Obsolete export template keyword", "CWE-676", "template<typename T> class Stack {};", "export template<typename T> class Stack {};", "Remove obsolete `export` keyword from template declarations.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo),
	}

	security := []cppRuleSpec{
		cppRule("sql-query-concatenation", "SQL query string concatenation", "CWE-89", "pstmt->setString(1, user_input);", "std::string query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\";", "Use parameterized prepared statements for SQL queries.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cppRule("system-command-execution", "system() command execution", "CWE-78", "execvp(args[0], args);", "system((\"ls \" + user_arg).c_str());", "Execute programs directly with execvp without passing through shell interpreters.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cppRule("path-traversal-filesystem", "Path constructed without canonical check", "CWE-22", "auto path = std::filesystem::weakly_canonical(base / user_input);", "auto path = base / user_input;\n    open_file(path);", "Canonicalize and verify paths stay within expected base directory boundaries.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh),
		cppRule("xml-external-entity-parser", "XML parser external entity enabled", "CWE-611", "parser->setFeature(XMLUni::fgXercesDisableDefaultEntityResolution, true);", "XercesDOMParser parser;\nparser.parse(user_xml);", "Disable external entity resolution in XML parsers to prevent XXE attacks.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cppRule("untrusted-deserialization-boost", "boost::serialization untrusted stream", "CWE-502", "json j = json::parse(user_stream);", "boost::archive::text_iarchive ia(user_stream);\nia >> obj;", "Use structured schema-validated formats (JSON, Protobuf) for untrusted data.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cppRule("format-string-user-input", "std::format with dynamic format string", "CWE-134", "std::format(\"{}\", user_str);", "std::vformat(user_str, std::make_format_args());", "Pass string literals as format strings to std::format.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cppRule("ldap-query-concatenation", "LDAP filter string concatenation", "CWE-90", "std::string filter = \"(uid=\" + escape_ldap(username) + \")\";", "std::string filter = \"(uid=\" + username + \")\";", "Escape special filter characters in LDAP queries.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cppRule("regex-dos-dynamic-pattern", "std::regex with dynamic pattern", "CWE-1333", "static const std::regex pattern(\"^[a-z]+$\");", "std::regex re(user_pattern);", "Use static pre-compiled regular expressions.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium),
	}

	families := map[string][]cppRuleSpec{
		"memory": memory, "oop": oop, "exceptions": exceptions, "stl": stl,
		"concurrency": concurrency, "casts": casts, "modern": modern, "security": security,
	}
	var allSpecs []cppRuleSpec
	for _, family := range []string{"memory", "oop", "exceptions", "stl", "concurrency", "casts", "modern", "security"} {
		for i := range families[family] {
			families[family][i].family = family
		}
		allSpecs = append(allSpecs, families[family]...)
	}

	rules := make([]rule.Rule, 0, len(allSpecs))
	for _, s := range allSpecs {
		cweSlice := []string{}
		if s.cwe != "" {
			cweSlice = []string{s.cwe}
		}
		owaspSlice := []string{}
		if s.family == "security" {
			owaspSlice = []string{"A03:2021"}
		}
		rules = append(rules, rule.Rule{
			Key: rule.Key("cpp:" + s.key), Name: s.name, Language: "C++", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"cpp", "cpp-" + s.family}, CWE: cweSlice, OWASP: owaspSlice,
			Description: cppDescription(s), Rationale: cppRationale(s),
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: cppEffort(s), Detection: s.detection,
		})
	}
	return rules
}

func cppDescription(s cppRuleSpec) string {
	shape := map[string]string{
		"raw-new-delete": "using raw new and delete instead of smart pointers",
		"rule-of-three-violation": "defining a destructor without defining copy constructor and assignment",
		"rule-of-five-violation": "defining copy operations without move operations",
		"owning-raw-pointer-member": "a class member declared as an owning raw pointer",
		"auto-ptr-deprecated": "using deprecated std::auto_ptr",
		"unique-ptr-custom-deleter-mismatch": "a scalar std::unique_ptr managing array allocations",
		"shared-ptr-from-this-in-constructor": "invoking shared_from_this() in a constructor",
		"destructor-throwing-exception": "throwing an exception from a destructor body",

		"missing-virtual-destructor": "a polymorphic base class with non-virtual destructor",
		"object-slicing-pass-by-value": "passing a polymorphic object by value",
		"virtual-call-in-constructor": "invoking virtual methods inside constructor bodies",
		"missing-override-specifier": "an overriding member function missing override specifier",
		"hidden-virtual-function": "a derived class method hiding virtual base method overloads",

		"exception-in-destructor": "an exception escaping a destructor body",
		"catch-by-value": "catching exception objects by value instead of reference",
		"throw-raw-pointer": "throwing raw heap pointers instead of exception objects",
		"noexcept-function-throws": "a function declared noexcept that throws exceptions",
		"empty-catch-clause": "an empty catch clause silently swallowing exceptions",
		"rethrow-sliced-exception": "rethrowing exceptions by name instead of throw;",

		"iterator-invalidation-loop": "modifying a container during iteration without iterator updating",
		"dangling-string-view-temporary": "binding std::string_view to a temporary std::string",
		"std-move-on-const-object": "calling std::move on a const object",
		"container-access-empty": "calling .front() or .back() on potentially empty containers",
		"iterator-past-the-end-deref": "dereferencing end() iterators from container lookups",
		"map-operator-bracket-unwanted-insert": "using operator[] on std::map for lookups",
		"algorithm-pass-by-value-functor": "passing stateful functors by value to algorithms",
		"unnecessary-temporary-vector": "allocating temporary vectors instead of using std::span",
		"dangling-reference-span": "constructing std::span referencing a temporary container",
		"find-on-associative-container": "using std::find instead of member find() on associative containers",

		"manual-mutex-lock-unlock": "calling manual lock() and unlock() on mutexes",
		"condition-variable-spurious-wakeup": "condition_variable wait without predicate loop",
		"lock-inversion-deadlock": "acquiring multiple mutexes without std::scoped_lock",
		"shared-variable-no-synchronization": "accessing shared variables across threads without synchronization",
		"thread-joinable-destructor": "destroying std::thread objects while joinable",
		"async-future-discarded": "discarding the return future of std::async",
		"double-checked-locking-pattern": "double-checked locking without std::call_once",

		"c-style-cast-in-cpp": "using C-style casts in C++ code",
		"reinterpret-cast-pointer-to-int": "reinterpret_cast from pointer to narrower integer",
		"const-cast-removing-constness": "const_cast used to mutate const objects",
		"reinterpret-cast-unrelated-classes": "reinterpret_cast between unrelated class types",
		"type-punning-union-misuse": "using unions for type punning in C++",

		"null-macro-instead-of-nullptr": "using NULL instead of nullptr in C++",
		"typedef-instead-of-using": "using typedef instead of using alias declarations",
		"raw-loop-instead-of-range-for": "using indexed loops instead of range-based for loops",
		"missing-constexpr-specifier": "declaring compile-time constants without constexpr",
		"auto-ptr-usage": "using removed std::auto_ptr",
		"bind-instead-of-lambda": "using std::bind instead of C++ lambda expressions",
		"explicit-constructor-missing": "single-argument constructor not marked explicit",
		"default-delete-special-members": "empty constructor body instead of = default",
		"enum-unscoped-in-header": "unscoped enum declaration in header files",
		"unbounded-template-recursion": "template recursion lacking termination base cases",
		"missing-typename-dependent-type": "dependent nested type names missing typename",
		"export-template-obsolete": "using obsolete export template keyword",

		"sql-query-concatenation": "constructing SQL queries via string concatenation",
		"system-command-execution": "calling system() with dynamic strings",
		"path-traversal-filesystem": "std::filesystem::path constructed from untrusted input without canonical check",
		"xml-external-entity-parser": "XML parser without disabling external entities",
		"untrusted-deserialization-boost": "boost::serialization deserializing untrusted input",
		"format-string-user-input": "passing dynamic strings to std::format",
		"ldap-query-concatenation": "constructing LDAP queries with string concatenation",
		"regex-dos-dynamic-pattern": "dynamic std::regex compilation from user input",
	}[s.key]
	return fmt.Sprintf("Reports %s. It inspects only that local syntax or structure and does not prove the surrounding runtime path, ownership, or input trust.", shape)
}

func cppRationale(s cppRuleSpec) string {
	reason := map[string]string{
		"raw-new-delete": "Raw new and delete require manual lifetime tracking and frequently cause memory leaks or double-frees.",
		"rule-of-three-violation": "Custom destructors indicate resource management; missing copy operations cause double-free on copy.",
		"rule-of-five-violation": "Providing copy operations without move operations disables efficient move semantics.",
		"owning-raw-pointer-member": "Raw pointer members without smart pointer ownership leak memory upon destruction.",
		"auto-ptr-deprecated": "std::auto_ptr has broken copy semantics that silently transfer ownership.",
		"unique-ptr-custom-deleter-mismatch": "Scalar delete on array allocations causes undefined heap corruption.",
		"shared-ptr-from-this-in-constructor": "Calling shared_from_this in constructor throws std::bad_weak_ptr because control block is not ready.",
		"destructor-throwing-exception": "Exceptions escaping destructors during stack unwinding cause immediate std::terminate calls.",

		"missing-virtual-destructor": "Deleting a derived object through a base pointer with non-virtual destructor causes undefined behavior and resource leaks.",
		"object-slicing-pass-by-value": "Passing polymorphic types by value truncates derived member state and virtual table pointers.",
		"virtual-call-in-constructor": "Virtual functions called in constructors do not dispatch to derived implementations.",
		"missing-override-specifier": "Missing override allows accidental signature divergence during refactoring without compiler errors.",
		"hidden-virtual-function": "Derived member functions with same name but different parameters hide all base overloads.",

		"exception-in-destructor": "Escaping exceptions in destructors trigger std::terminate when active during stack unwinding.",
		"catch-by-value": "Catching exceptions by value slices derived exception objects and loses error details.",
		"throw-raw-pointer": "Catching raw pointer exceptions requires manual memory management and leaks memory.",
		"noexcept-function-throws": "Throwing from noexcept functions bypasses catch blocks and immediately aborts the application.",
		"empty-catch-clause": "Silently swallowing exceptions masks critical faults and leaves system in inconsistent state.",
		"rethrow-sliced-exception": "throw e re-throws by value, slicing derived exception details.",

		"iterator-invalidation-loop": "Container modifications invalidate existing iterators, leading to use-after-free crashes.",
		"dangling-string-view-temporary": "std::string_view does not own storage; referencing expired temporary strings causes use-after-free.",
		"std-move-on-const-object": "Moving a const object silently falls back to copy construction, wasting performance.",
		"container-access-empty": "Calling front() or back() on empty containers causes undefined memory access.",
		"iterator-past-the-end-deref": "Dereferencing past-the-end iterators reads invalid heap/stack memory.",
		"map-operator-bracket-unwanted-insert": "operator[] inserts default elements for missing keys, mutating map state and wasting memory.",
		"algorithm-pass-by-value-functor": "Modifications to functors passed by value are discarded upon algorithm return.",
		"unnecessary-temporary-vector": "Allocating vectors purely for parameter passing causes unwanted heap churn.",
		"dangling-reference-span": "std::span referencing a temporary container holds dangling pointers when temporary expires.",
		"find-on-associative-container": "std::find performs linear search O(N), defeating the associative container's tree/hash index.",

		"manual-mutex-lock-unlock": "Manual lock/unlock leaks mutex locks if exceptions occur between lock and unlock.",
		"condition-variable-spurious-wakeup": "Spurious wakeups allow threads to proceed without satisfying synchronization preconditions.",
		"lock-inversion-deadlock": "Acquiring mutexes in different orders across threads creates circular wait deadlocks.",
		"shared-variable-no-synchronization": "Concurrent read/write without atomics or locks creates data races and undefined behavior.",
		"thread-joinable-destructor": "std::thread destructor calls std::terminate if thread is still joinable upon destruction.",
		"async-future-discarded": "Discarding std::async future blocks synchronously in temporary future destructor.",
		"double-checked-locking-pattern": "Double-checked locking without acquire/release memory barriers reads partially initialized objects.",

		"c-style-cast-in-cpp": "C-style casts perform unchecked casts that bypass type safety and hide reinterpret_casts.",
		"reinterpret-cast-pointer-to-int": "Truncating 64-bit pointers to 32-bit integers breaks on 64-bit architectures.",
		"const-cast-removing-constness": "Modifying an object originally created const produces undefined behavior.",
		"reinterpret-cast-unrelated-classes": "Casting between unrelated polymorphic types corrupts vtable pointers.",
		"type-punning-union-misuse": "Reading inactive union members violates strict aliasing rules in C++.",

		"null-macro-instead-of-nullptr": "NULL expands to 0 or 0L, causing ambiguous overload resolution with integer functions.",
		"typedef-instead-of-using": "`using` syntax is cleaner and supports template aliases directly.",
		"raw-loop-instead-of-range-for": "Manual indexing invites off-by-one errors and increases loop boilerplate.",
		"missing-constexpr-specifier": "constexpr enables compile-time evaluation and placement in read-only memory segments.",
		"auto-ptr-usage": "std::auto_ptr was deprecated in C++11 and removed in C++17.",
		"bind-instead-of-lambda": "Lambdas are faster, easier to optimize for compilers, and clearer to read than std::bind.",
		"explicit-constructor-missing": "Implicit conversions from single-argument constructors cause subtle type conversion bugs.",
		"default-delete-special-members": "Explicit empty constructors inhibit trivial type properties and compiler optimizations.",
		"enum-unscoped-in-header": "Unscoped enum constants pollute the enclosing namespace and invite name collisions.",
		"unbounded-template-recursion": "Infinite template recursion exceeds compiler instantiation depth limits.",
		"missing-typename-dependent-type": "Compilers assume dependent names are values unless prefixed with typename.",
		"export-template-obsolete": "`export template` is obsolete and unsupported in modern C++.",

		"sql-query-concatenation": "Concatenating strings into SQL queries enables SQL injection vulnerabilities.",
		"system-command-execution": "system() passes commands to a shell interpreter, allowing command injection attacks.",
		"path-traversal-filesystem": "Unsanitized path joins permit directory traversal attacks outside root boundaries.",
		"xml-external-entity-parser": "XML external entity processing allows reading local server files and SSRF.",
		"untrusted-deserialization-boost": "Deserializing untrusted data with boost archive allows remote code execution.",
		"format-string-user-input": "Dynamic format strings allow format specifier injection vulnerabilities.",
		"ldap-query-concatenation": "Unescaped LDAP queries allow authentication bypass and directory data theft.",
		"regex-dos-dynamic-pattern": "Untrusted regex patterns can trigger catastrophic backtracking and ReDoS.",
	}[s.key]

	source := "https://en.cppreference.com/w/cpp"
	if s.cwe != "" {
		source = "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(s.cwe, "CWE-") + ".html"
	}
	switch s.family {
	case "memory":
		source = "https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#r-resource-management"
	case "stl":
		source = "https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#sl-the-standard-library"
	case "concurrency":
		source = "https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#cp-concurrency"
	}
	return fmt.Sprintf("%s\n\nSource: %s", reason, source)
}

func cppEffort(s cppRuleSpec) int {
	switch s.family {
	case "memory", "security", "concurrency":
		return 30
	case "modern":
		return 5
	default:
		return 15
	}
}
