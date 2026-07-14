CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


G = "https://guava.dev/releases/snapshot/api/docs/"

# Java quality pack: Guava base-type/util superseded by java.util(.function), and EOL libraries.
RULES = [
    r(id="java-guava-optional", title="Guava Optional", desc="Guava's Optional is superseded by java.util.Optional.",
      rationale="Since Java 8, java.util.Optional is the standard.", remediation="Use java.util.Optional.",
      source=G, re=r"import\s+com\.google\.common\.base\.Optional\b", nc="import com.google.common.base.Optional;", c="import java.util.Optional;"),
    r(id="java-guava-function", title="Guava Function", desc="Guava's Function is superseded by java.util.function.Function.",
      rationale="Since Java 8, java.util.function.Function is the standard.", remediation="Use java.util.function.Function.",
      source=G, re=r"import\s+com\.google\.common\.base\.Function\b", nc="import com.google.common.base.Function;", c="import java.util.function.Function;"),
    r(id="java-guava-predicate", title="Guava Predicate", desc="Guava's Predicate is superseded by java.util.function.Predicate.",
      rationale="Since Java 8, java.util.function.Predicate is the standard.", remediation="Use java.util.function.Predicate.",
      source=G, re=r"import\s+com\.google\.common\.base\.Predicate\b", nc="import com.google.common.base.Predicate;", c="import java.util.function.Predicate;"),
    r(id="java-guava-supplier", title="Guava Supplier", desc="Guava's Supplier is superseded by java.util.function.Supplier.",
      rationale="Since Java 8, java.util.function.Supplier is the standard.", remediation="Use java.util.function.Supplier.",
      source=G, re=r"import\s+com\.google\.common\.base\.Supplier\b", nc="import com.google.common.base.Supplier;", c="import java.util.function.Supplier;"),
    r(id="java-guava-charsets", title="Guava Charsets", desc="Guava Charsets is superseded by StandardCharsets.",
      rationale="java.nio.charset.StandardCharsets is the standard constant holder.", remediation="Use StandardCharsets.",
      source=G, re=r"\bCharsets\.", nc="writer.write(text, Charsets.UTF_8);", c="writer.write(text, StandardCharsets.UTF_8);"),
    r(id="java-guava-throwables-propagate", title="Throwables.propagate()", desc="Guava Throwables.propagate is deprecated.",
      rationale="Throwables.propagate obscures the exception type and is deprecated.", remediation="Throw a specific exception directly.",
      source=G, re=r"Throwables\.propagate\s*\(", nc="throw Throwables.propagate(e);", c="throw new IllegalStateException(e);"),
    r(id="java-guava-tostringhelper", title="Objects.toStringHelper()", desc="Guava Objects.toStringHelper moved to MoreObjects.",
      rationale="Objects.toStringHelper is deprecated in favor of MoreObjects.toStringHelper.", remediation="Use MoreObjects.toStringHelper.",
      source=G, re=r"\bObjects\.toStringHelper\s*\(", nc="return Objects.toStringHelper(this).add(\"id\", id).toString();", c="return MoreObjects.toStringHelper(this).add(\"id\", id).toString();"),
    r(id="java-commons-escapehtml", title="StringEscapeUtils.escapeHtml (deprecated)", desc="escapeHtml is deprecated in commons-lang3.",
      rationale="Commons-lang3 deprecated escapeHtml in favor of escapeHtml4.", remediation="Use escapeHtml4 (or a context-aware encoder like OWASP Encoder).",
      source="https://commons.apache.org/proper/commons-lang/", re=r"StringEscapeUtils\.escapeHtml\b", nc="String safe = StringEscapeUtils.escapeHtml(input);", c="String safe = StringEscapeUtils.escapeHtml4(input);"),
    r(id="java-powermock-import", title="PowerMock import", desc="PowerMock is largely unmaintained.",
      rationale="PowerMock lags JDK/Mockito releases; prefer Mockito's modern features or refactoring for testability.", remediation="Use Mockito (mockStatic/mockConstruction) or refactor.",
      source="https://github.com/powermock/powermock", re=r"import\s+org\.powermock\.", nc="import org.powermock.api.mockito.PowerMockito;", c="import org.mockito.Mockito;"),
    r(id="java-commons-collections3", title="commons-collections 3", desc="commons-collections 3 is superseded by collections4.",
      rationale="commons-collections 3 is legacy (and was the source of the famous deserialization gadget).", remediation="Use org.apache.commons.collections4.",
      source="https://commons.apache.org/proper/commons-collections/", re=r"import\s+org\.apache\.commons\.collections\.", nc="import org.apache.commons.collections.CollectionUtils;", c="import org.apache.commons.collections4.CollectionUtils;"),
]
