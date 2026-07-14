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


# Java quality pack: Guava/commons deprecations + deprecated java.util.Date accessors.
RULES = [
    r(id="java-guava-files-tostring", title="Guava Files.toString()", desc="Guava Files.toString is deprecated.",
      rationale="Guava's Files.toString is deprecated in favor of Files.asCharSource(...).read().", remediation="Use Files.asCharSource(file, charset).read().",
      source="https://guava.dev/releases/snapshot/api/docs/", re=r"\bFiles\.toString\s*\(", nc="String s = Files.toString(file, UTF_8);", c="String s = Files.asCharSource(file, UTF_8).read();"),
    r(id="java-ioutils-closequietly", title="IOUtils.closeQuietly()", desc="closeQuietly is deprecated.",
      rationale="Commons IO closeQuietly is deprecated; try-with-resources handles closing.", remediation="Use try-with-resources.",
      source="https://commons.apache.org/proper/commons-io/", re=r"\bIOUtils\.closeQuietly\s*\(", nc="IOUtils.closeQuietly(stream);", c="try (stream) { /* ... */ }"),
    r(id="java-fileutils-read-no-charset", title="FileUtils.readFileToString without charset", desc="The no-charset overload is deprecated.",
      rationale="FileUtils.readFileToString(File) uses the platform charset and is deprecated.", remediation="Pass an explicit charset.",
      source="https://commons.apache.org/proper/commons-io/", re=r"\bFileUtils\.readFileToString\s*\(\s*[^,)]+\s*\)", nc="String s = FileUtils.readFileToString(file);", c="String s = FileUtils.readFileToString(file, StandardCharsets.UTF_8);"),
    r(id="java-date-getday", title="Date.getDay()", desc="Date.getDay is deprecated.",
      rationale="java.util.Date.getDay is deprecated in favor of java.time.", remediation="Use LocalDate.getDayOfWeek().",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/Date.html", re=r"\.getDay\s*\(\s*\)", nc="int d = date.getDay();", c="int d = localDate.getDayOfWeek().getValue();"),
    r(id="java-date-gethours", title="Date.getHours()", desc="Date.getHours is deprecated.",
      rationale="java.util.Date.getHours is deprecated in favor of java.time.", remediation="Use LocalTime.getHour().",
      source="https://docs.oracle.com/javase/8/docs/api/java/util/Date.html", re=r"\.getHours\s*\(\s*\)", nc="int h = date.getHours();", c="int h = localTime.getHour();"),
]
