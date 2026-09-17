#!/usr/bin/env python3
"""Fold cppcheck findings into the flat cqbench baseline export.

SonarQube Community Edition does not analyze C/C++, so the code-quality head-to-head uses cppcheck as the
competitor baseline for those languages. cppcheck emits XML (version 2); this reduces it to the same flat
{component, line, type} shape the Go reducer (cqbench.SonarQubeObservations) consumes and appends it to the
existing export, so the benchmark scores the owned engine against the best available free tool per language.

Usage: cppcheck_to_export.py <project-key> <cppcheck.xml> <export.json>

The export file is read, cppcheck's findings are appended to its "issues" array, and it is written back.
cppcheck severities map to the tool-neutral types the reducer scores: error/warning are correctness bugs;
style/performance/portability are code smells; information is dropped. Only the primary <location> of each
<error> is used (cppcheck attaches extra informational locations to one finding), and findings without a
line are skipped, matching the SonarQube reducer's `line != null` filter.
"""
import json
import sys
import xml.etree.ElementTree as ET

_SEVERITY_TO_TYPE = {
    "error": "BUG",
    "warning": "BUG",
    "style": "CODE_SMELL",
    "performance": "CODE_SMELL",
    "portability": "CODE_SMELL",
}


def cppcheck_findings(project_key, xml_path):
    """Return the flat findings for a cppcheck XML report, or [] if it is missing or unparseable."""
    try:
        root = ET.parse(xml_path).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"cppcheck xml unreadable ({exc}); no C/C++ baseline added", file=sys.stderr)
        return []
    findings = []
    for err in root.iter("error"):
        issue_type = _SEVERITY_TO_TYPE.get(err.get("severity", ""))
        if issue_type is None:
            continue
        location = err.find("location")
        if location is None or not location.get("line"):
            continue
        rel = location.get("file", "").lstrip("./")
        if not rel:
            continue
        findings.append(
            {"component": f"{project_key}:{rel}", "line": int(location.get("line")), "type": issue_type}
        )
    return findings


def main(argv):
    if len(argv) != 4:
        print("usage: cppcheck_to_export.py <project-key> <cppcheck.xml> <export.json>", file=sys.stderr)
        return 2
    project_key, xml_path, export_path = argv[1], argv[2], argv[3]
    extra = cppcheck_findings(project_key, xml_path)
    with open(export_path) as fh:
        export = json.load(fh)
    export["issues"] = export.get("issues", []) + extra
    with open(export_path, "w") as fh:
        json.dump(export, fh)
    print(f"cppcheck baseline added {len(extra)} C/C++ finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
