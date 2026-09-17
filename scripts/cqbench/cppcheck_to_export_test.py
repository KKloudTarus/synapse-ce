"""Tests for cppcheck_to_export: run with `python3 -m unittest` in scripts/cqbench."""
import json
import os
import tempfile
import unittest

import cppcheck_to_export as c


class TestCppcheckToExport(unittest.TestCase):
    def _xml(self, body):
        fd, path = tempfile.mkstemp(suffix=".xml")
        os.write(fd, body.encode())
        os.close(fd)
        return path

    def test_maps_severity_and_takes_primary_location(self):
        xml = self._xml(
            '<results><errors>'
            '<error id="returnDanglingLifetime" severity="error">'
            '<location file="c-dangling/sample.c" line="3" column="12"/>'
            '<location file="c-dangling/sample.c" line="2" info="created here"/>'
            '</error>'
            '<error id="unreadVariable" severity="style">'
            '<location file="a/b.cpp" line="7"/></error>'
            '<error id="note" severity="information">'
            '<location file="a/b.cpp" line="1"/></error>'
            '</errors></results>'
        )
        got = c.cppcheck_findings("proj", xml)
        self.assertEqual(
            got,
            [
                {"component": "proj:c-dangling/sample.c", "line": 3, "type": "BUG"},
                {"component": "proj:a/b.cpp", "line": 7, "type": "CODE_SMELL"},
            ],
        )

    def test_missing_or_bad_xml_is_fail_soft(self):
        self.assertEqual(c.cppcheck_findings("proj", "/no/such/file.xml"), [])
        bad = self._xml("<not-xml")
        self.assertEqual(c.cppcheck_findings("proj", bad), [])

    def test_main_appends_to_existing_export(self):
        xml = self._xml(
            '<results><errors><error id="x" severity="warning">'
            '<location file="d/e.c" line="9"/></error></errors></results>'
        )
        fd, exp = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps({"issues": [{"component": "proj:keep.py", "line": 1, "type": "BUG"}]}).encode())
        os.close(fd)
        self.assertEqual(c.main(["prog", "proj", xml, exp]), 0)
        with open(exp) as fh:
            merged = json.load(fh)
        self.assertEqual(
            merged["issues"],
            [
                {"component": "proj:keep.py", "line": 1, "type": "BUG"},
                {"component": "proj:d/e.c", "line": 9, "type": "BUG"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
