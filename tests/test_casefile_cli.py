from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from siberian.casefile import CaseFileError, load_case_file
from siberian.cli import main


def unknown_case() -> dict[str, object]:
    return {
        "schema_version": "siberian-case-v1",
        "context": {
            "os_profile": "windows",
            "os_release": "Windows 10",
            "system_build": "19045",
            "scope": "host:demo / Security.evtx",
            "interval_start": "2026-10-01T00:00:00Z",
            "interval_end": "2026-10-02T00:00:00Z",
            "acquisition_ref": "case://demo/security.evtx",
        },
        "activities": [
            {
                "action": "process_execution",
                "observations": [
                    {
                        "artifact_type": "security_event_4688",
                        "status": "unknown",
                        "reason": "acquisition_gap",
                        "evidence_ref": "case://demo/acquisition-gap",
                    }
                ],
            }
        ],
    }


class CaseFileCliTests(unittest.TestCase):
    def write_case(self, directory: str, text: str) -> Path:
        path = Path(directory) / "case.json"
        path.write_text(text, encoding="utf-8")
        return path

    def test_valid_case_builds_explicit_unknown_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, json.dumps(unknown_case()))
            analyzer, activities, observations = load_case_file(path)
        result = analyzer.analyze()
        self.assertEqual((activities, observations), (1, 1))
        self.assertEqual(result.unknown_count, 1)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, '{"schema_version":"siberian-case-v1","schema_version":"siberian-case-v1"}')
            with self.assertRaisesRegex(CaseFileError, "duplicate JSON object key"):
                load_case_file(path)

    def test_unknown_fields_are_rejected(self) -> None:
        case = unknown_case()
        case["unexpected"] = "value"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, json.dumps(case))
            with self.assertRaisesRegex(CaseFileError, "unknown fields"):
                load_case_file(path)

    def test_unknown_observation_requires_reason(self) -> None:
        case = unknown_case()
        activity = case["activities"][0]  # type: ignore[index]
        observation = activity["observations"][0]  # type: ignore[index]
        del observation["reason"]  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, json.dumps(case))
            with self.assertRaisesRegex(CaseFileError, "requires a reason"):
                load_case_file(path)

    def test_timestamps_without_timezone_are_rejected(self) -> None:
        case = unknown_case()
        context = case["context"]  # type: ignore[index]
        context["interval_start"] = "2026-10-01T00:00:00"  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, json.dumps(case))
            with self.assertRaisesRegex(CaseFileError, "must include a timezone"):
                load_case_file(path)

    def test_oversized_case_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b" " * (5 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(CaseFileError, "size limit"):
                load_case_file(path)

    def test_excessive_json_nesting_is_rejected_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, "[" * 10000 + "0" + "]" * 10000)
            with self.assertRaisesRegex(CaseFileError, "nesting depth"):
                load_case_file(path)

    def test_analyze_output_is_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, json.dumps(unknown_case()))
            outputs = []
            for _ in range(2):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(main(["analyze", str(path)]), 0)
                outputs.append(stdout.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        result = json.loads(outputs[0])
        self.assertEqual(result["counts"]["unknown"], 1)

    def test_synthetic_mixed_case_preserves_all_four_statuses(self) -> None:
        path = Path(__file__).parent.parent / "examples" / "case-mixed-statuses.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["analyze", str(path)]), 0)
        counts = json.loads(stdout.getvalue())["counts"]
        self.assertEqual(counts["expected"], 5)
        self.assertEqual(counts["present"], 2)
        self.assertEqual(counts["confirmed_absent"], 1)
        self.assertEqual(counts["unknown"], 1)
        self.assertEqual(counts["out_of_scope"], 1)

    def test_explain_includes_absence_supporting_references(self) -> None:
        path = Path(__file__).parent.parent / "examples" / "case-mixed-statuses.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["explain", str(path)]), 0)
        output = stdout.getvalue()
        self.assertIn("case://training/session-end", output)
        self.assertIn("case://training/audit-policy", output)
        self.assertIn("case://training/log-coverage", output)

    def test_explain_does_not_turn_unknown_into_deletion_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, json.dumps(unknown_case()))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["explain", str(path)]), 0)
        self.assertIn("acquisition_gap", stdout.getvalue())
        self.assertIn("Suggested next check: review acquisition coverage", stdout.getvalue())
        self.assertIn("Do not interpret this row as evidence that an artifact was deleted", stdout.getvalue())

    def test_explain_escapes_terminal_control_characters(self) -> None:
        case = unknown_case()
        context = case["context"]  # type: ignore[index]
        context["scope"] = "host:\u001b[2J\nsecond-line"  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_case(directory, json.dumps(case))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["explain", str(path)]), 0)
        self.assertNotIn("\u001b", stdout.getvalue())
        self.assertIn("\\u001b[2J\\u000asecond-line", stdout.getvalue())
        self.assertIn("does not establish deletion", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
