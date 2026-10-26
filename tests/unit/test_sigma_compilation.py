"""Compiler output is usable only when that backend completes successfully."""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration.constants import normalize_lucene_output, transpile_sigma


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["sigma", "convert"], returncode, stdout, stderr)


class LuceneNormalizationTests(unittest.TestCase):
    def test_cli_preamble_and_lab_channel_prefix_are_removed(self):
        output = (
            "  Parsing Sigma rules...\n"
            "\nwinlog.channel:Microsoft-Windows-Sysmon/Operational AND "
            "process.name:powershell.exe  \n"
        )
        self.assertEqual(normalize_lucene_output(output), "process.name:powershell.exe")

    def test_query_without_prefix_and_interior_channel_clause_are_preserved(self):
        query = "process.name:cmd.exe AND winlog.channel:Security"
        self.assertEqual(normalize_lucene_output("  " + query + "\n"), query)

    def test_empty_or_preamble_only_output_is_not_a_query(self):
        for output in ("", "  \n", "Parsing Sigma rules...\n"):
            with self.subTest(output=output):
                self.assertEqual(normalize_lucene_output(output), "")


class SigmaCompilationTests(unittest.TestCase):
    def compile(self, results):
        with patch("orchestration.constants.subprocess.run", side_effect=results) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                queries = transpile_sigma(Path("detections/execution/test.yml"))
        self.assertEqual(run.call_count, 2, "Both backends must be attempted independently")
        return queries

    def test_success_returns_normalized_lucene_and_trimmed_spl(self):
        self.assertEqual(self.compile([
            completed(stdout="Parsing Sigma rules...\nwinlog.channel:Security AND process.name:cmd.exe\n"),
            completed(stdout="  Image=cmd.exe\n"),
        ]), ("process.name:cmd.exe", "Image=cmd.exe"))

    def test_nonzero_exit_rejects_plausible_output_even_when_both_backends_emit_it(self):
        self.assertEqual(self.compile([
            completed(1, "process.name:cmd.exe", "unhandled Sigma modifier"),
            completed(2, "Image=cmd.exe", "unsupported condition"),
        ]), ("", ""))

    def test_failed_lucene_keeps_successful_spl(self):
        self.assertEqual(self.compile([
            completed(1, "process.name:cmd.exe", "compilation failed"),
            completed(stdout="Image=cmd.exe"),
        ]), ("", "Image=cmd.exe"))

    def test_failed_spl_keeps_successful_lucene(self):
        self.assertEqual(self.compile([
            completed(stdout="process.name:cmd.exe"),
            completed(1, "Image=cmd.exe", "compilation failed"),
        ]), ("process.name:cmd.exe", ""))

    def test_missing_cli_returns_empty_queries(self):
        self.assertEqual(self.compile([
            FileNotFoundError("sigma not found"), FileNotFoundError("sigma not found"),
        ]), ("", ""))

    def test_backend_exception_does_not_discard_other_backend_success(self):
        for failed_backend in (0, 1):
            results = [completed(stdout="process.name:cmd.exe"), completed(stdout="Image=cmd.exe")]
            results[failed_backend] = subprocess.TimeoutExpired("sigma", 1, output="partial query")
            expected = ["process.name:cmd.exe", "Image=cmd.exe"]
            expected[failed_backend] = ""
            with self.subTest(failed_backend=failed_backend):
                self.assertEqual(self.compile(results), tuple(expected))

    def test_success_without_query_returns_empty_strings(self):
        self.assertEqual(self.compile([
            completed(stdout="Parsing Sigma rules...\n"), completed(stdout="  \n"),
        ]), ("", ""))


if __name__ == "__main__":
    unittest.main()
