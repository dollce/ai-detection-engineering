"""Exercise wrapper failure propagation with fake Docker/model subprocesses only.

These are control-flow tests, never evidence of a real SIEM or model execution.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ade-e2e-wrapper-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "pipeline").mkdir()
        (self.root / ".venv/bin").mkdir(parents=True)
        shutil.copyfile(ROOT / "pipeline/e2e-elastic.sh", self.root / "pipeline/e2e-elastic.sh")
        self.calls = self.root / "subprocess-calls.jsonl"
        # The dependency probe is stubbed; all JSON/evidence operations use Python.
        # This keeps the control-flow test independent of installed sigma packages.
        real_python = shlex.quote(sys.executable)
        self.executable("python", '#!/usr/bin/env bash\nif [[ "$#" == 5 && "$1" == "-" ]]; then exit 0; fi\nexec ' + real_python + ' "$@"\n')
        self.executable("python3", '#!/usr/bin/env bash\nexec ' + real_python + ' "$@"\n')
        self.executable("sigma", "#!/bin/sh\nexit 0\n")
        self.executable("codex", "#!/bin/sh\nexit 0\n")
        self.executable("docker", '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path(os.environ["STUB_CALLS"]).open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
mode = os.environ["STUB_MODE"]
if args[:2] == ["compose", "version"]:
    print("2.24.4")
elif "up" in args and mode == "startup_failure":
    raise SystemExit(7)
elif "down" in args and mode == "cleanup_failure":
    raise SystemExit(8)
# All resource inventories are empty; no real Docker command is invoked.
''')
        runner = '''import argparse, json, os, pathlib
p = argparse.ArgumentParser()
p.add_argument("--report")
p.add_argument("--output-dir")
p.add_argument("--timeout")
p.add_argument("--llm-timeout")
a = p.parse_args()
if os.environ["STUB_MODE"] == "missing_report":
    raise SystemExit(0)
stages = {key: {"status": "PASS"} for key in ("preflight", "compile", "template", "query_validation", "replay", "deploy", "scheduled_alerts", "cleanup")}
elastic = {"status": "PASS", "stages": stages}
if a.output_dir:
    out = pathlib.Path(a.output_dir)
    out.mkdir()
    agent_stages = {key: {"status": "PASS"} for key in ("preflight", "scenario_generation", "sigma_generation", "case_assembly", "elastic_e2e")}
    path, report = out / "report.json", {"status": "PASS", "elastic": elastic, "stages": agent_stages, "calls": [{"status": "PASS"}, {"status": "PASS"}]}
    if os.environ["STUB_MODE"] == "missing_llm_calls":
        report.pop("calls")
    if os.environ["STUB_MODE"] == "missing_llm_stage":
        report["stages"].pop("sigma_generation")
else:
    path, report = pathlib.Path(a.report), elastic
if os.environ["STUB_MODE"] == "missing_elastic_stage":
    elastic["stages"].pop("template")
path.write_text(json.dumps(report))
'''
        for name in ("e2e_elastic.py", "e2e_agents.py"):
            (self.root / "pipeline" / name).write_text(runner)

    def executable(self, name, source):
        path = self.root / ".venv/bin" / name
        path.write_text(source)
        path.chmod(0o755)

    def invoke(self, mode, fixture_only=True, preflight=False):
        command = ["bash", "pipeline/e2e-elastic.sh"]
        if fixture_only:
            command.append("--fixture-only")
        if preflight:
            command.append("--preflight")
        env = {**os.environ, "STUB_MODE": mode, "STUB_CALLS": str(self.calls)}
        result = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=20)
        paths = list((self.root / "artifacts/e2e").glob("*/stack-report.json")) if (self.root / "artifacts/e2e").exists() else []
        report = json.loads(paths[0].read_text()) if paths else None
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return result, report, calls

    def assert_owned_cleanup(self, report, calls):
        teardown = [args for args in calls if "down" in args]
        self.assertEqual(len(teardown), 1)
        self.assertIn("--volumes", teardown[0])
        index = teardown[0].index("--project-name")
        self.assertEqual(teardown[0][index + 1], report["compose_project"])
        self.assertRegex(report["compose_project"], r"^ade-e2e-\d{8}t\d{6}-[0-9a-f]{10}$")
        self.assertTrue(any("logs" in args for args in calls))

    def test_startup_failure_is_recorded_and_partial_project_is_cleaned(self):
        result, report, calls = self.invoke("startup_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["last_stage"], "startup")
        self.assertIsNone(report["verified_runner_report"])
        self.assert_owned_cleanup(report, calls)

    def test_zero_runner_exit_without_report_is_not_a_pass(self):
        result, report, calls = self.invoke("missing_report")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["runner_exit_code"], 0)
        self.assertEqual(report["status"], "FAIL")
        self.assertIsNone(report["verified_runner_report"])
        self.assert_owned_cleanup(report, calls)

    def test_teardown_failure_overrides_a_successful_runner(self):
        result, report, calls = self.invoke("cleanup_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["runner_exit_code"], 0)
        self.assertIsNotNone(report["verified_runner_report"])
        self.assertEqual(report["stack_cleanup"]["status"], "FAIL")
        self.assertEqual(report["status"], "FAIL")
        self.assert_owned_cleanup(report, calls)

    def test_default_agent_mode_requires_report_and_owned_teardown(self):
        result, report, calls = self.invoke("success", fixture_only=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["mode"], "live_llm_and_elastic")
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["verified_runner_report"].endswith("agents/report.json"))
        self.assert_owned_cleanup(report, calls)

    def test_parent_pass_cannot_hide_missing_stage_or_model_evidence(self):
        for mode in ("missing_llm_calls", "missing_llm_stage", "missing_elastic_stage"):
            with self.subTest(mode=mode):
                result, report, calls = self.invoke(mode, fixture_only=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report["status"], "FAIL")
                self.assertIsNone(report["verified_runner_report"])
                # Inspect the latest run when the subtest creates several reports.
                shutil.rmtree(self.root / "artifacts")
                self.calls.unlink()

    def test_preflight_does_not_create_artifacts_or_mutate_stack(self):
        result, report, calls = self.invoke("success", preflight=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(report)
        self.assertFalse((self.root / "artifacts").exists())
        self.assertFalse(any("up" in args or "down" in args for args in calls))


if __name__ == "__main__":
    unittest.main()
