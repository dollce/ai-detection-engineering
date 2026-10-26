"""Regression coverage for automation routing to this repository's GitHub fork.

Every HTTP request and subprocess is mocked. These tests do not run agents,
create GitHub objects, contact a SIEM, or read local token configuration.
"""

from collections import deque
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import agent_runner, health_monitor  # noqa: E402
from orchestration.agents import coverage_agent, security_agent, tuning_agent  # noqa: E402

TARGET_REPO = "dollce/ai-detection-engineering"
API_ROOT = f"https://api.github.com/repos/{TARGET_REPO}"
WEB_ROOT = f"https://github.com/{TARGET_REPO}"
TOKEN_FIXTURE = "test-only-not-a-real-token"


class GithubRepositoryTargetTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))
        self.enterContext(patch.dict(os.environ, {"GITHUB_TOKEN": TOKEN_FIXTURE}))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("Unexpected subprocess")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("Unexpected network")))
        self.responses = deque()
        self.http = self.enterContext(patch("urllib.request.urlopen", side_effect=self.respond))
        self.alert = health_monitor.HealthAlert(
            condition="SILENT_RULE", rule_name="PowerShell fixture", technique_id="T1059.001",
            message="No fixture alerts in seven days", severity="high", label="needs-tuning",
            suggested_actions="Revalidate the fixture rule",
        )

    def respond(self, request, **kwargs):
        if not self.responses:
            raise AssertionError("Unexpected HTTP request")
        response = MagicMock()
        response.read.return_value = json.dumps(self.responses.popleft()).encode("utf-8")
        response.status = 201
        response.__enter__.return_value = response
        return response

    def request(self, index=0):
        return self.http.call_args_list[index].args[0]

    def assert_request(self, index, method, path):
        request = self.request(index)
        self.assertEqual(request.full_url, API_ROOT + path)
        self.assertEqual(request.get_method(), method)
        return json.loads(request.data) if request.data else None

    def assert_health_search(self, index, repo=TARGET_REPO):
        request = self.request(index)
        url = urlsplit(request.full_url)
        self.assertEqual((url.scheme, url.netloc, url.path),
                         ("https", "api.github.com", "/search/issues"))
        query = parse_qs(url.query)
        self.assertEqual(query["q"], [f"repo:{repo} is:issue is:open {self.alert.issue_title}"])
        self.assertEqual(request.get_method(), "GET")

    def test_config_and_security_default_target_the_fork(self):
        config = yaml.safe_load((REPO_ROOT / "autonomous/orchestration/config.yml").read_text(encoding="utf-8"))
        self.assertEqual(config["github"]["repo"], TARGET_REPO)
        self.assertEqual(config["github"]["base_branch"], "main")
        token, repo = security_agent._load_github_config()
        self.assertEqual(token, TOKEN_FIXTURE)
        self.assertEqual(repo, TARGET_REPO)
        self.http.assert_not_called()

    def test_agent_pr_creation_targets_fork_and_preserves_pr_payload(self):
        pr_url = WEB_ROOT + "/pull/42"
        self.responses.append({"html_url": pr_url})
        result = agent_runner._create_pr("detection/test-fixture", "author", "Fixture title", "Fixture body")
        self.assertEqual(result, pr_url)
        self.assertEqual(self.http.call_count, 1)
        payload = self.assert_request(0, "POST", "/pulls")
        self.assertEqual(payload, {"title": "Fixture title", "body": "Fixture body",
                                   "head": "detection/test-fixture", "base": "main"})

    def test_security_pr_file_lookup_targets_fork(self):
        files = [{"filename": "detections/execution/fixture.yml", "status": "modified"}]
        self.responses.append(files)
        self.assertEqual(security_agent.get_pr_changed_files(42), files)
        self.assertEqual(self.http.call_count, 1)
        self.assert_request(0, "GET", "/pulls/42/files")

    def test_security_pr_comment_targets_fork(self):
        self.responses.append({"id": 123})
        self.assertTrue(security_agent.post_pr_comment(42, "Fixture security review"))
        self.assertEqual(self.http.call_count, 1)
        self.assertEqual(self.assert_request(0, "POST", "/issues/42/comments"),
                         {"body": "Fixture security review"})

    def test_coverage_gap_lookup_targets_fork_and_retains_dedup_ids(self):
        self.responses.append([
            {"title": "[Gap] No detection for PowerShell (T1059.001)"},
            {"title": "[Gap] No detection for Process Injection (T1055)"},
            {"title": "Unrelated issue"},
        ])
        result = coverage_agent._list_open_gap_issues(TOKEN_FIXTURE)
        self.assertEqual(result, {"T1059.001", "T1055"})
        self.assertEqual(self.http.call_count, 1)
        self.assert_request(0, "GET", "/issues?labels=coverage-gap&state=open&per_page=100")

    def test_coverage_gap_creation_targets_fork_and_retains_gap_metadata(self):
        issue_url = WEB_ROOT + "/issues/43"
        self.responses.append({"html_url": issue_url})
        result = coverage_agent._create_gap_issue(
            "T1059.001", "PowerShell", 0.9, ["Fawkes"], ["sysmon_1"], TOKEN_FIXTURE)
        self.assertEqual(result, issue_url)
        self.assertEqual(self.http.call_count, 1)
        payload = self.assert_request(0, "POST", "/issues")
        self.assertIn("(T1059.001)", payload["title"])
        self.assertEqual(payload["labels"], ["coverage-gap", "needs-review"])
        self.assertIn("Fawkes", payload["body"])
        self.assertIn("sysmon_1", payload["body"])

    def test_tuning_investigation_issue_targets_fork(self):
        self.responses.append({"html_url": WEB_ROOT + "/issues/44"})
        tuning_agent._create_investigate_issue(
            {"technique_id": "T1059.001", "title": "PowerShell fixture"},
            {"health_score": 25}, days_inactive=8)
        self.assertEqual(self.http.call_count, 1)
        payload = self.assert_request(0, "POST", "/issues")
        self.assertIn("T1059.001", payload["title"])
        self.assertIn("8+ days", payload["title"])
        self.assertEqual(payload["labels"], ["health-check", "needs-review"])

    def test_health_monitor_search_and_issue_create_target_fork(self):
        issue_url = WEB_ROOT + "/issues/45"
        self.responses.extend([{"items": []}, {"number": 45, "html_url": issue_url}])
        monitor = health_monitor.DetectionHealthMonitor(github_token=TOKEN_FIXTURE)
        self.assertEqual(monitor.create_github_issue(self.alert), issue_url)
        self.assertEqual(self.http.call_count, 2)
        self.assert_health_search(0)
        payload = self.assert_request(1, "POST", "/issues")
        self.assertEqual(payload["title"], self.alert.issue_title)
        self.assertEqual(payload["labels"], ["detection-health", "needs-tuning"])

    def test_health_monitor_dedup_comments_in_fork_instead_of_creating_issue(self):
        issue_url = WEB_ROOT + "/issues/45"
        existing = {"number": 45, "title": self.alert.issue_title, "html_url": issue_url}
        self.responses.extend([{"items": [existing]}, {"id": 456}])
        monitor = health_monitor.DetectionHealthMonitor(github_token=TOKEN_FIXTURE)
        self.assertEqual(monitor.create_github_issue(self.alert), issue_url)
        self.assertEqual(self.http.call_count, 2)
        self.assert_health_search(0)
        self.assertIn(self.alert.message, self.assert_request(1, "POST", "/issues/45/comments")["body"])

    def test_health_monitor_close_targets_fork_for_comment_and_state_update(self):
        self.responses.extend([{"id": 456}, {"state": "closed"}])
        monitor = health_monitor.DetectionHealthMonitor(github_token=TOKEN_FIXTURE)
        monitor.close_github_issue(45, "Fixture resolved")
        self.assertEqual(self.http.call_count, 2)
        self.assertEqual(self.assert_request(0, "POST", "/issues/45/comments"),
                         {"body": "Closing: Fixture resolved"})
        self.assertEqual(self.assert_request(1, "PATCH", "/issues/45"),
                         {"state": "closed", "state_reason": "completed"})

    def test_health_monitor_explicit_repository_override_is_preserved(self):
        override = "example/alternate-lab"
        self.responses.extend([{"items": []}, {"number": 46, "html_url": f"https://github.com/{override}/issues/46"}])
        monitor = health_monitor.DetectionHealthMonitor(github_token=TOKEN_FIXTURE, repo=override)
        self.assertEqual(monitor.create_github_issue(self.alert), f"https://github.com/{override}/issues/46")
        self.assertEqual(self.http.call_count, 2)
        self.assert_health_search(0, repo=override)
        self.assertEqual(self.request(1).full_url, f"https://api.github.com/repos/{override}/issues")
        self.assertEqual(self.request(1).get_method(), "POST")

    def test_missing_token_still_skips_github_writes_and_security_reads(self):
        # Prevent fallback reads of real local token files while exercising the
        # original no-token branches; no agent runner or monitor run is invoked.
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}), patch.object(Path, "exists", return_value=False):
            self.assertIsNone(agent_runner._create_pr("fixture", "author", "title", "body"))
            self.assertEqual(security_agent.get_pr_changed_files(42), [])
            self.assertFalse(security_agent.post_pr_comment(42, "Fixture"))
            self.assertIsNone(tuning_agent._create_investigate_issue(
                {"technique_id": "T1059.001"}, {"health_score": 25}, 8))
            monitor = health_monitor.DetectionHealthMonitor()
            self.assertIsNone(monitor.create_github_issue(self.alert))
            monitor.close_github_issue(45, "Fixture")
        self.http.assert_not_called()


if __name__ == "__main__":
    unittest.main()
