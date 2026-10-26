"""Exercise branch automation in a local repository that has master but no main."""

import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import agent_runner


class MasterBranchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.remote = self.root / "remote.git"
        self.repo = self.root / "checkout"
        self.enterContext(patch.dict(os.environ, {
            "GIT_AUTHOR_NAME": "Branch test", "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Branch test", "GIT_COMMITTER_EMAIL": "test@example.com",
        }))
        self.git("init", "--bare", "--initial-branch=master", str(self.remote), cwd=self.root)
        self.git("init", "--initial-branch=master", str(self.repo), cwd=self.root)
        (self.repo / "README.md").write_text("fixture\n")
        self.git("add", "README.md")
        self.git("commit", "-m", "initial fixture")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "-u", "origin", "master")
        self.enterContext(patch.object(agent_runner, "REPO_ROOT", self.repo))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.repo, check=True,
                              text=True, capture_output=True).stdout.strip()

    def test_agent_branches_from_master_compares_changes_and_restores_user_work(self):
        (self.repo / "operator-notes.txt").write_text("keep this untracked note\n")
        branch, had_stash = agent_runner._create_branch("validation", "offline-test")
        self.assertTrue(had_stash)
        self.assertEqual(self.git("branch", "--show-current"), branch)
        self.assertEqual(self.git("branch", "--list", "main"), "")
        self.assertFalse(agent_runner._has_substantive_changes(branch))
        (self.repo / "rule.yml").write_text("title: fixture\n")
        self.git("add", "rule.yml")
        self.git("commit", "-m", "test substantive rule change")
        self.assertTrue(agent_runner._has_substantive_changes(branch))
        agent_runner._cleanup_branch(had_stash=True)
        self.assertEqual(self.git("branch", "--show-current"), "master")
        self.assertEqual((self.repo / "operator-notes.txt").read_text(), "keep this untracked note\n")

    def test_pipeline_can_create_and_push_its_branch_without_main(self):
        with patch.object(agent_runner, "StateManager"), \
             patch.object(agent_runner, "_generate_run_id", return_value="offline-test"), \
             patch.object(agent_runner, "_create_pr") as create_pr:
            agent_runner.run_pipeline([])
        branch = "agent/pipeline/offline-test"
        self.assertEqual(self.git("branch", "--show-current"), branch)
        self.assertEqual(self.git("rev-parse", f"origin/{branch}"), self.git("rev-parse", "master"))
        create_pr.assert_called_once()
        self.assertEqual(create_pr.call_args.args[0], branch)


class ManualPRBaseTests(unittest.TestCase):
    def test_manual_helper_defaults_to_master_and_preserves_explicit_override(self):
        for override in (None, "release/test"):
            with self.subTest(override=override):
                argv = ["create-pr.py", "placeholder-token", "test title", "feature/test"]
                if override:
                    argv.append(override)
                response = MagicMock()
                response.__enter__.return_value = response
                response.read.return_value = json.dumps({"number": 1, "html_url": "https://example.com/pr/1"}).encode()
                response.status = 201
                with patch.object(sys, "argv", argv), \
                     patch.dict(os.environ, {"GITHUB_PAT": "placeholder-token", "GITHUB_REPO": "example/repo"}), \
                     patch("subprocess.check_output", return_value="commit fixture"), \
                     patch("urllib.request.urlopen", return_value=response) as send, \
                     contextlib.redirect_stdout(io.StringIO()):
                    runpy.run_path(str(REPO_ROOT / "pipeline/create-pr.py"), run_name="__main__")
                payload = json.loads(send.call_args.args[0].data)
                self.assertEqual(payload["base"], override or "master")
                self.assertEqual(payload["head"], "feature/test")


if __name__ == "__main__":
    unittest.main()
