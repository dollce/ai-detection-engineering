"""Project-local Codex MCP setup tests; no CLI/server/network is started."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("configure_codex", REPO_ROOT / "pipeline/configure_codex.py")
configure_codex = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(configure_codex)


class CodexProjectConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'worktree "quoted" \\ 한글'
        self.root.mkdir()
        self.available = {"node": "/mock/bin/node", "npx": "/mock/bin/npx"}
        self.enterContext(patch.object(configure_codex.shutil, "which", side_effect=self.available.get))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("Setup test must not start a server")))
        self.enterContext(patch("urllib.request.urlopen", side_effect=AssertionError("Setup test must not use network")))
        self.enterContext(redirect_stdout(io.StringIO()))

    def servers(self, mode="elastic", cribl=False):
        content = configure_codex.render_config(self.root, include_cribl=cribl, siem_mode=mode)
        return tomllib.loads(content)["mcp_servers"]

    def test_elastic_and_both_modes_include_existing_elastic_server(self):
        for mode in ("elastic", "both"):
            with self.subTest(mode=mode):
                servers = self.servers(mode)
                self.assertEqual(set(servers), {"elasticsearch", "github"})
                elastic = servers["elasticsearch"]
                self.assertEqual(elastic["command"], "docker")
                self.assertIn("-i", elastic["args"])
                self.assertIn("blue-team-lab", elastic["args"])
                self.assertIn("docker.elastic.co/mcp/elasticsearch", elastic["args"])

    def test_splunk_only_does_not_register_inactive_elastic_or_invent_splunk_mcp(self):
        self.assertEqual(set(self.servers("splunk")), {"github"})
        self.available.clear()
        self.assertEqual(self.servers("splunk"), {})

    def test_optional_cribl_uses_the_selected_worktree_as_absolute_cwd(self):
        for mode in ("elastic", "splunk", "both"):
            with self.subTest(mode=mode):
                servers = self.servers(mode, cribl=True)
                cribl = servers["cribl"]
                self.assertEqual(cribl["command"], "node")
                self.assertEqual(cribl["args"], ["./cribl/mcp-server/index.js"])
                self.assertEqual(cribl["cwd"], str(self.root.resolve()))
                self.assertTrue(Path(cribl["cwd"]).is_absolute())
                self.assertEqual(cribl["env"]["CRIBL_URL"], "http://localhost:9000")
                self.assertEqual(servers["github"]["cwd"], str(self.root.resolve()))

    def test_missing_node_or_npx_omits_only_corresponding_optional_server(self):
        self.available.pop("node")
        self.assertEqual(set(self.servers(cribl=True)), {"elasticsearch", "github"})
        self.available["node"] = "/mock/bin/node"
        self.available.pop("npx")
        self.assertEqual(set(self.servers(cribl=True)), {"elasticsearch", "cribl"})
        self.available.clear()
        self.assertEqual(set(self.servers(cribl=True)), {"elasticsearch"})

    def test_github_token_is_forwarded_by_name_without_persisting_its_value(self):
        token_fixture = "test-only-not-a-real-token"
        with patch.dict(os.environ, {"GITHUB_PERSONAL_ACCESS_TOKEN": token_fixture}):
            content = configure_codex.render_config(self.root, include_cribl=True)
            self.assertTrue(configure_codex.write_config(self.root, include_cribl=True))
        self.assertNotIn(token_fixture, content)
        written = (self.root / ".codex/config.toml").read_text(encoding="utf-8")
        self.assertNotIn(token_fixture, written)
        github = tomllib.loads(written)["mcp_servers"]["github"]
        self.assertEqual(github["env_vars"], ["GITHUB_PERSONAL_ACCESS_TOKEN"])
        self.assertNotIn("env", github)

    def test_render_is_side_effect_free_and_escapes_unusual_worktree_paths(self):
        paths = (self.root, self.root / 'newline\nquote"backslash\\')
        for root in paths:
            with self.subTest(root=str(root)):
                rendered = configure_codex.render_config(root, include_cribl=True)
                parsed = tomllib.loads(rendered)
                self.assertEqual(parsed["mcp_servers"]["cribl"]["cwd"], str(root.resolve()))
                self.assertFalse((root / ".codex").exists())

    def test_write_creates_only_project_config_without_accessing_user_home(self):
        with patch.object(configure_codex.Path, "home", side_effect=AssertionError("Do not access user config")):
            self.assertTrue(configure_codex.write_config(self.root, include_cribl=True, siem_mode="both"))
        written_files = {path.relative_to(self.root).as_posix() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(written_files, {".codex/config.toml"})
        parsed = tomllib.loads((self.root / ".codex/config.toml").read_text(encoding="utf-8"))
        self.assertEqual(set(parsed), {"mcp_servers"})
        self.assertEqual(set(parsed["mcp_servers"]), {"elasticsearch", "cribl", "github"})

    def test_existing_custom_config_is_preserved_even_if_requested_services_change(self):
        config = self.root / ".codex/config.toml"
        config.parent.mkdir()
        original = b'# User settings\nmodel = "custom-model"\n'
        config.write_bytes(original)
        self.assertFalse(configure_codex.write_config(self.root, include_cribl=True, siem_mode="both"))
        self.assertEqual(config.read_bytes(), original)
        self.assertFalse(configure_codex.write_config(self.root, siem_mode="splunk"))
        self.assertEqual(config.read_bytes(), original)

    def test_generated_config_is_idempotent(self):
        self.assertTrue(configure_codex.write_config(self.root, include_cribl=True))
        config = self.root / ".codex/config.toml"
        original = config.read_bytes()
        self.assertFalse(configure_codex.write_config(self.root, include_cribl=True))
        self.assertEqual(config.read_bytes(), original)

    def test_invalid_mode_is_rejected_before_creating_config(self):
        for mode in ("invalid", "elastic\n[mcp_servers.injected]", ""):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    configure_codex.render_config(self.root, siem_mode=mode)
                with self.assertRaises(ValueError):
                    configure_codex.write_config(self.root, siem_mode=mode)
                self.assertFalse((self.root / ".codex").exists())

    def test_cli_respects_service_selection_and_does_not_overwrite_config(self):
        with patch.object(configure_codex, "REPO_ROOT", self.root), patch.object(
                sys, "argv", ["configure_codex.py", "--siem-mode", "splunk", "--cribl"]):
            self.assertEqual(configure_codex.main(), 0)
            self.assertEqual(configure_codex.main(), 0)
        parsed = tomllib.loads((self.root / ".codex/config.toml").read_text(encoding="utf-8"))
        self.assertEqual(set(parsed["mcp_servers"]), {"cribl", "github"})

    def test_cli_invalid_mode_does_not_create_project_config(self):
        with patch.object(configure_codex, "REPO_ROOT", self.root), patch.object(
                sys, "argv", ["configure_codex.py", "--siem-mode", "invalid"]), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                configure_codex.main()
        self.assertEqual(error.exception.code, 2)
        self.assertFalse((self.root / ".codex").exists())


if __name__ == "__main__":
    unittest.main()
