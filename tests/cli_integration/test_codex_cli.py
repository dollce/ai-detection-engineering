"""Opt-in installed-CLI checks using a localhost mock API, never a live model.

Run: CODEX_CLI_INTEGRATION=1 python -m unittest discover -s tests/cli_integration -v
Requires Codex CLI >= 0.163.0 and permission to bind a loopback socket. The mock
uses an empty temporary HOME/CODEX_HOME; it never reads real credentials or sends
requests to an external provider. Normal unit-test discovery does not run this.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import codex_llm  # noqa: E402


@unittest.skipUnless(os.environ.get("CODEX_CLI_INTEGRATION") == "1",
                     "Set CODEX_CLI_INTEGRATION=1 to run the local CLI checks")
@unittest.skipUnless(shutil.which("codex"), "Codex CLI is not installed")
class NativeCodexCLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="codex-cli-contract-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        isolated_home = root / "home"
        isolated_home.mkdir()
        self.fixture = root / "inert-fixture.txt"
        self.fixture.write_text("inert-before\n", encoding="utf-8")
        self.requests = []
        self.emit_patch = False
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = self.rfile.read(int(self.headers["Content-Length"]))
                test.requests.append(json.loads(payload))
                if test.emit_patch and len(test.requests) == 1:
                    item = {
                        "type": "custom_tool_call", "id": "ctc_offline",
                        "call_id": "call_offline", "name": "apply_patch",
                        "input": (f"*** Begin Patch\n*** Update File: {test.fixture}\n"
                                  "@@\n-inert-before\n+inert-after\n*** End Patch"),
                    }
                else:
                    item = {
                        "type": "message", "id": "msg_offline", "role": "assistant",
                        "content": [{"type": "output_text", "text": "OK", "annotations": []}],
                    }
                response = {
                    "id": f"resp_offline_{len(test.requests)}", "object": "response",
                    "status": "completed", "output": [item],
                    "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
                }
                events = [
                    {"type": "response.output_item.done", "output_index": 0, "item": item},
                    {"type": "response.completed", "response": response},
                ]
                body = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                               for event in events).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 5)
        self.addCleanup(self.server.shutdown)
        self.environment = {
            "PATH": os.environ.get("PATH", ""), "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home), "CODEX_HOME": str(isolated_home),
            "TMPDIR": str(root), "TMP": str(root), "TEMP": str(root),
            "LANG": "en_US.UTF-8",
        }
        if "SYSTEMROOT" in os.environ:
            self.environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        self.real_run = subprocess.run

    def run_with_local_provider(self, cmd, **kwargs):
        """Keep adapter policy intact; redirect only transport and credential home."""
        provider = (
            '{name="offline_contract",base_url="http://127.0.0.1:%d/v1",'
            'wire_api="responses",requires_openai_auth=false,'
            'request_max_retries=0,stream_max_retries=0}' % self.server.server_address[1]
        )
        # Disable compression so the fixture remains stdlib-only; suppress daemon
        # startup in the disposable home. Neither option changes the tool policy.
        self.assertEqual(cmd[-1], "-")
        cmd = cmd[:-1] + [
            "-c", 'model_provider="offline_contract"',
            "-c", f"model_providers.offline_contract={provider}",
            "-c", "features.enable_request_compression=false",
            "-c", "features.daemon_auto_start=false", "-",
        ]
        kwargs["env"] = self.environment
        return self.real_run(cmd, **kwargs)

    def invoke(self, *, web=False):
        # CI normally disables the adapter. This explicit opt-in fixture only
        # reaches the local fake provider, even if invoked by a CI operator.
        with patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""}), patch.object(
                codex_llm.subprocess, "run", side_effect=self.run_with_local_provider):
            if web:
                # The wrapper's model selection is explicit in this fixture only.
                with patch.dict(os.environ, {"CODEX_MODEL": "gpt-5.5"}):
                    result = codex_llm.ask_with_web_search(
                        "Return only OK. Offline contract test.", timeout_seconds=30)
            else:
                result = codex_llm.ask(
                    "Return only OK. Offline contract test.",
                    model="gpt-5.5", timeout_seconds=30)
        self.assertTrue(result["success"], result["error"])
        self.assertEqual(result["response"], "OK")
        self.assertTrue(self.requests, "Expected a request to the loopback fixture")

    def assert_tool_inventory(self, *, web=False):
        tools = self.requests[0]["tools"]
        names = {tool["name"] for tool in tools if "name" in tool}
        # These two CLI tools remain advertised. apply_patch is enforced by the
        # read-only sandbox; request_user_input is unavailable outside Plan mode.
        self.assertLessEqual(names, {"request_user_input", "apply_patch"})
        unnamed = {tool["type"] for tool in tools if "name" not in tool}
        if web:
            self.assertTrue(unnamed, "Native web search must be enabled")
            self.assertTrue(all(name.startswith("web_search") for name in unnamed), unnamed)
        else:
            self.assertFalse(unnamed, unnamed)

    def test_default_tool_inventory_and_read_only_patch_denial(self):
        self.emit_patch = True
        self.invoke()
        self.assert_tool_inventory()
        self.assertEqual(self.fixture.read_text(encoding="utf-8"), "inert-before\n")
        tool_outputs = [item["output"] for request in self.requests
                        for item in request["input"]
                        if item.get("type") == "custom_tool_call_output"]
        self.assertTrue(tool_outputs, "The model's patch request must receive a rejection")
        self.assertTrue(any("read-only sandbox" in output for output in tool_outputs), tool_outputs)
        self.assertTrue(all("inert-before" not in output for output in tool_outputs),
                        "Rejection must not expose the existing file contents")

    def test_web_wrapper_exposes_only_native_search_in_addition(self):
        self.invoke(web=True)
        self.assert_tool_inventory(web=True)


if __name__ == "__main__":
    unittest.main()
