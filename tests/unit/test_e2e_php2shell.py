"""PHP2Shell evidence boundaries: real log flags and fail-closed stage gates."""
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("e2e_php2shell", ROOT / "pipeline/e2e_php2shell.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)


def observation(method="POST", cookie="0", body_sid="0", progress="0", observed="1"):
    return {"request_id": "a" * 32, "method": method, "status": "200",
            "session_cookie_key": cookie, "session_body_token": body_sid,
            "progress_body_token": progress, "body_observed": observed}


class PredicateTests(unittest.TestCase):
    def test_aws_exact_three_legs_and_negative_controls(self):
        self.assertTrue(e2e.aws_match(observation(cookie="1", progress="1")))
        self.assertTrue(e2e.aws_match(observation(body_sid="1", progress="1")))
        for value in (observation(method="GET", cookie="1", body_sid="1", progress="1"),
                      observation(cookie="1"), observation(progress="1"), observation(body_sid="1")):
            self.assertFalse(e2e.aws_match(value))

    def test_missing_nginx_fields_are_not_negative_evidence(self):
        value = observation()
        del value["progress_body_token"]
        with self.assertRaises((KeyError, e2e.E2EFailure)):
            e2e.source_event(value)
        with self.assertRaises((KeyError, e2e.E2EFailure)):
            e2e.aws_match(value)
        value = observation(progress="unknown")
        with self.assertRaises(e2e.E2EFailure):
            e2e.source_event(value)
        value = observation(observed="0")
        with self.assertRaises(e2e.E2EFailure):
            e2e.aws_match(value)

    def test_source_event_contains_observed_signals_not_test_labels(self):
        source = e2e.source_event(observation(cookie="1", progress="1"))
        self.assertEqual(source["http"]["request"]["method"], "POST")
        self.assertEqual(source["php2shell"]["session_cookie_key"], "1")
        self.assertNotIn("expected_alert", json.dumps(source))


class ModelAndElasticGateTests(unittest.TestCase):
    def sample(self):
        return {"attack_events": [
                    {"description": "cookie route", "method": "POST", "session_cookie_key": True,
                     "session_body_token": False, "progress_body_token": True, "body_observed": True},
                    {"description": "body route", "method": "POST", "session_cookie_key": False,
                     "session_body_token": True, "progress_body_token": True, "body_observed": True}],
                "benign_events": [
                    {"description": "ordinary upload", "method": "POST", "session_cookie_key": False,
                     "session_body_token": False, "progress_body_token": False, "body_observed": True},
                    {"description": "session without progress", "method": "POST", "session_cookie_key": True,
                     "session_body_token": False, "progress_body_token": False, "body_observed": True}]}

    def test_generated_labels_must_follow_independent_oracle(self):
        cases = e2e.validate_generated(self.sample())
        self.assertEqual([case["expected_alert"] for case in cases], [True, True, False, False])
        invalid = self.sample()
        invalid["attack_events"][0]["progress_body_token"] = False
        with self.assertRaises(e2e.E2EFailure):
            e2e.validate_generated(invalid)
        invalid = self.sample()
        invalid["attack_events"][0]["body_observed"] = False
        with self.assertRaises(e2e.E2EFailure):
            e2e.validate_generated(invalid)

    def test_missing_elastic_stage_or_nonzero_exit_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            value = {"status": "PASS", "stages": {stage: {"status": "PASS"}
                      for stage in e2e.REQUIRED_ELASTIC_STAGES}}
            path.write_text(json.dumps(value))
            e2e.check_elastic_report(path, 0)
            with self.assertRaises(e2e.E2EFailure):
                e2e.check_elastic_report(path, 1)
            del value["stages"]["scheduled_alerts"]
            path.write_text(json.dumps(value))
            with self.assertRaises(e2e.E2EFailure):
                e2e.check_elastic_report(path, 0)

    def test_poc_response_ids_and_raw_dummy_proof_bind_to_nginx_logs(self):
        ids = [f"{number:032x}" for number in range(1, 5)]
        nonce = "0123456789abcdef"
        dummy_hash = hashlib.sha256((ROOT / "tests/e2e/php2shell/print-flag").read_bytes()).hexdigest()
        body = (f"{nonce}\nuid=101\n{dummy_hash}  /usr/local/bin/print-flag\n"
                "LOCAL_DUMMY_WIF_NEVER_USE\n").encode()
        def raw_response(request_id, payload=b"ok"):
            return (b"HTTP/1.1 200 OK\r\nX-E2E-Request-ID: " + request_id.encode()
                    + b"\r\n\r\n" + payload)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, request_id in (("heap", ids[1]), ("code", ids[2])):
                (directory / f"{name}.json").write_text(json.dumps({"consumers": []}))
                (directory / f"{name}.response.http").write_bytes(raw_response(request_id))
            final_raw = raw_response(ids[3], body)
            (directory / "final.response.http").write_bytes(final_raw)
            (directory / "final.response.body").write_bytes(body)
            (directory / "final.response.headers.json").write_text(json.dumps({
                "status": 200, "headers": [["X-E2E-Request-ID", ids[3]]]}))
            (directory / "final.json").write_text(json.dumps({
                "status": 200, "response_incomplete": False, "execution_proof_verified": True,
                "response_sha256": hashlib.sha256(final_raw).hexdigest(),
                "response_body_sha256": hashlib.sha256(body).hexdigest()}))
            stdout = json.dumps({"stage": "final", "nonce": nonce,
                                 "execution_proof_verified": True}) + "\n"
            logs = [{"request_id": request_id, "method": "GET" if index == 0 else "POST",
                     "uri": "/php-version.php", "status": "200"}
                    for index, request_id in enumerate(ids)]
            correlated, proof, health, final_id = e2e.check_poc_evidence(directory, stdout, logs)
            self.assertEqual((len(correlated), proof, health, final_id), (3, True, 1, ids[3]))
            with self.assertRaises(e2e.E2EFailure):
                e2e.check_poc_evidence(directory, stdout, logs + [{
                    "request_id": f"{5:032x}", "method": "POST", "uri": "/php-version.php", "status": "200"}])
            (directory / "final.response.body").write_bytes(b"forged")
            with self.assertRaises(e2e.E2EFailure):
                e2e.check_poc_evidence(directory, stdout, logs)

    def test_poc_port_must_belong_to_owned_nginx_container(self):
        def inspect(port):
            return subprocess.CompletedProcess([], 0,
                json.dumps({"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}), "")
        with patch.object(e2e.subprocess, "run", return_value=inspect(18167)):
            e2e.verify_nginx_port("nginx", 18167)
            with self.assertRaises(e2e.E2EFailure):
                e2e.verify_nginx_port("nginx", 18168)


if __name__ == "__main__":
    unittest.main()
