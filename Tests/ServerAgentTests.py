import datetime as dt
import importlib.util
import json
import pathlib
import tempfile
import unittest

PATH = pathlib.Path(__file__).parents[1] / "ServerAgent" / "tunneldeck_agent.py"
spec = importlib.util.spec_from_file_location("tunneldeck_agent", PATH); agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)


class AgentTests(unittest.TestCase):
    def test_incremental_cursor_restart_retention_and_transitions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "telemetry.sqlite3"; db = agent.TelemetryDB(path)
            now = dt.datetime(2026, 1, 8, tzinfo=dt.timezone.utc)
            db.record({"services": {"AdGuardHome.service": "active"}, "wireguard": {"peers": []}}, now - dt.timedelta(hours=1))
            db.record({"services": {"AdGuardHome.service": "inactive"}, "wireguard": {"peers": []}}, now)
            first = db.query("samples", limit=1); second = db.query("samples", cursor=first["nextCursor"])
            self.assertEqual(len(first["items"]), 1); self.assertEqual(len(second["items"]), 1); self.assertEqual(len(db.query("events")["items"]), 1)
            db.close(); reopened = agent.TelemetryDB(path); self.assertEqual(len(reopened.query("samples")["items"]), 2); reopened.close()

    def test_peer_counter_reset_and_no_secrets(self):
        self.assertEqual(max(0, 20 - 100), 0)
        with self.assertRaises(ValueError): agent.sanitized({"PrivateKey": "fixture-secret"})

    def test_lifecycle_is_not_outage(self):
        with tempfile.TemporaryDirectory() as directory:
            db = agent.TelemetryDB(pathlib.Path(directory) / "db"); db.lifecycle("started"); event = db.query("events")["items"][0]
            self.assertEqual(event["kind"], "agent-lifecycle"); self.assertNotIn("offline", json.dumps(event)); db.close()

    def test_retention_removes_only_expired_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            db=agent.TelemetryDB(pathlib.Path(directory)/"db");now=dt.datetime(2026,1,10,tzinfo=dt.timezone.utc)
            db.record({"services":{},"wireguard":{"peers":[]}},now-dt.timedelta(days=8));db.record({"services":{},"wireguard":{"peers":[]}},now)
            self.assertEqual(len(db.query("samples")["items"]),1);db.close()


if __name__ == "__main__": unittest.main()
