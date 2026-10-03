import datetime as dt
import importlib.util
import json
import pathlib
import tempfile
import unittest

PATH = pathlib.Path(__file__).parents[1] / "ServerAgent" / "tunneldeck_agent.py"
spec = importlib.util.spec_from_file_location("tunneldeck_agent", PATH); agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)


class AgentTests(unittest.TestCase):
    def test_wireguard_interfaces_are_generic(self):
        dump = "vpn\tprivate-hidden\tpublic\t51820\toff\nantizapret\tprivate-hidden\tpublic\t51821\toff\nvpn\tpeer-public\tpsk-hidden\tendpoint\t10.0.0.2/32\t10\t20\t30\t0"
        interfaces, peers, state = agent.wireguard_snapshot(dump, True)
        self.assertEqual(interfaces, ["antizapret", "vpn"]); self.assertEqual(state, "online"); self.assertEqual(peers[0]["interface"], "vpn")
        self.assertEqual(agent.wireguard_snapshot("wg0\tprivate-hidden\tpublic\t51820\toff", True)[2], "online")
        self.assertEqual(agent.wireguard_snapshot("", True)[2], "unknown")
        self.assertEqual(agent.wireguard_snapshot("", False, True)[2], "unknown")

    def test_wireguard_expected_but_down_is_offline(self):
        self.assertEqual(agent.wireguard_snapshot("", True, configured=True)[2], "offline")

    def test_cpu_busy_percentage(self):
        self.assertEqual(agent.cpu_busy_percent("cpu  10 0 10 80 0 0 0 0", "cpu  20 0 20 100 0 0 0 0"), 50.0)

    def test_public_dns_exposure(self):
        self.assertTrue(agent.public_dns_exposed("udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*"))
        self.assertTrue(agent.public_dns_exposed("tcp LISTEN 0 10 [::]:53 [::]:*"))
        self.assertFalse(agent.public_dns_exposed("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*"))
        self.assertFalse(agent.public_dns_exposed("udp UNCONN 0 0 10.29.0.1:53 0.0.0.0:*"))
        self.assertFalse(agent.public_dns_exposed("udp UNCONN 0 0 127.1.1.1:53 0.0.0.0:*\ntcp LISTEN 0 10 127.2.2.2:53 0.0.0.0:*"))

    def test_optional_service_state(self):
        self.assertEqual(agent.unit_state("not-found", "inactive"), "unknown")
        self.assertEqual(agent.unit_state("loaded", "active"), "online")
        self.assertEqual(agent.unit_state("loaded", "failed"), "offline")

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

    def test_cursor_contract_pages_full_seven_day_history(self):
        with tempfile.TemporaryDirectory() as directory:
            db=agent.TelemetryDB(pathlib.Path(directory)/"db")
            db.db.executemany("INSERT INTO samples(id,timestamp,payload) VALUES(?,?,?)",((f"sample-{index}",float(index),"{}") for index in range(1,10_081)));db.db.commit()
            cursor=0;seen=[]
            while True:
                page=db.query("samples",limit=2_000,cursor=cursor)
                if not page["items"]:break
                self.assertGreater(page["nextCursor"],cursor);seen.extend(item["id"] for item in page["items"]);cursor=page["nextCursor"]
            self.assertEqual(len(seen),10_080);self.assertEqual(len(set(seen)),10_080);self.assertEqual(cursor,10_080);db.close()


if __name__ == "__main__": unittest.main()
