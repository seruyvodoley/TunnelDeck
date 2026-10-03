#!/usr/bin/env python3
"""TunnelDeck Agent 2.0: read-only telemetry collector and versioned JSON API."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path

VERSION = "2.0.0"
SCHEMA_VERSION = 1
DEFAULT_DB = Path("/var/lib/tunneldeck/telemetry.sqlite3")
RETENTION_SECONDS = 7 * 86400
SECRET_RE = re.compile(r"(?i)(privatekey|presharedkey|password|authorization|cookie|token)\s*[:=]\s*\S+")


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def utc_text(value):
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value):
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def stable_id(kind, timestamp, component=""):
    return hashlib.sha256(f"{kind}\0{timestamp:.6f}\0{component}".encode()).hexdigest()


def sanitized(value):
    if isinstance(value, dict):
        forbidden = {"privatekey", "presharedkey", "password", "authorization", "cookie", "token"}
        if any(str(key).replace("_", "").lower() in forbidden for key in value):
            raise ValueError("collector output contains forbidden secret material")
        for nested in value.values(): sanitized(nested)
    elif isinstance(value, list):
        for nested in value: sanitized(nested)
    text = json.dumps(value, sort_keys=True)
    if SECRET_RE.search(text):
        raise ValueError("collector output contains forbidden secret material")
    return value


class TelemetryDB:
    def __init__(self, path=DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS samples(id TEXT PRIMARY KEY,timestamp REAL NOT NULL,payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS samples_time ON samples(timestamp);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,timestamp REAL NOT NULL,component TEXT NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS events_time_component ON events(timestamp,component);
        CREATE TABLE IF NOT EXISTS peers(id TEXT PRIMARY KEY,timestamp REAL NOT NULL,peer_id TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS peers_time_peer ON peers(timestamp,peer_id);
        CREATE TABLE IF NOT EXISTS adguard(id TEXT PRIMARY KEY,timestamp REAL NOT NULL,payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS adguard_time ON adguard(timestamp);
        """)
        self.db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('schemaVersion',?)", (str(SCHEMA_VERSION),))
        self.db.commit()

    def close(self):
        self.db.close()

    def record(self, snapshot, now=None):
        now = now or utc_now()
        stamp = now.timestamp()
        snapshot = sanitized(snapshot)
        previous = self.latest("samples")
        identifier = stable_id("sample", stamp)
        self.db.execute("INSERT OR IGNORE INTO samples VALUES(?,?,?)", (identifier, stamp, json.dumps(snapshot, sort_keys=True)))
        for peer in snapshot.get("wireguard", {}).get("peers", []):
            peer_id = peer.get("publicIdentifier", "")
            self.db.execute("INSERT OR IGNORE INTO peers VALUES(?,?,?,?)", (stable_id("peer", stamp, peer_id), stamp, peer_id, json.dumps(peer, sort_keys=True)))
        if snapshot.get("adguard"):
            self.db.execute("INSERT OR IGNORE INTO adguard VALUES(?,?,?)", (stable_id("adguard", stamp), stamp, json.dumps(snapshot["adguard"], sort_keys=True)))
        if previous:
            old = previous["payload"].get("services", {})
            for component, state in snapshot.get("services", {}).items():
                if old.get(component) != state:
                    payload = {"from": old.get(component, "unknown"), "to": state}
                    self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)", (stable_id("transition", stamp, component), stamp, component, "service-transition", json.dumps(payload)))
        self.prune(stamp)
        self.db.commit()
        return identifier

    def lifecycle(self, kind, now=None):
        stamp = (now or utc_now()).timestamp()
        self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)", (stable_id("lifecycle", stamp, kind), stamp, "agent", "agent-lifecycle", json.dumps({"event": kind})))
        self.db.commit()

    def prune(self, now):
        cutoff = now - RETENTION_SECONDS
        for table in ("samples", "events", "peers", "adguard"):
            self.db.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))

    def latest(self, table):
        row = self.db.execute(f"SELECT rowid,* FROM {table} ORDER BY timestamp DESC LIMIT 1").fetchone()
        return self._row(row) if row else None

    def query(self, table, since=None, until=None, limit=1000, cursor=0):
        if table not in {"samples", "events", "peers", "adguard"}:
            raise ValueError("invalid telemetry table")
        clauses, args = ["rowid > ?"], [max(0, int(cursor))]
        if since:
            clauses.append("timestamp >= ?"); args.append(parse_utc(since))
        if until:
            clauses.append("timestamp <= ?"); args.append(parse_utc(until))
        args.append(max(1, min(int(limit), 10000)))
        rows = self.db.execute(f"SELECT rowid,* FROM {table} WHERE {' AND '.join(clauses)} ORDER BY rowid LIMIT ?", args).fetchall()
        values = [self._row(row) for row in rows]
        return {"schemaVersion": SCHEMA_VERSION, "agentVersion": VERSION, "items": values, "nextCursor": rows[-1]["rowid"] if rows else int(cursor)}

    @staticmethod
    def _row(row):
        value = dict(row)
        value["timestamp"] = utc_text(dt.datetime.fromtimestamp(value["timestamp"], dt.timezone.utc))
        if "payload" in value:
            value["payload"] = json.loads(value["payload"])
        return value


def command(arguments):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=15, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def collect_snapshot():
    services = {}
    units = ["wg-quick@wg0.service", "AdGuardHome.service", "antizapret.service"]
    for unit in units:
        services[unit] = command(["systemctl", "is-active", unit]) or "unknown"
    peers = []
    for line in command(["sudo", "-n", "/usr/bin/wg", "show", "all", "dump"]).splitlines():
        fields = line.split("\t")
        if len(fields) >= 9:
            peers.append({"publicIdentifier": fields[1], "latestHandshake": int(fields[5] or 0), "rx": int(fields[6] or 0), "tx": int(fields[7] or 0)})
    memory_text = command(["free", "-b"]); disk_text = command(["df", "-P", "-B1", "/"])
    memory = memory_percent(memory_text); disk = disk_percent(disk_text)
    listeners = command(["ss", "-H", "-lntu"])
    return sanitized({
        "cpuPercent": 0.0, "memoryPercent": memory, "diskPercent": disk, "pingMilliseconds": None,
        "vpsState": "online", "wireGuardState": state_value(services.get("wg-quick@wg0.service")), "adGuardState": state_value(services.get("AdGuardHome.service")), "antiZapretState": state_value(services.get("antizapret.service")),
        "publicDNSExposed": False, "publicListeners": listener_keys(listeners),
        "system": {"uptime": command(["uptime", "-p"]), "load": command(["cat", "/proc/loadavg"]), "memory": memory_text, "disk": disk_text, "kernel": command(["uname", "-sr"])},
        "network": {"interfaces": command(["ip", "-j", "address"]), "routes": command(["ip", "-j", "route"]), "listeners": listeners, "firewallEvidence": command(["sudo", "-n", "/usr/sbin/nft", "list", "ruleset"])},
        "wireguard": {"peers": peers}, "services": services,
        "security": {"sshPolicy": ssh_policy(), "configurationHashes": safe_hashes()},
    })


def state_value(value): return "online" if value == "active" else "offline" if value in {"inactive", "failed"} else "unknown"
def memory_percent(text):
    try:
        parts = next(line for line in text.splitlines() if line.startswith("Mem:")).split(); return round((int(parts[1])-int(parts[6]))*100/int(parts[1]), 2)
    except (StopIteration, ValueError, ZeroDivisionError, IndexError): return 0.0
def disk_percent(text):
    try: return float(text.splitlines()[-1].split()[4].rstrip("%"))
    except (ValueError, IndexError): return 0.0
def listener_keys(text):
    return sorted({f"{parts[0].lower()}:{parts[4].rsplit(':',1)[-1]}" for line in text.splitlines() if len(parts := line.split()) >= 5})


def safe_hashes():
    paths = [Path("/etc/wireguard/wg0.conf"), Path("/opt/AdGuardHome/AdGuardHome.yaml")]
    hashes = {}
    for path in paths:
        output = command(["sudo", "-n", "/usr/bin/sha256sum", str(path)])
        if output: hashes[str(path)] = output.split()[0]
    return hashes


def ssh_policy():
    allowed = {"port", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "permitrootlogin", "permitemptypasswords", "maxauthtries", "maxsessions", "x11forwarding", "allowtcpforwarding"}
    return {parts[0]: " ".join(parts[1:]) for line in command(["sshd", "-T"]).splitlines() if (parts := line.split()) and parts[0] in allowed}


def envelope(data):
    return {"schemaVersion": SCHEMA_VERSION, "agentVersion": VERSION, **data}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("agent-version", "agent-status", "telemetry-summary", "telemetry-latest", "collect"):
        sub.add_parser(name)
    for name in ("telemetry-samples", "telemetry-events", "telemetry-peers", "telemetry-adguard"):
        item = sub.add_parser(name); item.add_argument("--since"); item.add_argument("--until"); item.add_argument("--limit", type=int, default=1000); item.add_argument("--cursor", type=int, default=0)
    args = parser.parse_args(argv)
    db = TelemetryDB(args.db)
    try:
        if args.action == "agent-version": result = envelope({})
        elif args.action == "agent-status":
            latest=db.latest("samples");lag=None if not latest else max(0,utc_now().timestamp()-parse_utc(latest["timestamp"]));health="unknown" if latest is None else "stale" if lag>180 else "healthy"
            result = envelope({"status": "online", "agentHealth":health,"telemetryLag":lag,"lastAgentSampleAt":None if latest is None else latest["timestamp"],"latest": latest})
        elif args.action == "telemetry-summary": result = envelope({name: db.db.execute(f"SELECT count(*) FROM {name}").fetchone()[0] for name in ("samples", "events", "peers", "adguard")})
        elif args.action == "telemetry-latest": result = envelope({"sample": db.latest("samples")})
        elif args.action == "collect": result = envelope({"id": db.record(collect_snapshot())})
        else: result = db.query(args.action.removeprefix("telemetry-"), args.since, args.until, args.limit, args.cursor)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
