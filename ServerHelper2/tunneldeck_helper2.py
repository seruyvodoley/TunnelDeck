#!/usr/bin/env python3
"""TunnelDeck Helper 2.0 transactional, allowlisted remediation framework."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import sys
from pathlib import Path

VERSION = "2.0.0"
PROTOCOL_VERSION = 2
CAPABILITIES = ["transaction-v2", "service-actions", "verified-manifest", "ssh-preview", "firewall-preview"]
EXIT_REJECTED = 2
EXIT_RUNTIME_FAILURE = 3
EXIT_ROLLBACK_FAILURE = 4
ALLOWED_UNITS = {"wg-quick@wg0.service", "AdGuardHome.service", "antizapret.service", "wg-quick@antizapret.service", "wg-quick@vpn.service", "openvpn-server@antizapret-udp.service", "openvpn-server@vpn-udp.service"}
NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,80}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


class HelperError(RuntimeError): pass
class ProtocolArgumentParser(argparse.ArgumentParser):
    def error(self, message): raise HelperError(message)


def validate_unit(value):
    if value not in ALLOWED_UNITS: raise HelperError("unit is not allowlisted")
    return value


def validate_name(value):
    if not NAME_RE.fullmatch(value) or ".." in value: raise HelperError("invalid identifier")
    return value


def validate_interface(value):
    if not INTERFACE_RE.fullmatch(value): raise HelperError("invalid interface")
    return value


def validate_network(value):
    return str(ipaddress.ip_network(value, strict=False))


def safe_child(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts: raise HelperError("path traversal rejected")
    root = Path(root).resolve(); candidate = root / relative
    if candidate.is_symlink() or root not in candidate.resolve(strict=False).parents: raise HelperError("unsafe path")
    return candidate


class TransactionEngine:
    def __init__(self, operation, adapter): self.operation, self.adapter = validate_name(operation), adapter
    def run(self, request, apply=False):
        operation_id = str(uuid.uuid4())
        result = {"protocolVersion": PROTOCOL_VERSION, "operationID": operation_id, "operation": self.operation, "preview": self.adapter.preview(request), "backup": None, "changedFiles": [], "preChecks": self.adapter.precheck(request), "postChecks": [], "result": "preview", "rollbackStatus": "not-required", "warnings": []}
        if not apply: return result
        backup = self.adapter.backup(request); result["backup"] = backup
        try:
            result["changedFiles"] = self.adapter.apply(request)
            result["postChecks"] = self.adapter.postcheck(request)
            result["result"] = "success"
        except Exception as original:
            try:
                self.adapter.rollback(backup); self.adapter.validate_rollback(request)
                result.update(result="failed", rollbackStatus="success", warnings=[str(original)])
            except Exception as rollback:
                result.update(result="failed", rollbackStatus="failed", warnings=[str(original), str(rollback)])
        return result


class ServiceAdapter:
    def __init__(self, runner=None): self.runner=runner or self._run;self.previous=None;self.unit=None
    @staticmethod
    def _run(arguments): return subprocess.run(arguments,text=True,capture_output=True,timeout=30,check=False)
    def preview(self, request): return {"unit": validate_unit(request["unit"]), "action": request["action"]}
    def precheck(self, request):
        if request["action"] not in {"start", "stop", "restart"}: raise HelperError("invalid service action")
        validate_unit(request["unit"]); return ["unit-allowlisted"]
    def backup(self, request): self.unit=validate_unit(request["unit"]);self.previous=self.runner(["systemctl","is-active",self.unit]).stdout.strip();return f"service-state:{self.previous or 'unknown'}"
    def apply(self, request):
        result=self.runner(["systemctl",request["action"],self.unit])
        if result.returncode != 0: raise HelperError(result.stderr.strip() or "service action failed")
        return []
    def postcheck(self, request):
        state=self.runner(["systemctl","is-active",self.unit]).stdout.strip();expected="inactive" if request["action"]=="stop" else "active"
        if state != expected: raise HelperError(f"post-check expected {expected}, got {state or 'unknown'}")
        return [f"service-state:{state}"]
    def rollback(self, backup):
        action="start" if self.previous=="active" else "stop";result=self.runner(["systemctl",action,self.unit])
        if result.returncode != 0: raise HelperError("service rollback failed")
    def validate_rollback(self, request):
        state=self.runner(["systemctl","is-active",self.unit]).stdout.strip()
        if state != self.previous: raise HelperError("service rollback validation failed")


def verify_manifest(root, identifier):
    directory = safe_child(root, validate_name(identifier)); manifest_path = safe_child(directory, "manifest.json")
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest.get("files", []):
        source = safe_child(directory, entry["backupPath"])
        if hashlib.sha256(source.read_bytes()).hexdigest() != entry["sha256"]: raise HelperError("backup hash mismatch")
    return manifest


def helper_info(): return {"version": VERSION, "protocolVersion": PROTOCOL_VERSION, "capabilities": CAPABILITIES}
def exit_code(output):
    if output.get("result") != "failed": return 0
    return EXIT_ROLLBACK_FAILURE if output.get("rollbackStatus") == "failed" else EXIT_RUNTIME_FAILURE


def main(argv=None):
    parser = ProtocolArgumentParser(); sub = parser.add_subparsers(dest="command", required=True, parser_class=ProtocolArgumentParser)
    sub.add_parser("helper-info")
    service = sub.add_parser("service"); service.add_argument("service_action", choices=["start", "stop", "restart"]); service.add_argument("unit"); service.add_argument("--apply", action="store_true")
    ssh = sub.add_parser("ssh-hardening"); ssh.add_argument("--apply", action="store_true")
    firewall = sub.add_parser("firewall-rule"); firewall.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "helper-info": output = helper_info()
    elif args.command == "service": output = TransactionEngine("service", ServiceAdapter()).run({"action": args.service_action, "unit": args.unit}, args.apply)
    else:
        if args.apply: raise HelperError("apply adapter not installed; preview-only safety boundary")
        output = {"protocolVersion": PROTOCOL_VERSION, "operationID": str(uuid.uuid4()), "operation": args.command, "preview": True, "backup": None, "changedFiles": [], "preChecks": ["independent-access-required"], "postChecks": [], "result": "preview", "rollbackStatus": "not-required", "warnings": ["Deployment adapter intentionally absent"]}
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return exit_code(output)


if __name__ == "__main__":
    try: raise SystemExit(main())
    except HelperError as error:
        print(json.dumps({"protocolVersion": PROTOCOL_VERSION, "result": "rejected", "error": str(error)}))
        print(str(error), file=sys.stderr)
        raise SystemExit(EXIT_REJECTED)
