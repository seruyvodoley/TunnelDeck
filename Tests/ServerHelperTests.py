import importlib.machinery
import importlib.util
import pathlib
import tempfile
import unittest
import hashlib
import json

path = pathlib.Path(__file__).parents[1] / "ServerHelper" / "tunneldeck-helper"
loader = importlib.machinery.SourceFileLoader("tunneldeck_helper", str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class HelperValidationTests(unittest.TestCase):
    def make_backup(self, root, identifier="safe_backup", target="/etc/wireguard/wg0.conf", relative="etc/wireguard/wg0.conf", content=b"[Interface]\nAddress = 10.8.0.1/24\n"):
        directory = pathlib.Path(root) / identifier
        source = directory / relative
        source.parent.mkdir(parents=True)
        source.write_bytes(content)
        manifest = {"timestamp": "2026-01-01T00:00:00Z", "operation": "test", "files": [{"path": target, "backupPath": relative, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}]}
        (directory / "manifest.json").write_text(json.dumps(manifest))
        return directory
    def test_peer_name(self):
        self.assertEqual(helper.validate_name("MacBook_01"), "MacBook_01")
        for invalid in ["", "bad name", "../escape", "x" * 49]:
            with self.assertRaises(helper.HelperError):
                helper.validate_name(invalid)

    def test_peer_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            original = helper.WG_CONFIG
            helper.WG_CONFIG = pathlib.Path(directory) / "wg0.conf"
            helper.WG_CONFIG.write_text("[Interface]\nAddress = 10.8.0.1/24\n")
            try:
                self.assertEqual(helper.validate_ip("10.8.0.2"), "10.8.0.2")
                for invalid in ["10.8.0.1", "10.8.0.255", "192.0.2.2", "not-ip"]:
                    with self.assertRaises((helper.HelperError, ValueError)):
                        helper.validate_ip(invalid)
            finally:
                helper.WG_CONFIG = original

    def test_allowed_ips(self):
        self.assertEqual(helper.validate_allowed_ips("0.0.0.0/0"), "0.0.0.0/0")
        self.assertEqual(helper.validate_allowed_ips("10.0.0.7/24"), "10.0.0.0/24")

    def test_peer_block_exact_match(self):
        config = "[Interface]\nPrivateKey = hidden\n\n[Peer]\nPublicKey = AAA=\nAllowedIPs = 10.0.0.2/32\n\n[Peer]\nPublicKey = BBB=\nAllowedIPs = 10.0.0.3/32\n"
        prefix, blocks = helper.peer_blocks(config)
        self.assertIn("[Interface]", prefix)
        self.assertEqual([helper.block_public_key(block) for block in blocks], ["AAA=", "BBB="])

    def test_managed_block_exact_removal(self):
        original = "[Interface]\nPrivateKey = hidden\n"
        key = "A" * 43 + "="
        managed = original + f"\n# TunnelDeck BEGIN {key}\n# Name: Test\n[Peer]\nPublicKey = {key}\nAllowedIPs = 10.8.0.6/32\n# TunnelDeck END {key}\n"
        self.assertEqual(helper.remove_managed_block_exact(managed, key), original)

    def test_backup_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            original = helper.BACKUP_ROOT
            helper.BACKUP_ROOT = pathlib.Path(directory)
            try:
                for number in range(18):
                    (helper.BACKUP_ROOT / f"2026-01-{number + 1:02d}_scheduled").mkdir()
                helper.cleanup_backups(14)
                self.assertEqual(len(list(helper.BACKUP_ROOT.iterdir())), 14)
            finally:
                helper.BACKUP_ROOT = original

    def test_restore_preview_and_hash_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            original_root, original_wg = helper.BACKUP_ROOT, helper.WG_CONFIG
            helper.BACKUP_ROOT = pathlib.Path(directory) / "backups"; helper.BACKUP_ROOT.mkdir()
            helper.WG_CONFIG = pathlib.Path(directory) / "wg0.conf"; helper.WG_CONFIG.write_text("[Interface]\nAddress = 10.8.0.1/24\n# current\n")
            try:
                self.make_backup(helper.BACKUP_ROOT, target=str(helper.WG_CONFIG))
                preview = helper.restore_preview("safe_backup", "wireguard")
                self.assertTrue(preview["verified"]); self.assertTrue(preview["files"][0]["changed"])
            finally: helper.BACKUP_ROOT, helper.WG_CONFIG = original_root, original_wg

    def test_restore_rejects_hash_mismatch_and_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            original = helper.BACKUP_ROOT; helper.BACKUP_ROOT = pathlib.Path(directory); backup = self.make_backup(directory)
            try:
                (backup / "etc/wireguard/wg0.conf").write_text("tampered")
                with self.assertRaises(helper.HelperError): helper.load_verified_manifest("safe_backup")
                manifest = json.loads((backup / "manifest.json").read_text()); manifest["files"][0]["backupPath"] = "../escape"; (backup / "manifest.json").write_text(json.dumps(manifest))
                with self.assertRaises(helper.HelperError): helper.load_verified_manifest("safe_backup")
            finally: helper.BACKUP_ROOT = original

    def test_restore_rejects_symlink_and_unknown_target(self):
        with tempfile.TemporaryDirectory() as directory:
            original = helper.BACKUP_ROOT; helper.BACKUP_ROOT = pathlib.Path(directory); backup = self.make_backup(directory, target="/etc/shadow")
            try:
                with self.assertRaises(helper.HelperError): helper.restore_entries("safe_backup", "wireguard")
                source = backup / "etc/wireguard/wg0.conf"; source.unlink(); source.symlink_to("/etc/hosts")
                with self.assertRaises(helper.HelperError): helper.load_verified_manifest("safe_backup")
            finally: helper.BACKUP_ROOT = original


if __name__ == "__main__":
    unittest.main()
