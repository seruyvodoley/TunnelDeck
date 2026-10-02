import importlib.machinery
import importlib.util
import pathlib
import tempfile
import unittest

path = pathlib.Path(__file__).parents[1] / "ServerHelper" / "tunneldeck-helper"
loader = importlib.machinery.SourceFileLoader("tunneldeck_helper", str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class HelperValidationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
