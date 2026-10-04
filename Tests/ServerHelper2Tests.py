import importlib.util
import pathlib
import tempfile
import unittest
from types import SimpleNamespace

PATH = pathlib.Path(__file__).parents[1] / "ServerHelper2" / "tunneldeck_helper2.py"
spec = importlib.util.spec_from_file_location("tunneldeck_helper2", PATH); helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)


class Adapter:
    def preview(self, request): return request
    def precheck(self, request): return ["ok"]
    def backup(self, request): return "backup"
    def apply(self, request): return ["fixture"]
    def postcheck(self, request): return ["healthy"]
    def rollback(self, backup): self.rolled_back = True
    def validate_rollback(self, request): return None


class Helper2Tests(unittest.TestCase):
    def test_capabilities_and_allowlist(self):
        self.assertEqual(helper.helper_info()["protocolVersion"], 2); self.assertIn("transaction-v2", helper.helper_info()["capabilities"])
        self.assertEqual(helper.validate_unit("AdGuardHome.service"), "AdGuardHome.service")
        with self.assertRaises(helper.HelperError): helper.validate_unit("ssh.service")
        with self.assertRaises(helper.HelperError): helper.main(["service", "invalid", "AdGuardHome.service"])

    def test_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(helper.HelperError): helper.safe_child(directory, "../escape")

    def test_preview_and_success(self):
        adapter = Adapter(); engine = helper.TransactionEngine("fixture", adapter)
        self.assertEqual(engine.run({}, False)["result"], "preview"); self.assertEqual(engine.run({}, True)["result"], "success")

    def test_postcheck_failure_rolls_back(self):
        adapter = Adapter(); adapter.postcheck = lambda request: (_ for _ in ()).throw(helper.HelperError("failed"))
        result = helper.TransactionEngine("fixture", adapter).run({}, True)
        self.assertEqual(result["rollbackStatus"], "success"); self.assertTrue(adapter.rolled_back)
        self.assertEqual(helper.exit_code(result), helper.EXIT_RUNTIME_FAILURE)

    def test_rollback_failure_has_distinct_nonzero_exit(self):
        adapter = Adapter(); adapter.apply = lambda request: (_ for _ in ()).throw(helper.HelperError("apply failed")); adapter.rollback = lambda backup: (_ for _ in ()).throw(helper.HelperError("rollback failed"))
        result = helper.TransactionEngine("fixture", adapter).run({}, True)
        self.assertEqual(result["rollbackStatus"], "failed")
        self.assertEqual(helper.exit_code(result), helper.EXIT_ROLLBACK_FAILURE)

    def test_ssh_and_firewall_are_preview_only(self):
        self.assertEqual(helper.main(["ssh-hardening"]), 0); self.assertEqual(helper.main(["firewall-rule"]), 0)
        with self.assertRaises(helper.HelperError): helper.main(["ssh-hardening", "--apply"])

    def test_allowlisted_service_transaction(self):
        responses=iter([SimpleNamespace(stdout="active\n",stderr="",returncode=0),SimpleNamespace(stdout="",stderr="",returncode=0),SimpleNamespace(stdout="active\n",stderr="",returncode=0)])
        adapter=helper.ServiceAdapter(runner=lambda arguments:next(responses));result=helper.TransactionEngine("service",adapter).run({"action":"restart","unit":"AdGuardHome.service"},True)
        self.assertEqual(result["result"],"success")


if __name__ == "__main__": unittest.main()
