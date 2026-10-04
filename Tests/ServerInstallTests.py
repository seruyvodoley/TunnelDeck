import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest
from types import SimpleNamespace

ROOT=pathlib.Path(__file__).parents[1];PATH=ROOT/"ServerInstall"/"tunneldeck_install.py"
spec=importlib.util.spec_from_file_location("tunneldeck_install",PATH);installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class Result:
    def __init__(self,code=0,out=""):self.returncode=code;self.stdout=out;self.stderr=""

class FakeSystem:
    def __init__(self,fail=None,enabled=False,timer_active=False,service_active=False):self.fail=fail;self.commands=[];self.enabled_state=enabled;self.timer_active=timer_active;self.service_active=service_active
    def user(self,name):return SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid(),pw_name=name)
    def user_groups(self,name):return set()
    def enabled(self,unit):return self.enabled_state
    def active(self,unit):return self.timer_active if unit.endswith("timer")else self.service_active
    def run(self,args,check=True):
        self.commands.append(tuple(args));joined=" ".join(args)
        if self.fail and self.fail in joined:
            result=Result(1)
            if check:raise installer.InstallError(f"fixture failure: {self.fail}")
            return result
        if args[:3]==["systemctl","enable","--now"]:self.enabled_state=True;self.timer_active=True
        if args[:2]==["systemctl","enable"] and args[-1].endswith("timer"):self.enabled_state=True
        if args[:2]==["systemctl","disable"] and args[-1].endswith("timer"):self.enabled_state=False
        if args[:2]==["systemctl","start"]:
            if args[-1].endswith("timer"):self.timer_active=True
            else:self.service_active=True
        if args[:2]==["systemctl","stop"]:
            if args[-1].endswith("timer"):self.timer_active=False
            else:self.service_active=False
        return Result(0,"success\n" if "--property=Result" in args else "")

class InstallerTests(unittest.TestCase):
    def test_agent_unit_bounds_sudo_transition_and_read_evidence_capabilities(self):
        unit=(ROOT/"ServerAgent"/"tunneldeck-agent.service").read_text()
        self.assertIn("CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE CAP_NET_ADMIN",unit)
        self.assertNotIn("AmbientCapabilities=CAP_NET_ADMIN",unit)

    def make(self,system=None):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        return installer.Installer(ROOT,temporary.name,system or FakeSystem()),pathlib.Path(temporary.name)
    def seed(self,root,path,content=b"old",mode=0o600):
        target=root/path.lstrip("/");target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content);target.chmod(mode);return target

    def test_clean_first_install_success_and_permissions(self):
        engine,root=self.make();result=engine.install_agent("fixture-user")
        self.assertEqual(result["result"],"success")
        for path in installer.AGENT_FILES:self.assertTrue((root/path.lstrip("/")).is_file())
        self.assertEqual(stat.S_IMODE((root/"etc/sudoers.d/tunneldeck-agent-api").stat().st_mode),0o440)
        self.assertEqual(stat.S_IMODE((root/"var/lib/tunneldeck").stat().st_mode),0o750)

    def test_clean_first_install_failure_removes_new_files(self):
        engine,root=self.make(FakeSystem(fail="agent-version"))
        with self.assertRaises(installer.InstallError):engine.install_agent("fixture-user")
        for path in installer.AGENT_FILES:self.assertFalse((root/path.lstrip("/")).exists())
        self.assertFalse((root/"var/lib/tunneldeck").exists())

    def test_failed_first_install_removes_created_agent_account(self):
        class MissingAgent(FakeSystem):
            def __init__(self):super().__init__(fail="agent-version");self.agent_exists=False
            def user(self,name):
                if name==installer.AGENT_USER and not self.agent_exists:return None
                return super().user(name)
            def run(self,args,check=True):
                if args[0]=="useradd":self.agent_exists=True;return Result()
                if args[0]=="userdel":self.agent_exists=False;self.commands.append(tuple(args));return Result()
                return super().run(args,check)
        system=MissingAgent();engine,_=self.make(system)
        with self.assertRaises(installer.InstallError):engine.install_agent("fixture-user")
        self.assertFalse(system.agent_exists);self.assertIn(("userdel",installer.AGENT_USER),system.commands)

    def test_upgrade_failure_restores_binary_unit_sudoers_modes_and_states(self):
        system=FakeSystem(fail="agent-version",enabled=True,timer_active=True,service_active=True);engine,root=self.make(system)
        expected={}
        for index,path in enumerate(installer.AGENT_FILES):expected[path]=f"old-{index}".encode();self.seed(root,path,expected[path],0o600+index)
        with self.assertRaises(installer.InstallError):engine.install_agent("fixture-user")
        for index,(path,content) in enumerate(expected.items()):
            target=root/path.lstrip("/");self.assertEqual(target.read_bytes(),content);self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600+index)
        self.assertTrue(system.enabled_state);self.assertTrue(system.timer_active);self.assertTrue(system.service_active)

    def test_upgrade_success_replaces_candidate_but_not_legacy_helper(self):
        engine,root=self.make();legacy=self.seed(root,"/usr/local/libexec/tunneldeck-helper",b"legacy-1.2.1",0o750);old=self.seed(root,"/usr/local/libexec/tunneldeck-helper2",b"old-helper2",0o700)
        result=engine.install_helper2();self.assertEqual(result["result"],"success");self.assertEqual(legacy.read_bytes(),b"legacy-1.2.1");self.assertNotEqual(old.read_bytes(),b"old-helper2")

    def test_visudo_failure_prevents_any_install(self):
        engine,root=self.make(FakeSystem(fail="visudo"))
        with self.assertRaises(installer.InstallError):engine.install_agent("fixture-user")
        for path in installer.AGENT_FILES:self.assertFalse((root/path.lstrip("/")).exists())

    def test_service_verification_failure_rolls_back(self):
        engine,root=self.make(FakeSystem(fail="--property=Result"));old=self.seed(root,"/usr/local/libexec/tunneldeck-agent",b"old")
        with self.assertRaises(installer.InstallError):engine.install_agent("fixture-user")
        self.assertEqual(old.read_bytes(),b"old")

    def test_timer_verification_failure_rolls_back(self):
        class TimerFailure(FakeSystem):
            def active(self,unit):return False if unit.endswith("timer")else super().active(unit)
        engine,root=self.make(TimerFailure());old=self.seed(root,"/etc/systemd/system/tunneldeck-agent.timer",b"old-timer")
        with self.assertRaises(installer.InstallError):engine.install_agent("fixture-user")
        self.assertEqual(old.read_bytes(),b"old-timer")

    def test_sudoers_is_exact_and_excludes_collect_and_wrong_path(self):
        engine,_=self.make();text=engine.candidate("ServerAgent/tunneldeck-agent.sudoers","fixture-user").decode()
        self.assertIn("fixture-user ALL=(tunneldeck-agent)",text);self.assertNotIn(" collect",text);self.assertNotIn("/tmp/",text)
        self.assertEqual(text.count("/usr/local/libexec/tunneldeck-agent"),8)

    def test_management_user_has_no_direct_database_access_by_design(self):
        engine,root=self.make();engine.install_agent("fixture-user");data=root/"var/lib/tunneldeck"
        self.assertEqual(stat.S_IMODE(data.stat().st_mode),0o750)
        self.assertNotIn("fixture-user",data.read_text() if data.is_file() else "")

    def test_uninstall_preserves_data_unless_explicitly_purged(self):
        engine,root=self.make();self.seed(root,"/var/lib/tunneldeck/telemetry.sqlite3",b"history");self.seed(root,"/etc/sudoers.d/tunneldeck-agent-api")
        engine.uninstall_agent(False);self.assertTrue((root/"var/lib/tunneldeck/telemetry.sqlite3").exists());self.assertFalse((root/"etc/sudoers.d/tunneldeck-agent-api").exists())
        engine.uninstall_agent(True);self.assertFalse((root/"var/lib/tunneldeck").exists())

if __name__=="__main__":unittest.main()
