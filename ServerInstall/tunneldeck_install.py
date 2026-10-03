#!/usr/bin/env python3
"""Transactional installer for side-by-side TunnelDeck server components."""
import argparse, grp, hashlib, json, os, platform, pwd, re, shutil, stat, subprocess, sys, tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

USER_RE=re.compile(r"^[a-z_][a-z0-9_-]{0,31}$");AGENT_USER="tunneldeck-agent"
AGENT_FILES={
 "/usr/local/libexec/tunneldeck-agent":("ServerAgent/tunneldeck_agent.py",0o755),
 "/etc/systemd/system/tunneldeck-agent.service":("ServerAgent/tunneldeck-agent.service",0o644),
 "/etc/systemd/system/tunneldeck-agent.timer":("ServerAgent/tunneldeck-agent.timer",0o644),
 "/etc/sudoers.d/tunneldeck-agent-api":("ServerAgent/tunneldeck-agent.sudoers",0o440),
 "/etc/sudoers.d/tunneldeck-agent-collector":("ServerAgent/tunneldeck-agent-collector.sudoers",0o440)}

class InstallError(RuntimeError):pass
@dataclass
class FileState: exists:bool;content:bytes=b"";mode:int=0;uid:int=0;gid:int=0;sha256:Optional[str]=None
@dataclass
class DirectoryState: exists:bool;mode:int=0;uid:int=0;gid:int=0
class System:
 def run(self,args,check=True):
  result=subprocess.run(args,text=True,capture_output=True,check=False)
  if check and result.returncode:raise InstallError(result.stderr.strip() or result.stdout.strip() or f"command failed: {args[0]}")
  return result
 def enabled(self,unit):return self.run(["systemctl","is-enabled",unit],False).returncode==0
 def active(self,unit):return self.run(["systemctl","is-active",unit],False).returncode==0
 def user(self,name):
  try:return pwd.getpwnam(name)
  except KeyError:return None
 def user_groups(self,username):return{entry.gr_name for entry in grp.getgrall()if username in entry.gr_mem}

class Installer:
 def __init__(self,source_root=None,root="/",system=None):self.source_root=Path(source_root or Path(__file__).resolve().parents[1]);self.root=Path(root);self.system=system or System()
 def target(self,path):return self.root/path.lstrip("/")
 @staticmethod
 def digest(data):return hashlib.sha256(data).hexdigest()
 def snapshot_file(self,path):
  target=self.target(path)
  if not target.exists() and not target.is_symlink():return FileState(False)
  if target.is_symlink() or not target.is_file():raise InstallError(f"unsafe target: {path}")
  info=target.stat();content=target.read_bytes();return FileState(True,content,stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid,self.digest(content))
 def snapshot_directory(self,path):
  target=self.target(path)
  if not target.exists():return DirectoryState(False)
  if target.is_symlink()or not target.is_dir():raise InstallError(f"unsafe directory: {path}")
  info=target.stat();return DirectoryState(True,stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid)
 def atomic_write(self,target,content,mode,uid=0,gid=0):
  target.parent.mkdir(parents=True,exist_ok=True);fd,temporary=tempfile.mkstemp(prefix=".tunneldeck-stage-",dir=target.parent)
  try:
   with os.fdopen(fd,"wb") as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
   os.chmod(temporary,mode)
   if os.geteuid()==0:os.chown(temporary,uid,gid)
   if self.digest(Path(temporary).read_bytes())!=self.digest(content):raise InstallError("staged SHA-256 mismatch")
   os.replace(temporary,target)
  finally:
   if os.path.exists(temporary):os.unlink(temporary)
 def restore_file(self,path,state):
  target=self.target(path)
  if not state.exists:
   if target.exists() or target.is_symlink():target.unlink()
  else:self.atomic_write(target,state.content,state.mode,state.uid,state.gid)
 def candidate(self,relative,user=None):
  data=(self.source_root/relative).read_bytes()
  if relative.endswith("tunneldeck-agent.sudoers"):
   if not user or not USER_RE.fullmatch(user):raise InstallError("invalid management user")
   data=data.replace(b"@MANAGEMENT_USER@",user.encode())
  return data
 def validate_sudoers(self,data):
  with tempfile.NamedTemporaryFile("wb",delete=False) as stream:stream.write(data);path=stream.name
  try:return self.system.run(["visudo","-cf",path],False).returncode==0
  finally:os.unlink(path)
 def agent_candidates(self,user):
  values={target:(self.candidate(source,user),mode)for target,(source,mode)in AGENT_FILES.items()}
  compile(values["/usr/local/libexec/tunneldeck-agent"][0],"tunneldeck-agent","exec")
  if b"[Service]"not in values["/etc/systemd/system/tunneldeck-agent.service"][0]or b"[Timer]"not in values["/etc/systemd/system/tunneldeck-agent.timer"][0]:raise InstallError("invalid systemd candidate")
  for target,(content,_)in values.items():
   if not content:raise InstallError(f"empty candidate: {target}")
   if "/sudoers.d/"in target and not self.validate_sudoers(content):raise InstallError("sudoers validation failed")
  return values
 def precheck(self,action,user=None):
  checks={"rootRequiredForApply":os.geteuid()==0,"linux":platform.system()=="Linux","systemd":Path("/run/systemd/system").exists(),"freeBytes":shutil.disk_usage(self.root).free}
  for command in("python3","sudo","visudo","install","systemctl"):checks[command]=shutil.which(command)is not None
  if action in{"install-agent","upgrade-agent"}:
   checks["useradd"]=shutil.which("useradd")is not None;checks["userdel"]=shutil.which("userdel")is not None
   for path in("/usr/local/libexec","/etc/systemd/system","/etc/sudoers.d","/var/lib"):
    target=self.target(path);checks[f"target:{path}"]=target.is_dir()and os.access(target,os.W_OK)
   management=self.system.user(user)if user else None;agent=self.system.user(AGENT_USER);agent_exists=agent is not None
   outside_group=bool(user)and AGENT_USER not in self.system.user_groups(user)and(not management or not agent or management.pw_gid!=agent.pw_gid)
   checks.update(managementUserValid=bool(user and USER_RE.fullmatch(user)),managementUserExists=bool(management),managementUserIsNotAgent=user!=AGENT_USER,managementUserOutsideAgentGroup=outside_group,agentUserExists=agent_exists,agentUserProvisionable=agent_exists or(checks["useradd"]and checks["userdel"]),minimumFreeSpace=checks["freeBytes"]>=10*1024*1024)
   try:
    api=self.candidate("ServerAgent/tunneldeck-agent.sudoers",user);collector=self.candidate("ServerAgent/tunneldeck-agent-collector.sudoers")
    if not agent_exists:api=api.replace(b"(tunneldeck-agent)",b"(root)");collector=collector.replace(b"tunneldeck-agent ALL=",b"root ALL=")
    checks["sudoersCandidateValid"]=self.validate_sudoers(api)and self.validate_sudoers(collector)
   except(InstallError,OSError):checks["sudoersCandidateValid"]=False
  return checks
 @staticmethod
 def embedded_version(state):
  if not state.exists:return None
  match=re.search(rb'^VERSION\s*=\s*["\']([^"\']+)',state.content,re.MULTILINE);return match.group(1).decode()if match else None
 @staticmethod
 def ready(checks):return all(value is True for key,value in checks.items() if key not in{"rootRequiredForApply","freeBytes","agentUserExists"})
 def preview(self,action,user=None,purge=False):
  checks=self.precheck(action,user);legacy=self.snapshot_file("/usr/local/libexec/tunneldeck-helper");helper2=self.snapshot_file("/usr/local/libexec/tunneldeck-helper2")
  targets={path:{"exists":state.exists,"sha256":state.sha256,"mode":oct(state.mode)if state.exists else None,"uid":state.uid if state.exists else None,"gid":state.gid if state.exists else None}for path in AGENT_FILES for state in[self.snapshot_file(path)]}if action in{"install-agent","upgrade-agent","uninstall-agent"}else{}
  return{"action":action,"mode":"preview","ready":self.ready(checks),"checks":checks,"targets":targets,"legacyHelper":{"path":"/usr/local/libexec/tunneldeck-helper","exists":legacy.exists,"version":self.embedded_version(legacy),"sha256":legacy.sha256,"unchanged":True},"helper2":{"path":"/usr/local/libexec/tunneldeck-helper2","exists":helper2.exists,"version":self.embedded_version(helper2),"sha256":helper2.sha256},"purgeData":purge,"changesApplied":False}
 def apply(self,action,user=None,purge=False):
  checks=self.precheck(action,user)
  if os.geteuid()!=0:raise InstallError("--apply requires root")
  if not self.ready(checks):raise InstallError("precheck failed")
  if action in{"install-agent","upgrade-agent"}:return self.install_agent(user)
  if action in{"install-helper2","upgrade-helper2"}:return self.install_helper2()
  if action=="uninstall-agent":return self.uninstall_agent(purge)
  if action=="uninstall-helper2":return self.uninstall_helper2()
  raise InstallError("unsupported action")
 def install_agent(self,user):
  snapshots={path:self.snapshot_file(path)for path in AGENT_FILES};data_state=self.snapshot_directory("/var/lib/tunneldeck");enabled=self.system.enabled("tunneldeck-agent.timer");timer_active=self.system.active("tunneldeck-agent.timer");service_active=self.system.active("tunneldeck-agent.service");created_user=False
  try:
   if self.system.user(AGENT_USER)is None:self.system.run(["useradd","--system","--home-dir","/var/lib/tunneldeck","--shell","/usr/sbin/nologin",AGENT_USER]);created_user=True
   candidates=self.agent_candidates(user)
   for target,(content,mode)in candidates.items():
    self.atomic_write(self.target(target),content,mode)
   agent=self.system.user(AGENT_USER);data=self.target("/var/lib/tunneldeck");data.mkdir(parents=True,exist_ok=True);os.chmod(data,0o750)
   if os.geteuid()==0 and agent:os.chown(data,agent.pw_uid,agent.pw_gid)
   self.system.run(["systemctl","daemon-reload"]);self.system.run(["systemctl","enable","--now","tunneldeck-agent.timer"]);self.system.run(["systemctl","start","tunneldeck-agent.service"]);self.system.run(["sudo","-n","-u",AGENT_USER,"/usr/local/libexec/tunneldeck-agent","agent-version"])
   if not self.system.active("tunneldeck-agent.timer"):raise InstallError("timer verification failed")
   if self.system.run(["systemctl","show","tunneldeck-agent.service","--property=Result","--value"]).stdout.strip()!="success":raise InstallError("service verification failed")
   return{"result":"success","component":"agent","rollback":"not-required"}
  except Exception:
   for path,state in snapshots.items():self.restore_file(path,state)
   data=self.target("/var/lib/tunneldeck")
   if data_state.exists:
    os.chmod(data,data_state.mode)
    if os.geteuid()==0:os.chown(data,data_state.uid,data_state.gid)
   elif data.exists():shutil.rmtree(data)
   self.system.run(["systemctl","daemon-reload"],False);self.restore_unit("tunneldeck-agent.timer",enabled,timer_active);self.restore_unit("tunneldeck-agent.service",False,service_active)
   if created_user:self.system.run(["userdel",AGENT_USER],False)
   raise
 def restore_unit(self,unit,enabled,active):self.system.run(["systemctl","enable"if enabled else"disable",unit],False);self.system.run(["systemctl","start"if active else"stop",unit],False)
 def install_helper2(self):
  target="/usr/local/libexec/tunneldeck-helper2";snapshot=self.snapshot_file(target)
  try:
   content=self.candidate("ServerHelper2/tunneldeck_helper2.py");compile(content,"tunneldeck-helper2","exec");self.atomic_write(self.target(target),content,0o750);self.system.run([target,"helper-info"]);return{"result":"success","component":"helper2","legacyHelperChanged":False}
  except Exception:self.restore_file(target,snapshot);raise
 def uninstall_agent(self,purge=False):
  self.system.run(["systemctl","disable","--now","tunneldeck-agent.timer"],False);self.system.run(["systemctl","stop","tunneldeck-agent.service"],False)
  for path in AGENT_FILES:
   target=self.target(path)
   if target.exists()or target.is_symlink():target.unlink()
  self.system.run(["systemctl","daemon-reload"])
  if purge:
   data=self.target("/var/lib/tunneldeck")
   if data.exists():shutil.rmtree(data)
  return{"result":"success","component":"agent","dataPurged":purge}
 def uninstall_helper2(self):
  target=self.target("/usr/local/libexec/tunneldeck-helper2")
  if target.exists()or target.is_symlink():target.unlink()
  return{"result":"success","component":"helper2","legacyHelperChanged":False}

def main(argv=None):
 parser=argparse.ArgumentParser();parser.add_argument("action",choices=["install-agent","upgrade-agent","uninstall-agent","install-helper2","upgrade-helper2","uninstall-helper2"]);parser.add_argument("--management-user");mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument("--preview",action="store_true");mode.add_argument("--apply",action="store_true");parser.add_argument("--purge-data",action="store_true");args=parser.parse_args(argv);installer=Installer()
 try:result=installer.preview(args.action,args.management_user,args.purge_data)if args.preview else installer.apply(args.action,args.management_user,args.purge_data);print(json.dumps(result,sort_keys=True));return 0
 except InstallError as error:print(json.dumps({"result":"failed","error":str(error)},sort_keys=True));print(str(error),file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
