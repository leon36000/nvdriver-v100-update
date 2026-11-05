#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect a read-only NVIDIA package/library and kernel-build inventory from PC3's V100 guest.

The transport reuses the existing pinned PC3-to-guest SSH route. The guest
command runs as ubuntu and only reads dpkg metadata, driver-library bytes, and
generated kernel-header metadata for the running guest kernel.
No package, service, module, VM, PCI, or boot state is changed.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PINNED_LIBCUDA_PATH = "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04"
PINNED_LIBCUDA_SHA256 = "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"
PINNED_LIBCUDA_BYTES = 96284520
MAX_REMOTE_BYTES = 8 * 1024 * 1024
GUEST_KEY = "/var/lib/pc3-v100-vm/id_ed25519"
GUEST_KNOWN_HOSTS = "/tmp/codex-pc3-vm-known_hosts"
GUEST_HOSTKEY_FINGERPRINT = "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
NVIDIA_CUDA_PACKAGE_PREFIXES = (
    "nvidia-", "libnvidia-", "cuda-", "libcuda", "libcudnn", "libcublas",
    "libcufft", "libcufile", "libcurand", "libcusolver", "libcusparse",
    "libcupti", "libcuxxfilt", "libnpp", "libnvcuvid", "libnvoptix",
    "libnvjitlink", "libnvfatbin", "libnvjpeg", "libnvrtc", "libnvvm",
    "libnvtx", "libnvperf", "libnvdisasm", "tensorrt", "libtensorrt",
)
DRIVER_LIBRARY_PACKAGE_PREFIXES = (
    "nvidia-", "libnvidia-", "libcuda", "libnvcuvid", "libnvoptix",
)


GUEST_INVENTORY_SCRIPT = r'''import datetime,hashlib,json,os,platform,re,shutil,socket,stat,subprocess,sys,tempfile
MAX_QUERY=4*1024*1024
def run(args,pass_fds=()):
 r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"},check=False,pass_fds=pass_fds)
 if r.returncode!=0: raise RuntimeError("guest read-only query failed")
 if len(r.stdout)>MAX_QUERY: raise RuntimeError("guest query exceeded its output bound")
 return r.stdout
release=platform.release()
if not re.fullmatch(r"[A-Za-z0-9._+~-]{1,128}",release): raise RuntimeError("guest kernel release is unsafe")
header_package_names={"linux-headers-"+release,"linux-headers-"+release.rsplit("-",1)[0]}
PACKAGE_PREFIXES=@@PACKAGE_PREFIXES@@
DRIVER_LIBRARY_PREFIXES=@@DRIVER_LIBRARY_PREFIXES@@
def relevant(name):
 n=name.split(":",1)[0]
 return n in ("cuda","cuda-toolkit") or n.startswith(PACKAGE_PREFIXES)
raw=run(["dpkg-query","-W",r"-f=${binary:Package}\t${Version}\t${Architecture}\t${Status}\n"])
packages=[]
kernel_header_packages=[]
for line in raw.decode("utf-8","strict").splitlines():
 fields=line.split("\t")
 if len(fields)!=4: raise RuntimeError("guest package row is malformed")
 name,version,architecture,status=fields
 if relevant(name) and status=="install ok installed":
  packages.append({"name":name,"version":version,"architecture":architecture,"status":status})
 if name.split(":",1)[0] in header_package_names and status=="install ok installed":
  kernel_header_packages.append({"name":name,"version":version,"architecture":architecture,"status":status})
packages.sort(key=lambda x:x["name"])
kernel_header_packages.sort(key=lambda x:x["name"])
if not packages: raise RuntimeError("no installed NVIDIA or CUDA packages were found")
package_names={p["name"] for p in packages}
libraries={}
for package in packages:
 base=package["name"].split(":",1)[0]
 if not base.startswith(DRIVER_LIBRARY_PREFIXES): continue
 listing=run(["dpkg-query","-L",package["name"]]).decode("utf-8","strict")
 for path in listing.splitlines():
  name=os.path.basename(path)
  if not (name.startswith("libcuda.so") or name.startswith("libnvidia-") or name.startswith("libnv")) or ".so" not in name: continue
  if not os.path.isabs(path) or "\x00" in path or ".." in path.split("/"): raise RuntimeError("guest package library path is unsafe")
  try:
   st=os.lstat(path); resolved=os.path.realpath(path); target=os.stat(path)
  except OSError:
   continue
  if not stat.S_ISREG(target.st_mode) or not (resolved.startswith("/usr/lib/") or resolved.startswith("/lib/")): continue
  digest=hashlib.sha256()
  with open(path,"rb") as stream:
   for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
  row=libraries.get(path)
  if row is None:
   row={"package":package["name"],"path":path,"resolved_path":resolved,"is_symlink":stat.S_ISLNK(st.st_mode),"bytes":target.st_size,"sha256":digest.hexdigest()}
   libraries[path]=row
  elif row["resolved_path"]!=resolved or row["bytes"]!=target.st_size or row["sha256"]!=digest.hexdigest():
   raise RuntimeError("guest package library changed during collection")
if "@@PINNED_LIBCUDA@@" not in libraries: raise RuntimeError("pinned R580 libcuda path was not found in installed package manifests")
modules_directory="/lib/modules/"+release
def directory(path): return os.path.isdir(path)
def regular_file(path):
 try:
  resolved=os.path.realpath(path)
  if not resolved.startswith(("/usr/src/","/lib/modules/","/usr/lib/modules/")): return False
  return stat.S_ISREG(os.stat(path).st_mode)
 except OSError: return False
def link_info(path):
 try: st=os.lstat(path)
 except OSError: return {"exists":False,"is_symlink":False,"target":None,"resolved":None,"directory_exists":False}
 is_link=stat.S_ISLNK(st.st_mode)
 target=os.readlink(path) if is_link else None
 resolved=os.path.realpath(path)
 return {"exists":True,"is_symlink":is_link,"target":target,"resolved":resolved,"directory_exists":os.path.isdir(resolved)}
build=link_info(os.path.join(modules_directory,"build"))
source=link_info(os.path.join(modules_directory,"source"))
build_path=build["resolved"]
symvers_path=os.path.join(build_path,"Module.symvers") if build_path else None
symvers_exists=bool(symvers_path and regular_file(symvers_path))
symvers_bytes=None
symvers_sha256=None
if symvers_exists:
 symvers_bytes=os.stat(symvers_path).st_size
 if symvers_bytes<=64*1024*1024:
  digest=hashlib.sha256()
  with open(symvers_path,"rb") as stream:
   for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
  symvers_sha256=digest.hexdigest()
def file_at(relative): return bool(build_path and regular_file(os.path.join(build_path,relative)))
kernel_build={
 "modules_directory":modules_directory,
 "modules_directory_exists":directory(modules_directory),
 "build_link_exists":build["exists"],
 "build_link_is_symlink":build["is_symlink"],
 "build_link_target":build["target"],
 "resolved_build_path":build_path,
 "resolved_build_directory_exists":build["directory_exists"],
 "makefile_exists":file_at("Makefile"),
 "auto_config_exists":file_at("include/config/auto.conf"),
 "generated_autoconf_exists":file_at("include/generated/autoconf.h"),
 "generated_utsrelease_exists":file_at("include/generated/utsrelease.h"),
 "scripts_makefile_build_exists":file_at("scripts/Makefile.build"),
 "scripts_makefile_modpost_exists":file_at("scripts/Makefile.modpost"),
 "scripts_modpost_exists":file_at("scripts/mod/modpost"),
 "scripts_fixdep_exists":file_at("scripts/basic/fixdep"),
 "module_symvers_exists":symvers_exists,
 "module_symvers_bytes":symvers_bytes,
 "module_symvers_sha256":symvers_sha256,
 "source_link_exists":source["exists"],
 "source_link_is_symlink":source["is_symlink"],
 "source_link_target":source["target"],
 "resolved_source_path":source["resolved"],
 "resolved_source_directory_exists":source["directory_exists"],
}
required_inputs=("modules_directory_exists","build_link_exists","resolved_build_directory_exists","makefile_exists","auto_config_exists","generated_autoconf_exists","generated_utsrelease_exists","scripts_makefile_build_exists","scripts_makefile_modpost_exists","scripts_modpost_exists","scripts_fixdep_exists","module_symvers_exists")
kernel_build["kernel_build_ready"]=all(kernel_build[k] for k in required_inputs) and symvers_bytes is not None and symvers_bytes>0 and symvers_sha256 is not None
def safe_read(path):
 try:return open(path,encoding="ascii").read().strip()
 except OSError:return None
def loaded_snapshot():
 loaded=[]
 for line in open("/proc/modules",encoding="ascii").read().splitlines():
  fields=line.split()
  if fields and fields[0].startswith("nvidia"):
   if not re.fullmatch(r"nvidia[a-z0-9_]*",fields[0]):raise RuntimeError("loaded module name is malformed")
   loaded.append(fields[0])
 return {"modules":sorted(set(loaded)),
  "version":safe_read("/sys/module/nvidia/version"),
  "srcversion":safe_read("/sys/module/nvidia/srcversion")}
loaded_before=loaded_snapshot()
enforcement=safe_read("/sys/module/module/parameters/sig_enforce")
if enforcement not in ("Y","N"):enforcement="unavailable"
lockdown_raw=safe_read("/sys/kernel/security/lockdown")
lockdown_match=re.search(r"\[([a-z]+)\]",lockdown_raw or "")
lockdown=lockdown_match.group(1) if lockdown_match else ("none" if lockdown_raw else "unavailable")
secure_boot="unavailable"
mokutil=shutil.which("mokutil")
if mokutil:
 try:
  sb=subprocess.run([mokutil,"--sb-state"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"},check=False)
  text=sb.stdout.decode("utf-8","replace").lower()
  secure_boot="enabled" if sb.returncode==0 and "secureboot enabled" in text else ("disabled" if sb.returncode==0 and "secureboot disabled" in text else "unknown")
 except (OSError,subprocess.TimeoutExpired):secure_boot="unknown"
def module_file(name):
 try:path=run(["modinfo","-k",release,"-n",name]).decode("utf-8","strict").strip()
 except (RuntimeError,UnicodeDecodeError):path=""
 row={"name":name,"exists":False,"path":None,"bytes":None,"sha256":None,"version":None,"srcversion":None,"license":None,"vermagic":None,"signer":None}
 if not path or not os.path.isabs(path):return row
 resolved=os.path.realpath(path)
 allowed=("/lib/modules/"+release+"/","/usr/lib/modules/"+release+"/")
 if not resolved.startswith(allowed) or not os.path.isfile(path):return row
 def identity(st):
  return (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_uid,st.st_gid)
 descriptor=None
 try:
  before=os.stat(resolved,follow_symlinks=False)
  if not stat.S_ISREG(before.st_mode):return row
  descriptor=os.open(resolved,os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0))
  opened=os.fstat(descriptor)
  if identity(before)!=identity(opened):raise RuntimeError("stock module changed during collection")
  size=opened.st_size
  if size<=0 or size>512*1024*1024:raise RuntimeError("stock module file size is outside its bound")
  digest=hashlib.sha256()
  total=0
  with os.fdopen(descriptor,"rb",closefd=False) as stream:
   for block in iter(lambda:stream.read(1024*1024),b""):
    total+=len(block)
    if total>512*1024*1024:raise RuntimeError("stock module file size is outside its bound")
    digest.update(block)
  hashed=os.fstat(descriptor)
  if total!=size or identity(opened)!=identity(hashed):raise RuntimeError("stock module changed during collection")
  with tempfile.TemporaryDirectory(prefix="pc3-module-modinfo-") as metadata_directory:
   metadata_path=metadata_directory+"/"+resolved.rsplit("/",1)[-1]
   os.symlink("/proc/self/fd/"+str(descriptor),metadata_path)
   def field(key):
    value=run(["modinfo","-k",release,"-F",key,metadata_path],pass_fds=(descriptor,)).decode("utf-8","strict").strip()
    if key in ("version","license","vermagic") and not value:
     raise RuntimeError("stock module is missing required "+key+" metadata")
    return value[:512]
   metadata={"version":field("version"),"srcversion":field("srcversion"),
    "license":field("license"),"vermagic":field("vermagic"),"signer":field("signer")}
  after=os.stat(resolved,follow_symlinks=False)
  if identity(opened)!=identity(after) or os.path.realpath(path)!=resolved:
   raise RuntimeError("stock module changed during collection")
 except OSError:raise RuntimeError("stock module changed during collection") from None
 finally:
  if descriptor is not None:os.close(descriptor)
 row.update({"exists":True,"path":path,"bytes":size,"sha256":digest.hexdigest(),**metadata})
 return row
installed_modules=[module_file(name) for name in ("nvidia","nvidia_drm","nvidia_modeset","nvidia_uvm")]
loaded_after=loaded_snapshot()
loaded=loaded_after["modules"]
loaded_version=loaded_after["version"]
loaded_srcversion=loaded_after["srcversion"]
loaded_observations_match=(loaded_before==loaded_after)
nvidia_module=installed_modules[0]
loaded_matches_installed=(None if not loaded_observations_match or "nvidia" not in loaded or not loaded_version or
                          not loaded_srcversion or not nvidia_module["exists"] or
                          not nvidia_module["version"] or not nvidia_module["srcversion"] else
                          loaded_version==nvidia_module["version"] and
                          loaded_srcversion.upper()==nvidia_module["srcversion"].upper())
module_state={"loaded_nvidia_modules":loaded,
 "loaded_nvidia_module_version":loaded_version,
 "loaded_nvidia_module_srcversion":loaded_srcversion,
 "loaded_nvidia_module_pre_capture":loaded_before,
 "loaded_nvidia_module_matches_installed_source_identity":loaded_matches_installed,
 "signature_enforcement":enforcement,"lockdown_state":lockdown,
 "secure_boot_state":secure_boot,
 "installed_modules":installed_modules}
result={"schema":"nvidia-hybrid-pc3-v100-package-inventory-v6","observed_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),"hostname":socket.gethostname(),"kernel_release":release,"packages":packages,"kernel_header_packages":kernel_header_packages,"libraries":sorted(libraries.values(),key=lambda x:x["path"]),"pinned_libcuda_path":"@@PINNED_LIBCUDA@@","kernel_build":kernel_build,"module_state":module_state}
print(json.dumps(result,separators=(",",":"),sort_keys=True))
'''.replace("@@PINNED_LIBCUDA@@", PINNED_LIBCUDA_PATH).replace(
    "@@PACKAGE_PREFIXES@@", repr(NVIDIA_CUDA_PACKAGE_PREFIXES)).replace(
    "@@DRIVER_LIBRARY_PREFIXES@@", repr(DRIVER_LIBRARY_PACKAGE_PREFIXES))


ROOT_REMOTE_SCRIPT = r'''import base64,hashlib,json,os,shlex,stat,subprocess,sys
KEY="/var/lib/pc3-v100-vm/id_ed25519"
KNOWN="/tmp/codex-pc3-vm-known_hosts"
EXPECTED="SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
if os.geteuid()!=0 or len(sys.argv)!=3: raise SystemExit(2)
key_st=os.lstat(KEY); known_st=os.lstat(KNOWN)
if not stat.S_ISREG(key_st.st_mode) or key_st.st_uid!=0 or stat.S_IMODE(key_st.st_mode)!=0o600: raise SystemExit(3)
if not stat.S_ISREG(known_st.st_mode) or known_st.st_uid!=0 or known_st.st_mode&0o022: raise SystemExit(4)
selected=subprocess.run(["/usr/bin/ssh-keygen","-F","[127.0.0.1]:22223","-f",KNOWN],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False)
lines=[x for x in selected.stdout.decode("utf-8","strict").splitlines() if x and not x.startswith("#")]
fps=set()
for line in lines:
 fields=line.split()
 if len(fields)<3 or fields[0].startswith("@"): raise SystemExit(5)
 blob=base64.b64decode(fields[2],validate=True)
 fps.add("SHA256:"+base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("="))
if selected.returncode or fps!={EXPECTED}: raise SystemExit(6)
try: guest_code=base64.b64decode(sys.argv[1],validate=True)
except Exception: raise SystemExit(7)
if hashlib.sha256(guest_code).hexdigest()!=sys.argv[2]: raise SystemExit(8)
remote=shlex.join(["python3","-c",guest_code.decode("utf-8","strict")])
ssh=["/usr/bin/ssh","-F","/dev/null","-T","-oBatchMode=yes","-oIdentitiesOnly=yes","-oStrictHostKeyChecking=yes","-oUserKnownHostsFile="+KNOWN,"-oConnectTimeout=8","-oConnectionAttempts=1","-i",KEY,"-p","22223","ubuntu@127.0.0.1",remote]
try: result=subprocess.run(ssh,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,check=False)
except Exception: raise SystemExit(9)
if len(result.stdout)>8*1024*1024: raise SystemExit(10)
envelope={"schema":"nvidia-hybrid-pc3-v100-package-transport-v1","guest_ssh_exit_code":result.returncode,"guest_stdout_b64":base64.b64encode(result.stdout).decode("ascii"),"guest_stderr_sha256":hashlib.sha256(result.stderr).hexdigest(),"hostkey_fingerprint":EXPECTED}
print(json.dumps(envelope,separators=(",",":"),sort_keys=True))
'''


def validate_guest_inventory(raw: bytes) -> dict[str, Any]:
    """Validate and return the bounded, redacted guest inventory payload."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REMOTE_BYTES:
        raise ValueError("guest inventory size is invalid")
    try:
        report = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("guest inventory is not valid UTF-8 JSON") from None

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict), "guest inventory must be an object")
    required = {"schema", "observed_at_utc", "hostname", "kernel_release", "packages",
                "kernel_header_packages", "libraries", "pinned_libcuda_path", "kernel_build",
                "module_state"}
    require(set(report) == required, "guest inventory fields differ from the expected schema")
    require(report["schema"] == "nvidia-hybrid-pc3-v100-package-inventory-v6",
            "guest inventory schema is unsupported")
    try:
        observed = datetime.fromisoformat(report["observed_at_utc"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        observed = None
    require(observed is not None and observed.tzinfo is not None,
            "guest inventory timestamp is invalid")
    require(isinstance(report["hostname"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", report["hostname"]),
            "guest hostname is invalid")
    require(isinstance(report["kernel_release"], str) and
            re.fullmatch(r"[A-Za-z0-9._+~-]{1,128}", report["kernel_release"]),
            "guest kernel release is invalid")
    require(report["pinned_libcuda_path"] == PINNED_LIBCUDA_PATH,
            "pinned libcuda path differs from the known R580 guest capture")
    packages = report["packages"]
    require(isinstance(packages, list) and 1 <= len(packages) <= 512,
            "guest installed package inventory is empty or over its bound")
    package_names: set[str] = set()
    package_fields = {"name", "version", "architecture", "status"}
    for package in packages:
        require(isinstance(package, dict) and set(package) == package_fields,
                "guest package record fields are invalid")
        name, version, architecture, status = (package[k] for k in
                                                ("name", "version", "architecture", "status"))
        require(isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", name),
                "guest package name is invalid")
        base_name = name.split(":", 1)[0]
        require(base_name in ("cuda", "cuda-toolkit") or
                base_name.startswith(NVIDIA_CUDA_PACKAGE_PREFIXES),
                "guest package is outside the NVIDIA/CUDA inventory scope")
        require(isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,160}", version),
                "guest package version is invalid")
        require(isinstance(architecture, str) and re.fullmatch(r"[a-z0-9-]{1,32}", architecture),
                "guest package architecture is invalid")
        require(status == "install ok installed", "guest package is not installed")
        require(name not in package_names, "guest package inventory contains a duplicate")
        package_names.add(name)
    require([p["name"] for p in packages] == sorted(package_names),
            "guest package inventory is not sorted")
    header_packages = report["kernel_header_packages"]
    expected_header_names = {
        "linux-headers-" + report["kernel_release"],
        "linux-headers-" + report["kernel_release"].rsplit("-", 1)[0],
    }
    require(isinstance(header_packages, list) and len(header_packages) <= 2,
            "guest kernel header package inventory is invalid")
    header_names: set[str] = set()
    for package in header_packages:
        require(isinstance(package, dict) and set(package) == package_fields,
                "guest kernel header package record fields are invalid")
        name, version, architecture, status = (package[k] for k in
                                                ("name", "version", "architecture", "status"))
        require(isinstance(name, str) and name.split(":", 1)[0] in expected_header_names,
                "guest kernel header package does not match the running kernel")
        require(isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,160}", version),
                "guest kernel header package version is invalid")
        require(isinstance(architecture, str) and re.fullmatch(r"[a-z0-9-]{1,32}", architecture),
                "guest kernel header package architecture is invalid")
        require(status == "install ok installed", "guest kernel header package is not installed")
        require(name not in header_names, "guest kernel header package inventory contains a duplicate")
        header_names.add(name)
    require([p["name"] for p in header_packages] == sorted(header_names),
            "guest kernel header package inventory is not sorted")

    libraries = report["libraries"]
    require(isinstance(libraries, list) and len(libraries) <= 2048,
            "guest library inventory is over its bound")
    library_fields = {"package", "path", "resolved_path", "is_symlink", "bytes", "sha256"}
    paths: set[str] = set()
    pinned_found = False
    for library in libraries:
        require(isinstance(library, dict) and set(library) == library_fields,
                "guest library record fields are invalid")
        package, path, resolved = library["package"], library["path"], library["resolved_path"]
        require(isinstance(package, str) and package in package_names,
                "guest library owner is not in the installed package inventory")
        require(isinstance(path, str) and path.startswith("/") and ".." not in PurePosixPath(path).parts and
                (path.startswith("/usr/lib/") or path.startswith("/lib/")),
                "guest library path is outside approved library directories")
        require(isinstance(resolved, str) and resolved.startswith("/") and
                ".." not in PurePosixPath(resolved).parts and
                (resolved.startswith("/usr/lib/") or resolved.startswith("/lib/")),
                "guest library path resolves outside approved library directories")
        require(isinstance(library["is_symlink"], bool), "guest library symlink flag is invalid")
        require(type(library["bytes"]) is int and 0 < library["bytes"] <= 8 * 1024**3,
                "guest library size is invalid")
        require(isinstance(library["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", library["sha256"]),
                "guest library SHA-256 is invalid")
        require(path not in paths, "guest library inventory contains a duplicate path")
        paths.add(path)
        if path == PINNED_LIBCUDA_PATH:
            pinned_found = True
    require(pinned_found, "pinned libcuda library was not captured")
    require([x["path"] for x in libraries] == sorted(paths),
            "guest library inventory is not sorted")

    build = report["kernel_build"]
    build_fields = {
        "modules_directory", "modules_directory_exists", "build_link_exists",
        "build_link_is_symlink", "build_link_target", "resolved_build_path",
        "resolved_build_directory_exists", "makefile_exists", "auto_config_exists",
        "generated_autoconf_exists", "generated_utsrelease_exists",
        "scripts_makefile_build_exists", "scripts_makefile_modpost_exists",
        "scripts_modpost_exists", "scripts_fixdep_exists", "module_symvers_exists",
        "module_symvers_bytes", "module_symvers_sha256", "source_link_exists",
        "source_link_is_symlink", "source_link_target", "resolved_source_path",
        "resolved_source_directory_exists", "kernel_build_ready",
    }
    require(isinstance(build, dict) and set(build) == build_fields,
            "kernel build inventory fields differ from the expected schema")
    expected_modules_directory = "/lib/modules/" + report["kernel_release"]
    require(build["modules_directory"] == expected_modules_directory,
            "kernel build directory does not match the guest kernel release")
    boolean_fields = build_fields - {
        "modules_directory", "build_link_target", "resolved_build_path",
        "module_symvers_bytes", "module_symvers_sha256", "source_link_target",
        "resolved_source_path",
    }
    require(all(isinstance(build[key], bool) for key in boolean_fields),
            "kernel build inventory flags are invalid")

    def validate_kernel_path(value, label, optional=False):
        if optional and value is None:
            return
        require(isinstance(value, str) and len(value) <= 4096 and value.startswith("/") and
                ".." not in PurePosixPath(value).parts and
                not any(ord(char) < 32 for char in value),
                f"{label} is invalid")

    for prefix in ("build", "source"):
        exists = build[f"{prefix}_link_exists"]
        is_symlink = build[f"{prefix}_link_is_symlink"]
        target = build[f"{prefix}_link_target"]
        resolved_key = "resolved_build_path" if prefix == "build" else "resolved_source_path"
        directory_key = ("resolved_build_directory_exists" if prefix == "build" else
                         "resolved_source_directory_exists")
        resolved = build[resolved_key]
        directory_exists = build[directory_key]
        require(not is_symlink or exists, f"{prefix} link cannot be a symlink when absent")
        require((target is not None) == is_symlink,
                f"{prefix} link target disagrees with its symlink flag")
        if target is not None:
            require(isinstance(target, str) and 0 < len(target) <= 4096 and
                    not any(ord(char) < 32 for char in target),
                    f"{prefix} link target is invalid")
        require((resolved is not None) == exists,
                f"resolved {prefix} path disagrees with link existence")
        if resolved is not None:
            validate_kernel_path(resolved, f"resolved {prefix} path")
            require(resolved.startswith(("/usr/src/", "/lib/modules/", "/usr/lib/modules/")) or
                    resolved in ("/usr/src", "/lib/modules", "/usr/lib/modules"),
                    f"resolved {prefix} path is outside system kernel source locations")
        require(not directory_exists or exists,
                f"resolved {prefix} directory exists without a link")

    input_fields = (
        "makefile_exists", "auto_config_exists", "generated_autoconf_exists",
        "generated_utsrelease_exists", "scripts_makefile_build_exists",
        "scripts_makefile_modpost_exists", "scripts_modpost_exists", "scripts_fixdep_exists",
    )
    require(not any(build[key] for key in input_fields) or
            build["resolved_build_directory_exists"],
            "kernel build files are reported without a resolved build directory")
    symvers_bytes, symvers_digest = build["module_symvers_bytes"], build["module_symvers_sha256"]
    require(build["module_symvers_exists"] == (symvers_bytes is not None),
            "Module.symvers existence and size disagree")
    if symvers_bytes is not None:
        require(type(symvers_bytes) is int and 0 <= symvers_bytes <= 8 * 1024**3,
                "Module.symvers size is invalid")
        if symvers_bytes <= 64 * 1024**2:
            require(isinstance(symvers_digest, str) and
                    re.fullmatch(r"[0-9a-f]{64}", symvers_digest),
                    "Module.symvers SHA-256 is invalid")
        else:
            require(symvers_digest is None, "oversized Module.symvers must not be hashed")
    else:
        require(symvers_digest is None, "Module.symvers hash exists while the file is missing")
    ready_inputs = (
        "modules_directory_exists", "build_link_exists", "resolved_build_directory_exists",
        *input_fields, "module_symvers_exists",
    )
    expected_ready = (all(build[key] for key in ready_inputs) and
                      symvers_bytes is not None and symvers_bytes > 0 and
                      symvers_digest is not None)
    require(build["kernel_build_ready"] == expected_ready,
            "kernel build readiness disagrees with its required inputs")
    module_state = report["module_state"]
    module_state_fields = {"loaded_nvidia_modules", "loaded_nvidia_module_version",
                           "loaded_nvidia_module_srcversion",
                           "loaded_nvidia_module_pre_capture",
                           "loaded_nvidia_module_matches_installed_source_identity",
                           "signature_enforcement", "lockdown_state", "secure_boot_state",
                           "installed_modules"}
    require(isinstance(module_state, dict) and set(module_state) == module_state_fields,
            "guest module state fields are invalid")
    loaded = module_state["loaded_nvidia_modules"]
    require(isinstance(loaded, list) and loaded == sorted(set(loaded)) and len(loaded) <= 64 and
            all(isinstance(name, str) and re.fullmatch(r"nvidia[a-z0-9_]*", name)
                for name in loaded), "guest module state loaded-module list is invalid")
    version = module_state["loaded_nvidia_module_version"]
    require(version is None or (isinstance(version, str) and
            re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", version)),
            "guest module state version is invalid")
    loaded_srcversion = module_state["loaded_nvidia_module_srcversion"]
    require(loaded_srcversion is None or (isinstance(loaded_srcversion, str) and
            re.fullmatch(r"[A-Fa-f0-9]{1,64}", loaded_srcversion)),
            "guest module state loaded srcversion is invalid")
    pre_capture = module_state["loaded_nvidia_module_pre_capture"]
    require(isinstance(pre_capture, dict) and set(pre_capture) == {"modules", "version", "srcversion"},
            "guest module state pre-capture snapshot fields are invalid")
    pre_modules = pre_capture["modules"]
    require(isinstance(pre_modules, list) and pre_modules == sorted(set(pre_modules)) and
            len(pre_modules) <= 64 and
            all(isinstance(name, str) and re.fullmatch(r"nvidia[a-z0-9_]*", name)
                for name in pre_modules),
            "guest module state pre-capture loaded-module list is invalid")
    pre_version = pre_capture["version"]
    require(pre_version is None or (isinstance(pre_version, str) and
            re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", pre_version)),
            "guest module state pre-capture version is invalid")
    pre_srcversion = pre_capture["srcversion"]
    require(pre_srcversion is None or (isinstance(pre_srcversion, str) and
            re.fullmatch(r"[A-Fa-f0-9]{1,64}", pre_srcversion)),
            "guest module state pre-capture srcversion is invalid")
    require(module_state["signature_enforcement"] in ("Y", "N", "unavailable") and
            module_state["lockdown_state"] in
            ("none", "integrity", "confidentiality", "unavailable") and
            module_state["secure_boot_state"] in
            ("enabled", "disabled", "unknown", "unavailable"),
            "guest module state security policy is invalid")
    installed = module_state["installed_modules"]
    module_names = ("nvidia", "nvidia_drm", "nvidia_modeset", "nvidia_uvm")
    module_fields = {"name", "exists", "path", "bytes", "sha256", "version",
                     "srcversion", "license", "vermagic", "signer"}
    require(isinstance(installed, list) and len(installed) == len(module_names) and
            tuple(item.get("name") for item in installed if isinstance(item, dict)) == module_names,
            "guest module state stock-module inventory is incomplete")
    for item in installed:
        require(isinstance(item, dict) and set(item) == module_fields and
                isinstance(item["exists"], bool), "guest module state stock module is malformed")
        if not item["exists"]:
            require(all(item[key] is None for key in
                        ("path", "bytes", "sha256", "version", "srcversion", "license",
                         "vermagic", "signer")),
                    "guest module state missing-module metadata is inconsistent")
            continue
        path = item["path"]
        require(isinstance(path, str) and
                path.startswith(("/lib/modules/" + report["kernel_release"] + "/",
                                 "/usr/lib/modules/" + report["kernel_release"] + "/")) and
                ".." not in PurePosixPath(path).parts,
                "guest module state stock-module path is invalid")
        require(type(item["bytes"]) is int and 0 < item["bytes"] <= 512 * 1024 * 1024 and
                isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
                "guest module state stock-module hash or size is invalid")
        for field in ("version", "srcversion", "license", "vermagic", "signer"):
            value = item[field]
            require(isinstance(value, str) and len(value) <= 512 and
                    not any(ord(char) < 32 for char in value),
                    "guest module state stock-module metadata is invalid")
        require(bool(item["version"]) and bool(item["license"]),
                "guest module state required stock-module metadata is missing")
        require(not item["srcversion"] or re.fullmatch(r"[A-Fa-f0-9]{1,64}", item["srcversion"]),
                "guest module state stock-module srcversion is invalid")
        require(item["vermagic"].startswith(report["kernel_release"] + " "),
                "guest module state stock-module vermagic differs from the running kernel")
    nvidia_module = installed[0]
    observations_match = (pre_modules == loaded and pre_version == version and
                          pre_srcversion == loaded_srcversion)
    if not observations_match or "nvidia" not in loaded or not version or not loaded_srcversion or \
            not nvidia_module["exists"] or not nvidia_module["version"] or \
            not nvidia_module["srcversion"]:
        expected_source_match = None
    else:
        expected_source_match = (version == nvidia_module["version"] and
                                 loaded_srcversion.upper() == nvidia_module["srcversion"].upper())
    require(module_state["loaded_nvidia_module_matches_installed_source_identity"] is
            expected_source_match,
            "guest module state loaded source identity does not match its version and srcversion")
    return report


def load_transport():
    path = ROOT / "tools/run_pc3_v100_guest_reference.py"
    spec = importlib.util.spec_from_file_location("pc3_v100_guest_reference_transport", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("the pinned PC3 V100 guest transport is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def output_path(value: str | None) -> Path:
    if value is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        candidate = ROOT / "evidence" / f"pc3-v100-package-inventory-{stamp}.json"
    else:
        raw = Path(value)
        candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = Path(os.path.abspath(candidate))
    try:
        candidate.relative_to(ROOT)
    except ValueError:
        raise ValueError("inventory output must remain inside the canonical project") from None
    cursor = ROOT
    for part in candidate.parent.relative_to(ROOT).parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            cursor.mkdir(mode=0o700)
            info = cursor.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("inventory output directory contains an unsafe component")
    if candidate.exists() or candidate.is_symlink():
        raise FileExistsError("inventory output already exists")
    return candidate


def write_private_json(path: Path, report: dict[str, Any]) -> str:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return hashlib.sha256(payload).hexdigest()


def collect(transport, target: str, host_key_alias: str,
            direct_pc3: bool = False) -> dict[str, Any]:
    guest_bytes = GUEST_INVENTORY_SCRIPT.encode("utf-8")
    guest_digest = hashlib.sha256(guest_bytes).hexdigest()
    guest_b64 = base64.b64encode(guest_bytes).decode("ascii")
    sudo_prefix = "sudo -n python3 -c " if direct_pc3 else "sudo -S -p '' python3 -c "
    remote_command = sudo_prefix + shlex.quote(ROOT_REMOTE_SCRIPT) + " " + \
        shlex.quote(guest_b64) + " " + shlex.quote(guest_digest)
    if direct_pc3:
        if target != transport.DEFAULT_PC3_TARGET or host_key_alias != transport.DEFAULT_HOST_KEY_ALIAS:
            raise ValueError("direct collection is restricted to the pinned PC3 SSH route")
        ssh_base = transport.pc3_direct_ssh_base(target, host_key_alias)
        try:
            result = subprocess.run(ssh_base + [remote_command], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("direct read-only package inventory transport failed") from None
    else:
        secret = transport.fetch_pc3_sudo_secret(transport.DEFAULT_CREDENTIAL_HOST,
                                                  transport.DEFAULT_CREDENTIAL_FILE)
        try:
            result = subprocess.run(transport.pc3_ssh_base(target, host_key_alias) + [remote_command],
                                    input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("read-only package inventory transport failed") from None
        finally:
            secret = None
    if result.returncode != 0 or len(result.stdout) > MAX_REMOTE_BYTES:
        raise RuntimeError("PC3 did not return a bounded successful guest inventory")
    try:
        envelope = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 returned an invalid package inventory envelope") from None
    if (not isinstance(envelope, dict) or
            set(envelope) != {"schema", "guest_ssh_exit_code", "guest_stdout_b64",
                              "guest_stderr_sha256", "hostkey_fingerprint"} or
            envelope.get("schema") != "nvidia-hybrid-pc3-v100-package-transport-v1" or
            envelope.get("guest_ssh_exit_code") != 0 or
            envelope.get("hostkey_fingerprint") != GUEST_HOSTKEY_FINGERPRINT or
            not isinstance(envelope.get("guest_stderr_sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", envelope["guest_stderr_sha256"]) is None):
        raise RuntimeError("PC3 guest identity or inventory envelope failed validation")
    try:
        guest_raw = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    except (ValueError, TypeError):
        raise RuntimeError("PC3 guest inventory encoding is invalid") from None
    inventory = validate_guest_inventory(guest_raw)
    libraries = {item["path"]: item for item in inventory["libraries"]}
    pinned = libraries[PINNED_LIBCUDA_PATH]
    return {
        "schema": "nvidia-hybrid-pc3-v100-package-inventory-capture-v1",
        "status": "collected",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "transport_mode": "pc3-direct-key-sudo-n" if direct_pc3 else "pc6-sourced-sudo-auth",
        "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
        "transport_script_sha256": hashlib.sha256(ROOT_REMOTE_SCRIPT.encode()).hexdigest(),
        "guest_script_sha256": guest_digest,
        "guest_stderr_sha256": envelope["guest_stderr_sha256"],
        "guest_inventory": inventory,
        "pinned_libcuda_comparison": {
            "path": PINNED_LIBCUDA_PATH,
            "captured_bytes": pinned["bytes"],
            "captured_sha256": pinned["sha256"],
            "prior_capture_bytes": PINNED_LIBCUDA_BYTES,
            "prior_capture_sha256": PINNED_LIBCUDA_SHA256,
            "matches_prior_capture": pinned["bytes"] == PINNED_LIBCUDA_BYTES and
                                      pinned["sha256"] == PINNED_LIBCUDA_SHA256,
        },
        "collection_scope": "installed NVIDIA/CUDA package versions, package-owned NVIDIA driver library hashes, running-kernel build-tree metadata, loaded driver module names, kernel signature policy, and exact stock module file hashes",
        "read_only_guest_query": True,
        "host_or_guest_mutation_performed": False,
        "driver_or_gpu_execution_tested": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="private JSON destination under the canonical project")
    parser.add_argument("--target", default="pc3@pc3")
    parser.add_argument("--host-key-alias", default="pc3")
    parser.add_argument("--direct-pc3", action="store_true",
                        help="use only the configured local SSH key and PC3 sudo -n; never contact PC6")
    args = parser.parse_args(argv)
    try:
        destination = output_path(args.output)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    status = "collected"
    try:
        result = collect(load_transport(), args.target, args.host_key_alias,
                         direct_pc3=args.direct_pc3)
    except Exception as error:
        status = "failed"
        result = {
            "schema": "nvidia-hybrid-pc3-v100-package-inventory-capture-v1",
            "status": status,
            "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": args.target,
            "transport_mode": "pc3-direct-key-sudo-n" if args.direct_pc3 else "pc6-sourced-sudo-auth",
            "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
            "read_only_guest_query": True,
            "host_or_guest_mutation_performed": False,
            "driver_or_gpu_execution_tested": False,
            "failure": str(error)[:240],
        }
    try:
        digest = write_private_json(destination, result)
    except OSError as error:
        print(f"could not publish private inventory report: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": status, "report": str(destination), "sha256": digest}, sort_keys=True))
    return 0 if status == "collected" else 2


if __name__ == "__main__":
    raise SystemExit(main())
