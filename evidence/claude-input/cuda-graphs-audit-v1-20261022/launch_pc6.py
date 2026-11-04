#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys
from pathlib import Path
root=Path("/home/pc6/.cache/codex-tasks/cuda-graphs-audit-3f3W7q")
workdir=root/"output"
project=root/"project"
prompt=(root/"TASK_PROMPT.txt").read_text().strip()
plugin=Path("/home/pc6/.claude/plugins/cache/claude-plugins-official/ralph-loop/1.0.0")
setup=plugin/"scripts/setup-ralph-loop.sh"
env=os.environ.copy()
env["PATH"]="/home/pc6/.local/bin:"+env.get("PATH","")
setup_cmd=["bash",str(setup),prompt,"--max-iterations","8","--completion-promise","CUDA_GRAPHS_AUDIT_COMPLETE"]
setup_result=subprocess.run(setup_cmd,cwd=workdir,env=env,text=True,capture_output=True,check=False)
if setup_result.returncode:
    print(setup_result.stdout,end="");print(setup_result.stderr,end="",file=sys.stderr);sys.exit(setup_result.returncode)
cmd=[
    "/home/pc6/.local/bin/claude", "--bg",
    "--model", "claude-opus-5-5", "--effort", "max",
    "--name", "cuda-graphs-opus-audit",
    "--permission-mode", "dontAsk",
    "--plugin-dir", str(plugin),
    "--add-dir", str(project),
    "--allowedTools=Read,Grep,Glob,Write,Task",
    prompt,
]
result=subprocess.run(cmd,cwd=workdir,env=env,text=True,capture_output=True,check=False)
print(json.dumps({"setup_exit_code":setup_result.returncode,"setup_output":setup_result.stdout,"argv":cmd[:-1]+["<prompt sha256>"],"prompt_sha256":hashlib.sha256(prompt.encode()).hexdigest(),"cwd":str(workdir),"exit_code":result.returncode,"stdout":result.stdout,"stderr":result.stderr},indent=2))
sys.exit(result.returncode)
