import hashlib, json
from pathlib import Path
root=Path(__file__).resolve().parent
inputs=root/"inputs"
manifest=json.loads((inputs/"INPUTS.json").read_text())
for entry in manifest["inputs"]:
    path=inputs/entry["name"]
    if not path.is_file():
        raise SystemExit("MISSING " + entry["name"])
    payload=path.read_bytes()
    if len(payload) != entry["bytes"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
        raise SystemExit("MISMATCH " + entry["name"])
for name in ("TASK.md", "agents.json"):
    if hashlib.sha256((root/name).read_bytes()).hexdigest() != hashlib.sha256((inputs/name).read_bytes()).hexdigest():
        raise SystemExit("ROOT_COPY_MISMATCH " + name)
print("verified_inputs", len(manifest["inputs"]))
print("source_archive", manifest["source_archive_sha256"])
print("patch", manifest["patch_sha256"])
