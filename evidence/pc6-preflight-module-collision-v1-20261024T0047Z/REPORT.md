# Adversarial review: active kernel-module collision gate (PC3 canary static preflight)

Status: **FINAL (iteration 1)**. Own analysis complete; the independent Sonnet 5.5 review has been
received and reconciled (§9). Decision: **changes required** (`DECISION.json`).

Path aliases. Line numbers refer to the supplied copies.
- **GATE** = `tools/audit_pc3_canary_preflight.py`
- **COLL** = `tools/collect_pc3_canary_host_state.py`
- **TEST** = `tests/test_pc3_canary_preflight.py`

## 1. Answer to the README question

> Does the new static preflight gate correctly fail closed when the exact candidate kernel module name
> is already active, and can its input/reporting contract create a false-clear or misleading result?

- **`nvidia_uvm`: the gate fails closed (correct today).**
  - A loaded `nvidia_uvm` (or `nvidia-uvm`) produces `loaded_module_name_conflict` and `blocked` (P4, F7-isolation).
  - The owner's blocked PC3 result is consistent with the code and is **not** a false clear.
  - However, no test pins "a conflict makes the status `blocked`": mutant M12 survives (§5).
- **`hybrid580_open`, `hybrid580_legacy`, `hybrid580_frontend` (3 of 4 candidates): the gate does not fail closed (proven defect D1).**
  - The collector and both validators admit only names that start with `nvidia`, so these three exact names can never reach the comparison.
  - With `hybrid580_open` loaded, the collector's own code drops it, its validator and `make_report` accept the snapshot, and the gate returns **`static-preflight-clear`** with `candidate_module_name_conflicts: []` (P1, P1b, P2).
  - Sonnet's F1 reached the same conclusion independently.
- **The contract also accepts other bad inputs** (risks R1–R6):
  - undated, stale or wrong-host inventories;
  - internally inconsistent inventories;
  - non-canonical names;
  - and the report wording can mislead.
- **The collector's validator rejects the collector's own stored snapshot** (proven latent defect D2; found by Sonnet's F6, confirmed by execution). The obvious fix of reusing the collector's validator in the gate would therefore fail.

## 2. Scope, method and constraints

- **What I read.** README, GATE and TEST in full. COLL's `active_modules` collection and validation
  path in detail, plus a cross-check of which top-level fields COLL emits versus which GATE consumes.
  All file text was treated as data.
- **What I did not touch.** No network, hosts, hardware, credentials or live project, and no module
  loaded or installed.
  - COLL line 29 imports `tools.run_pc3_v100_guest_reference`, which is not in the packet. Only in my
    scratch harness, I replaced it with a stub whose functions raise.
  - No probe read the real `/proc`, `/sys` or `/dev`, or ran `modinfo` or `ssh`.
- **Supplied files are unchanged.** SHA-256 was recorded before any execution and re-verified with
  `sha256sum -c`: all `OK`, three times (see `ITERATION_LOG.md`). No `__pycache__` was written into the
  packet.
- **Executions.**
  1. The README's focused test command (§6).
  2. Pure-function probes of `evaluate_preflight`, `validate_host_state`, `make_report` and
     `_parse_json_bytes` on synthetic snapshots. The collector's `/proc/modules` loop (COLL 101–107) was
     extracted **verbatim** from `REMOTE_HOST_STATE_SCRIPT` with `ast` and executed with a stubbed
     `read_text` serving synthetic text.
  3. Mutation checks: the same focused test module run against mutated **scratch copies** of GATE.
- **Where the scripts and raw outputs are** (session scratchpad, outside the packet; the outputs this
  report relies on are quoted inline):
  - `/tmp/claude-1000/-home-pc6-claude-driver-hybrid-preflight-module-collision-v1/03db2023-5736-4525-ad0a-11fe2b2ab530/scratchpad/probes/probe_gate.py` → `/tmp/claude-1000/-home-pc6-claude-driver-hybrid-preflight-module-collision-v1/03db2023-5736-4525-ad0a-11fe2b2ab530/scratchpad/probe_output_run1.txt`
  - `/tmp/claude-1000/-home-pc6-claude-driver-hybrid-preflight-module-collision-v1/03db2023-5736-4525-ad0a-11fe2b2ab530/scratchpad/probes/probe_reconcile.py` → `/tmp/claude-1000/-home-pc6-claude-driver-hybrid-preflight-module-collision-v1/03db2023-5736-4525-ad0a-11fe2b2ab530/scratchpad/reconcile_output_run1.txt`
  - `/tmp/claude-1000/-home-pc6-claude-driver-hybrid-preflight-module-collision-v1/03db2023-5736-4525-ad0a-11fe2b2ab530/scratchpad/probes/probe_mutants.py` → `/tmp/claude-1000/-home-pc6-claude-driver-hybrid-preflight-module-collision-v1/03db2023-5736-4525-ad0a-11fe2b2ab530/scratchpad/mutant_output_run2.txt`
- **Classification.**
  - **Proven defect**: the code demonstrably contradicts its stated contract, shown by code reading and by execution.
  - **Risk**: the mechanism is demonstrated, but harm depends on how snapshots are produced, merged or aged.
  - **Hypothesis**: needs evidence that is not in the packet.

## 3. Proven defects

### D1 (high): the inventory prefix filter blinds the collision check to 3 of 4 candidate names → false clear

| Step | Location | Behavior |
|---|---|---|
| Candidate names | GATE 21–26 | `hybrid580_open`, `hybrid580_legacy`, `hybrid580_frontend`, `nvidia_uvm` |
| Identity enforced | GATE 180–182 | any other name raises `module_identity_mismatch`, so a run that can clear uses exactly these names |
| Collector filter | COLL 103–107 (filter at 105) | keeps a `/proc/modules` line only if `fields[0].startswith("nvidia")` |
| Collector validation | COLL 270–272 (`active_modules`) and 273–275 (`loaded_nvidia_modules`) | rejects any name not starting with `nvidia` |
| Gate validation | GATE 85–89 (prefix test at 88) | rejects any name not starting with `nvidia` (`active NVIDIA module record is invalid`) |
| Gate comparison | GATE 166–177 (test at 172) | `name in active_module_names` for each role |

`replace('-', '_')` cannot change the `nvidia` prefix, so every accepted active name starts with `nvidia`.
For any run that passes the identity check, the `open`, `legacy` and `frontend` comparisons can never
match. In effect only the `uvm` role is ever checked.

**Execution evidence**

| Probe | Input | Result |
|---|---|---|
| P1 | `/proc/modules` = `hybrid580_open 16384000 0 - Live 0x0…` + `snd_hda_intel …` | collector loop → `"active_modules": []`; `validate_host_state` → `ok`; `make_report` → ok; gate (policy off) → `"status": "static-preflight-clear"`, `"blocker_codes": []`, `"candidate_module_name_conflicts": []` |
| P1b | same, plus Secure Boot, `sig_enforce` and `integrity` lockdown, plus trust evidence built by the owner's `signature_trust_evidence()` | `"static-preflight-clear"`, `"signature_trust_verified": true` |
| P2 | all three `hybrid580_*` loaded | collector keeps none → `static-preflight-clear` |
| P3 | inventory that lists `{"name": "hybrid580_open"}` | gate: `ValueError: active NVIDIA module record is invalid`; COLL: `ValueError: active module record is invalid` |
| P4 (control) | stock `nvidia_uvm`, `nvidia_drm`, `nvidia_modeset`, `nvidia` | `["loaded_module_name_conflict"]`, `[{"name": "nvidia_uvm", "role": "uvm"}]`, `"blocked"` |
| M3 | comparison restricted to `role == 'uvm'` | all 37 tests still pass |

P3 has two consequences:
- A *complete* inventory cannot reach the conflict check. It ends in the CLI's exit-2
  "preflight failed" path (GATE 494–496) with a wrong diagnosis ("invalid record"), not a
  `loaded_module_name_conflict` blocker.
- So the gate cannot consume a full inventory at all.

**Impact**
- **Today on PC3: latent.** No experimental module has been loaded (README), and the current report
  is blocked for other reasons.
- **Becomes a real false clear** when the gate is re-run after a partial or failed canary that leaves a
  `hybrid580_*` module loaded, either on a host without signature policy, or once valid trust evidence
  exists (P1b).
- **What happens at load time then.**
  - `insmod` would fail with EEXIST.
  - Sonnet notes that `modprobe` without `--first-time` reports success for an already-loaded name
    (modprobe(8)). An older loaded build could then keep running while the report's
    `candidate_modules` hashes describe the new one (H8; depends on the canary's load procedure, which
    is not in the packet).
- **The report makes it worse.** `active_nvidia_modules` plus an empty
  `candidate_module_name_conflicts` reads as a complete check, and nothing discloses the `nvidia*`
  scope. If the owner meant to cover only stock-driver collisions, then README lines 5 and 12 and the
  report overstate the coverage. Either the code or the contract has to change.

**Minimal owner-side correction** (not implemented here)
1. **COLL 103–107:** put every `/proc/modules` name into `active_modules`. `loaded_nvidia_modules`
   may stay as the `nvidia`-filtered view, in which case COLL 274 is unchanged.
2. **COLL 271 and GATE 88:** replace `startswith('nvidia')` with a module-name grammar check, e.g. a
   non-empty `[A-Za-z0-9_-]+` fullmatch. This also closes R4.
3. **Mark the semantic change,** so an old prefix-filtered snapshot cannot pass as complete. Either bump
   the host-state schema (COLL 32 and the literal at COLL 180, GATE 19), or add a required
   `active_modules_scope: "all"`.
4. **Report:** compute conflicts against the full set (`active_nvidia_modules` can remain a display
   view), and add an inventory-scope field and count.
5. **Tests:** see §5 "Recommended tests" (per-role conflicts, collector-parser test, scope rejection).

The narrowest alternative is to also admit the `hybrid580` prefix in all three places. It works, but it
couples COLL to GATE's `ROLE_NAMES`.

### D2 (low, latent, fail-closed): the collector's validator rejects the collector's own stored snapshot

*Found by Sonnet's F6; confirmed by execution.*

- **Mechanism.** `make_report` (COLL 310–327) adds
  `collector_metadata.transport.{credential_host, credential_value_logged, credential_value_persisted}`
  (COLL 324–325). `validate_host_state` starts with `_check_no_sensitive_material` (COLL 239), whose
  `SENSITIVE_KEY` (COLL 45) matches `credential`.
- **Execution.**
  - `validate_host_state(raw_state)` → `ok`.
  - `validate_host_state(make_report(raw_state, 'user@pc3', 'pc6'))` →
    `ValueError: sensitive field is forbidden in host-state snapshot: snapshot.collector_metadata.transport.credential_host`.
  - The gate accepts the same stored report and returns `static-preflight-clear`, because the gate
    validates nothing about provenance.
- **Impact.** No effect on today's gate output. But any re-validation of a stored evidence file
  fails, and so would the natural remediation for R2 ("have the gate reuse the collector's validator"):
  every real snapshot would be rejected.
- **Minimal correction.** Validate stored snapshots as `validate_host_state` applied to the state
  without `collector_metadata`, and check the metadata with its own small schema. Alternatively, rename
  the three transport keys so they do not match `SENSITIVE_KEY`, and bump `COLLECTOR_SCHEMA`.
  - Add the round-trip test `validate_host_state(make_report(...))`.

## 4. Risks (mechanism proven by execution; harm depends on snapshot handling)

### R1: no freshness or boot binding for the inventory (stale inventory → false clear)
- **The timestamp is not enforced.** GATE `_validate_inputs` (55–113) never checks `observed_at_utc`;
  GATE 249 only echoes it. COLL checks its format only (255–257), never its age.
  - P5a (absent), P5b (`2019-01-01T00:00:00Z`) and P5c (`not-a-time`) all give
    `static-preflight-clear`. P5a reports `"observed_at_utc": null`.
  - COLL rejects P5c (`observation timestamp must be UTC RFC3339`).
  - The owner's fixture has no timestamp, yet TEST 579–589, 697–710 and 712–725 all reach a clear.
- **There is no boot binding.** COLL never collects `boot_id`: its `state` dict is COLL 179–200, and
  P11 lists `boot_id` as consumed but not collected. GATE binds `boot_id` only for signature-trust
  evidence (GATE 121, 128–129, 149), never for the module inventory.
- **What can go stale.** Any module loaded after the snapshot is invisible: autoloaders such as
  `nvidia-modprobe` or a first CUDA call (Sonnet F2), a manual load, or a reboot. The blocker text
  "is already loaded" (GATE 175–177) also speaks in the present tense about an undated snapshot.
- **Correction.**
  - In COLL: record `/proc/sys/kernel/random/boot_id`.
  - In GATE:
    - require an RFC3339 `observed_at_utc` and enforce a maximum age at evaluation time;
    - require the inventory's `boot_id` to equal the trust evidence's;
    - report `evaluated_at_utc` and the snapshot age.

### R2: the gate applies none of the collector's validation and checks no provenance
- **The gate accepts snapshots COLL would reject.**
  - The owner's fixture `host_state()` (TEST 68–86) lacks **7 of the 16** `REQUIRED_STATE_FIELDS`:
    `char_device_major_names`, `gpu_ownership`, `installed_nvidia_module`,
    `loaded_nvidia_module_version`, `loaded_nvidia_modules`, `local_module_signing_key_metadata`,
    `observed_at_utc`. COLL rejects it; the gate clears it (P5a).
  - Host `pc6` is accepted by the gate and by `validate_host_state` (P6). Only `make_report` enforces
    PC3 (COLL 312–313).
- **No provenance check.**
  - `collector_metadata` (COLL 319–326) is ignored and not propagated: the preflight report records
    only the snapshot file's hash (GATE 465–468).
  - No expected-digest input exists, so the link to the digest COLL prints (COLL 388–392) is manual.
- **Correction.** Share validation between COLL and GATE (fix D2 first). Require host `pc3` and
  `collector_metadata`, ideally checking `remote_script_sha256` against an allowlist and copying it
  into the preflight report.

### R3: the two copies of the inventory are never cross-checked
- **Mechanism.** COLL emits `active_modules` and `loaded_nvidia_modules` from one loop (101–107), and
  validates them independently (267–275). GATE reads only `active_modules`.
- **It also ignores the cross-evidence in the same snapshot:**
  - `loaded_nvidia_module_version`
  - `char_device_major_names`
  - `gpu_ownership[].driver`
  - `/dev/nvidia-uvm` in `active_char_devices`
- **Execution.**
  - P7: `active_modules: []`, `loaded_nvidia_modules: ["nvidia", "nvidia_uvm"]`, a `nvidia-uvm` major,
    and `nvidia` version set.
  - Sonnet's exact F3 trigger: `loaded_nvidia_modules: ["nvidia_uvm"]` plus a `/dev/nvidia-uvm` 511:0
    node.
  - In both, COLL validation → `ok` and the gate → `static-preflight-clear`.
- **Where it bites.** A truncated collection, or a merge or edit step, can empty `active_modules` and
  nothing notices. A merge step must exist for `boot_id` and `module_signature_trust` to appear at all
  (P11, H5).
- **Correction.** Require `set(loaded_nvidia_modules) == {n for n in active names if n.startswith('nvidia')}`
  (after D1), or drop the duplicate field. Optionally block on contradicting evidence such as a
  `/proc/devices` `nvidia-uvm` major.

### R4: names are only prefix-checked (silent non-match)
- **Accepted, never matching:** `nvidia_uvm ` (trailing space), `nvidia_uvm\n`, `nvidia_uvm\x00`,
  `nvidia_uvm.ko`, `nvidia_uvm [permanent]` and `nvidia‐uvm` (U+2010) all pass **both** validators.
  None matches, so each gives `static-preflight-clear` (P8, F4). The report even shows
  `"active_nvidia_modules": ["nvidia_uvm\u0000"]`.
- **Who can produce them.** Not the current collector, which uses `line.split()[0]` (COLL 104). The
  exposure is limited to other producers and edited snapshots. The candidate side is protected by the
  identity check (GATE 181).
- **Correction.** The grammar check from D1 step 2.

### R5 (adjacent to the primary scope): the device-number gate ignores the `/proc/devices` majors COLL collects
- **Mechanism.** COLL gathers `char_device_major_names` (122–133). GATE checks only `/dev` nodes
  (`active_char_devices`, 228–244).
- **Execution.** P10: stock `nvidia` loaded, `{"major": 195, "name": "nvidia"}` registered, no `/dev`
  nodes → `static-preflight-clear`. Yet the frontend's `register_chrdev_region(MKDEV(195, …))` would
  then collide.
- **Classification.** A risk, because whether PC3 can be in that state (driver loaded, nodes not yet
  created) depends on deployment. Sonnet flagged it as incidental too.
- **Correction.** Also block when `char_device_major_names` lists the layout major.

### R6 (low): report fields that can mislead (Sonnet F5; facts confirmed by reading GATE)
- `modules_loaded: false` and `modules_installed: false` (GATE 263–264) are constants meaning "this
  tool loaded nothing". They sit next to `active_nvidia_modules` listing loaded modules and a
  conflict, which invites the reading "nothing relevant is loaded".
- `active_nvidia_modules` (GATE 254) shows normalized, de-duplicated names. Raw spelling, count and
  source are lost.
- `evidence_refs` (GATE 463) is an unvalidated pass-through.
- `observed_at_utc` may be `null` (R1).
- **Correction.** Rename the constants (e.g. `tool_loaded_modules`), and add inventory scope, count,
  raw names and age.

## 5. Test coverage (proven by mutation on scratch copies)

Each mutant was run with `python3 -m unittest discover -s tests -p test_pc3_canary_preflight.py` in its
own scratch copy. Every run executed 37 tests. Control M0 (unmodified copy) → `OK`.

| Mutant | Mutation of GATE | Result | Meaning |
|---|---|---|---|
| M1 | drop `replace('-','_')` on active side (167) | killed (`test_candidate_module_name_conflicts_with_loaded_stock_uvm`) | active-side normalization pinned |
| M2 | drop `replace('-','_')` on candidate side (171) | survived | harmless: hyphenated candidates already fail identity (181) |
| M3 | compare only `role == 'uvm'` (172) | **survived** | `hybrid580_*` roles never exercised (D1) |
| M4 | `active_nvidia_modules` → constant `[]` (254) | **survived** | field never asserted |
| M5 | `candidate_module_name_conflicts` → constant `[]` (255) | **survived** | only asserted as `[]` on an empty inventory (TEST 520) |
| M6 | skip per-record validation (86–89) | **survived** | malformed records untested |
| M7 | drop `startswith('nvidia')` (88) | survived | prefix rule untested (also the D1 fix direction) |
| M8 | suppress the conflict blocker (175) | killed | blocker emission pinned |
| M9 | missing inventory treated as `[]` (84) | killed (`test_missing_loaded_module_inventory_fails_closed`) | requirement pinned |
| M11 | substring match instead of exact (172) | **survived** | exact-match semantics unpinned (would over-block) |
| M12 | status ignores `loaded_module_name_conflict` (251) | **survived** | **the core fail-closed property is unpinned** (Sonnet F7) |

**Why M12 survives.**
- The only positive conflict test (TEST 487–500) asserts neither `status` nor the conflict list.
- It uses `nvidia-uvm` (TEST 491), a spelling `/proc/modules` never prints.
- Its fixture has Secure Boot on and no trust evidence, so `signature_trust_unverified` makes the status
  `blocked` regardless.

**Other gaps.**
- The realistic `nvidia_uvm` conflict in the default fixture is computed but never asserted (TEST 475–485).
- No test imports COLL, calls GATE's `main()`, or calls `_parse_json_bytes`. The only `main(` in TEST is
  `unittest.main()` at line 730.
- The fixture is not a valid collector snapshot (R2), and its `active_modules` (TEST 77–80) mirrors
  the implementation's `nvidia*` assumption. This is how D1 escaped.

**Recommended tests** (owner-side, CPU-only; these would kill M3–M7, M11 and M12 and expose D1, D2 and R1–R4):
1. **Per role.** Policy off, no devices, `active_modules=[{'name': ROLE_NAMES[role]}]`. Expect
   `blocked`, blocker codes exactly `{loaded_module_name_conflict}`, and conflicts exactly
   `[{'role': role, 'name': ...}]`. Also assert the exact `active_nvidia_modules` (or the full
   inventory field after the fix). Today the three `hybrid580_*` roles raise `ValueError`.
2. **Negative.** `nvidia`, `nvidia_modeset`, `nvidia_drm`, `nvidia_peermem` without uvm → clear, `[]`
   conflicts. Current code passes this.
3. **Spelling matrix.**
   - `nvidia-uvm` → conflict.
   - Space, newline, NUL, `.ko`, U+2010 variants → `ValueError` after the grammar fix.
4. **Collector parser.** Synthetic `/proc/modules` containing `hybrid580_open …` through the inventory
   loop. Factor the loop into a function, or exec the script with a patched `read_text`.
5. **Contract round trip.** One fixture passes `validate_host_state`, then
   `validate_host_state(make_report(...))` (fails today, D2), then the gate.
6. **Freshness and provenance.** Missing, garbage or over-age `observed_at_utc` (injected clock),
   missing `boot_id`, `host != 'pc3'`, missing `collector_metadata` → rejected.
7. **Consistency.** `active_modules` vs `loaded_nvidia_modules` mismatch → rejected.
8. **CLI.** A conflict gives exit 1 with a JSON payload. A malformed inventory or a duplicate
   `active_modules` key gives exit 2.

Probe results against current code for items 1 (uvm role) and 2:
- F7-isolation → `blocked`, `["loaded_module_name_conflict"]`.
- F7-negative → `static-preflight-clear`, `[]`.

## 6. Focused test run (README command)

```
$ PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_pc3_canary_preflight.py -v
...
test_candidate_module_name_conflicts_with_loaded_stock_uvm (...) ... ok
test_missing_loaded_module_inventory_fails_closed (...) ... ok
...
----------------------------------------------------------------------
Ran 37 tests in 0.083s

OK
```
Python 3.12.3. This confirms the owner's "37 passed". It says nothing about D1, D2 or R1–R6, which no
test exercises.

## 7. Hypotheses (need evidence not in the packet)

| ID | Hypothesis | What would settle it | Source |
|---|---|---|---|
| H1 | `hybrid580_*` built from NVIDIA sources may export symbols a loaded stock `nvidia` already exports; the kernel refuses duplicate exports. The name gate does not model this; the report disclaims load readiness (GATE 252, 263–266) but `[]` conflicts can be over-read | compare candidate and stock export tables offline | mine, Sonnet F8 |
| H2 | Built-in modules are absent from `/proc/modules` but occupy `/sys/module/<name>` | also list `/sys/module`; unlikely for these names | mine, Sonnet F8 |
| H3 | GATE compares the `.modinfo` `name` (GATE 407–418); the kernel's duplicate check uses `struct module`'s name. Same for kbuild output; would diverge only for a crafted object | compare with the ELF `this_module` name | mine, Sonnet F8 |
| H4 | "Loaded **stock** module" (README 19) is an inference: the inventory holds names only and cannot tell stock `nvidia_uvm` from a leftover candidate. The outcome (blocked) is the same | collect `srcversion` or version per loaded module | mine |
| H5 | The owner's PC3 report used either raw COLL output (then trust can never verify, matching its signature blocker) or a merged file whose merge step was not reviewed and could alter `active_modules` (R3) or attach a fresh `boot_id` to a stale inventory (R1) | the owner's snapshot, report and merge tool | mine, Sonnet F2 |
| H6 | An installed stock `nvidia_uvm.ko` could be autoloaded by alias or softdep after the snapshot. COLL collects installed metadata only for `nvidia` (COLL 64–75) | review modprobe config and udev rules | Sonnet F8 |
| H7 | `/proc/driver/nvidia` or PCI driver-name clashes between candidates and stock modules | candidate source or `modinfo` | Sonnet F8 |
| H8 | With `modprobe` (no `--first-time`) an older loaded `hybrid580_*` build silently stays in place under D1 | the canary's load procedure | Sonnet F1 |

## 8. Checked and found sound

- **Malformed inventories fail closed.**
  - A missing, `null`, dict or string inventory raises `active_modules must be a list` (P9; TEST 502–508).
  - Non-object records, missing `name` and non-string names raise
    `active NVIDIA module record is invalid` (P9).
- **Duplicate JSON keys are rejected.** `duplicate JSON key: active_modules` (P9; GATE 426–434). COLL
  does the same (205–211).
- **Name matching.**
  - Active-side hyphen normalization works: `nvidia-uvm` → conflict (P8).
  - Matching is exact: `nvidia_uvm_tools` and `nvidia` do not conflict (P8).
  - `NVIDIA_UVM` is rejected, which is over-strict but fail-closed.
- **The collector loop is conservative.** It keeps every module state and refcount, uses `split()[0]`
  (no whitespace), and preserves raw spelling (COLL 103–107).
- **Status and disclaimers.**
  - The status derives only from `blockers` (GATE 251).
  - Readiness flags are constant `false`, with `qualification: static-preflight-only`.
  - A host-supplied `signature_trust_verified: true` is ignored (TEST 568–577).
- **Exit codes.** 0 clear, 1 blocked, 2 handled error (GATE 493–496). An unhandled exception exits 1
  with no payload, so it is never a clear.
- **File reads.** The snapshot is read with symlink refusal and a stat-identity check (GATE 270–288).

## 9. Reconciliation with the independent Sonnet 5.5 review

- **How it was obtained.** Custom subagent `sonnet-reviewer` via the Agent (Task) tool, model Sonnet
  5.5 (`agents.json`: `claude-sonnet-5-5`), tools Read, Glob and Grep only. The brief contained the
  README question, the file paths and the output format. It contained none of my findings, and it was
  launched before my probes ran.
- **Its limits.** It executed nothing, so I executed every claim that iteration-1 probes had not
  already covered (`probe_reconcile.py`, mutant M12).

| Sonnet finding | Its class | My evidence | Verdict | Report ID |
|---|---|---|---|---|
| F1: 3 of 4 names can never conflict | proven defect | P1, P1b, P2, P3, M3 | **confirmed**, found independently | D1 (+H8 from its modprobe note) |
| F2: no freshness, boot, host or provenance binding | risk | P5a/b/c, P6, P11 | **confirmed**; adopted its autoload staleness mechanism and its merge-tool hypothesis | R1, R2, H5 |
| F3: no completeness or consistency check | risk | P7, plus its exact trigger executed (F3 probe) | **confirmed** | R3 |
| F4: non-canonical names accepted | risk | P8, plus its NUL case executed (F4 probe) | **confirmed** | R4 |
| F5: misleading report fields | proven facts, low | GATE 175–177, 249, 254–255, 263–266, 463 read | **confirmed** as low-impact wording issues. The "`active_modules` implies in use" point is cosmetic only, since COLL keeps refcount-0 modules | R6, R1 |
| F6: collector validator rejects its own stored output | proven, low | F6 probe: `sensitive field is forbidden … credential_host`; fixture missing 7/16 fields | **confirmed**; I had missed it. It invalidated my draft R2 correction ("share one validator"), which is now amended | D2, R2 |
| F7: conflict test adequacy and surviving mutants | proven | M3, M4, M5, M7, M11 survive (mine); its predicted "status ignores conflict" mutant executed as M12 → survived | **confirmed** | §5 |
| F7: `main()` and parser untested | proven | grep: only `unittest.main()` at TEST 730 | **confirmed**. My first regex probe falsely reported `calls_main: true` by matching `unittest.main()`; corrected | §5 |
| F8: symbol, alias/softdep, built-in, `/proc/driver`, PCI name, modinfo-vs-`this_module` | hypotheses | not in packet | **accepted as hypotheses**, unverified | H1–H3, H6, H7 |
| Incidental: `char_device_major_names` unused | — | P10, P11 | **confirmed** | R5 |
| Incidental: uncaught exception exits 1 | — | read GATE 493–500 | **confirmed**, fail-closed | §8 |
| "Not checked: 37-pass claim; collector unimportable" | — | I ran the suite (37 OK) and executed COLL with a stubbed transport | **resolved** | §6, §2 |

- **Disagreements: none of substance.** Sonnet rates F1's likelihood "medium". I agree: it needs a
  prior experimental load, which is exactly what the canary workflow will produce.
- **What I contributed beyond Sonnet.**
  - Execution of every claim (the collector loop run verbatim, end-to-end false clears with and
    without signature policy).
  - The mutation matrix.
  - The executed P10 consequence of R5.
  - H4.
  - Acceptance of host `pc6` even by `validate_host_state` (P6).
  - The missing propagation of `collector_metadata` into the preflight report.

## 10. Unresolved and out of reach

- **Not in the packet:** the owner's fresh PC3 snapshot and preflight report (`evidence/` is empty);
  `tools/run_pc3_v100_guest_reference`; any merge step that adds `boot_id`/`module_signature_trust`;
  the canary load procedure.
- **Deliberately not executed** (no module loads allowed): the kernel and kmod behaviors cited
  (EEXIST on a duplicate name, `modprobe --first-time` semantics, duplicate-symbol refusal,
  `register_chrdev_region` EBUSY). They are stated as documented behavior, not tested.

## 11. Decision

**Changes required** (`DECISION.json`):
- The gate is **not accepted as a complete loaded-module collision check**, because of D1. D2 must be
  fixed before validation can be shared.
- The current PC3 `blocked` outcome stands and is not a false clear.
- No `static-preflight-clear` produced by this version should be relied on for the absence of loaded
  `hybrid580_*` modules or for inventory freshness.
