# PC3 R580 direct-kprobe observer

This GPL-only diagnostic module tests the direct Linux `register_kprobe()` path
for the stock R580 wrapper function `nvidia:rm_init_adapter`. Its default mode
records only a 64-bit entry count. The opt-in selector-path mode adds fixed
probes for `nvidia:_nv000790rm` and `nvidia:_nv031399rm`; those handlers also
only increment counters by default. The separately opt-in `capture_selector`
mode reads only `_nv031399rm`'s second register argument as one 32-bit scalar;
it never dereferences or emits a pointer. The optional `capture_state` mode
nofault-reads only the two documented `nv_state_t` scalar fields described by
the runner and emits no pointer values. The module does not issue RM/CUDA
calls, alter PCI state, or change the NVIDIA module on disk.

The default `arm=false` mode registers each requested probe disabled. That
exercises module-qualified symbol lookup and instruction preparation without
inserting an active breakpoint. `arm=true` briefly activates the probes through
the kernel kprobe API. Handlers do not allocate, log, lock, or sleep. Read-only
module parameters expose counters and, when requested, scalar samples.

The additional `--capture-lookup-callsite` mode is limited to the statically
pinned `nvidia:_nv031364rm+0x92` instruction. It samples the first three
32-bit call arguments without dereferencing them, uses a sequence-protected
snapshot, and counts dropped concurrent samples. The runner requires exactly
one callsite sample, no drops, one matching lookup-entry sample, and agreement
on the second argument. The emitted report therefore contains raw register
scalars: keep it mode 0600 and do not copy those values into shared notes. This
check confirms one observed callsite/lookup pair only; it does not establish
the argument's semantic meaning, branch selection, cache hit/miss, loaded
module identity, CUDA execution, or hybrid operation.

The opt-in `--capture-lookup-branch` mode also counts the fixed JBE at
`_nv031364rm+0xa81`, its target at `+0xd7e`, and the five statically verified
pre-jump instructions (`+0x31d`, `+0x9c1`, `+0xa94`, `+0xaaa`, `+0xdaa`) that
lead into the shared call setup at `+0x8c`. It is permitted only with active
selector-path and callsite capture. The probes count entries only; they do not
capture branch operands or mutate RM state. The 2026-10-22 bounded canary
paired one callsite/lookup sample with one hit at `+0xaaa`, while the JBE and
its target counters stayed at zero. This identifies a compatible predecessor
route in that observation window, not its causal trigger, same-stack-frame
pairing, CUDA behavior, or the descriptor-cache outcome. The exact guest
module build-id matches the installed module, but the embedded RM object
identity remains unverified.

Build against the exact guest kernel headers in a private scratch directory;
do not install this module into `/lib/modules` or enable it at boot. Use the
runner's `--build-only` mode first. Its `--active` mode is explicit and proceeds
only after a successful idle-GPU query; `--observe-selector-path` and
`--capture-state` require active mode. `--capture-selector` additionally
requires `--observe-selector-path`; its report passes only when exactly one
descriptor-lookup entry occurred during the trigger window and the read-only
sample is exactly eight hexadecimal digits. The runner registers probes disabled,
verifies their cleanup, then optionally arms the observation and unloads the
observer immediately. Do not unload or rebind the NVIDIA driver as part of this
test. A failed registration or unload stops the experiment for diagnosis.

Use `--build-only` before any active mode; it compiles and modposts without
loading the observer. Active runs remain bounded canaries on the stock guest
driver and require an idle-GPU check. They never install or replace the NVIDIA
driver.

Unrequested optional observations are reported as `null`. PCI-binding and
VM/firmware state are not measured and remain `null`; separate
`*_change_requested=false` fields describe the runner's scope. A positive
counter proves that a function was entered during the observation window. The
optional scalar capture reports only the latest second argument observed at
`_nv031399rm`; a single lookup delta ties that sample to one entry in the
window, but does not establish descriptor-cache hit/miss semantics or prove
CUDA execution or hybrid-driver behavior.
