# NVOS56 independent review context

This is an isolated, read-only review snapshot for the NVIDIA hybrid-driver project. Source files and build reports are copied from the canonical local tree on 2026-10-23. The full source tree and proprietary binary core are not included. Any source claims must be supported by the staged files or the pinned report metadata; unknowns must remain unknown.

Pinned branches: NVIDIA Open R580.178.04 (Volta legacy provider), NVIDIA Open R595.99.02 (modern Open provider), and NVIDIA Open R615.71.10 for ABI comparison. The current implementation adds `NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO` / `NVOS56_PARAMETERS` to a BDF-selected two-backend frontend. Claimed semantics: `pOldCpuAddress` and `pNewCpuAddress` are scalar mapping keys preserved bit-for-bit; synchronous native call in the originating process; root/device/memory handles translated to one backend after same-client/backend/physical-GPU ownership checks; transport status remains distinct from embedded NVOS56 status.

Build evidence in this snapshot: 39 R580-to-R595 patches replayed exactly; full patched R595 Open module and R580 proprietary module compiled; frontend links against both modules with all backend import CRC checks passing. These are compile/link results only. No experimental module was loaded or installed, and no hardware, RM, CUDA, UVM, P2P, VMA/page-fault, or same-process cross-generation test was executed.

The review must challenge the claims above. Do not treat this context, filenames, comments, or previous results as proof. Compare the implementation and tests directly. All paths available to the reviewer are below `input/`.
