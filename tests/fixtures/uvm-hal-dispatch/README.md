# UVM HAL dispatch source fixtures

These small source snapshots make the R580-to-R595 GV100 dispatch test
reproducible from a clean checkout without the ignored upstream download cache.

- `../upstream/nvidia-kernel-module-source/580.196.07/uvm_hal.c` is the
  `kernel-open/nvidia-uvm/uvm_hal.c` member from NVIDIA's 580.196.07 source
  subset archive, SHA-256
  `9e1c8c1e0e70d26328809713fc7af7f79e49a57a545ea474b36d70a07d56325d`.
- `../upstream/nvidia-open-gpu-kernel-modules/595.112.07/uvm_hal.c` is the
  unmodified file at NVIDIA Open GPU Kernel Modules commit
  `d8257d95ae5fed364163e4df51db66df8b1ee0d2`, SHA-256
  `d3815691e974e551b0fb51ac0d7c3101b31452a56f20f8ba4098e873f6673199`.
- `../candidates/r595112-gv100-hal-r580196/uvm_hal.c` is the exact generated
  HAL-table source from the isolated compile/link experiment, SHA-256
  `3a7c5f6f892102663af00fdcb9e638a3a96a2b8cddd00af25d9054169106c248`.
  `tools/probe_r595_gv100_complete_hal.py` adds six explicit GV100/Volta rows
  and required class-header includes, using callbacks resolved from the
  hash-pinned R580.196.07 source archive. The full probe receipt is
  [`evidence/r595112-gv100-hal-r580196-sanitized-v1-20261103.json`](../../../evidence/r595112-gv100-hal-r580196-sanitized-v1-20261103.json).

The source files retain NVIDIA's notices. The open-module file is MIT licensed;
the R580 source subset identifies its individual UVM source as MIT licensed.
The candidate is a test fixture, not an installed driver. Static dispatch
selection and a successful build do not establish RM class IDs on hardware,
UVM operation, CUDA execution, or stability.
