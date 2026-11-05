# Pinned upstream test fixture

These files are copied unmodified from NVIDIA's `nvidia-modprobe` repository at commit `4ffadd6b30c4c8ea7d17495c8b26c8ab2b4688b2`:

- `modprobe-utils/nvidia-modprobe-utils.c` — SHA-256 `0d293dc50bbcd26c4829408a63dd0dbcdc892c4ffb900620f761dbd112813f4d`
- `modprobe-utils/nvidia-modprobe-utils.h` — SHA-256 `c4d3501a09924ab3a2a7d73a7273598442af4995ae6e5263f6be938623a28541`
- `modprobe-utils/pci-enum.h` — SHA-256 `ba186befe87b3568da15c74fd0054338f8375be967b07f48c9aeb4e2f1c217cb`

Upstream source: <https://github.com/NVIDIA/nvidia-modprobe/tree/4ffadd6b30c4c8ea7d17495c8b26c8ab2b4688b2/modprobe-utils>.

The C files carry their upstream license notices. The test compiles this pinned implementation in a temporary directory and remaps only its `/proc/devices`, `/proc/sys/kernel/modprobe`, and `/sys/module` paths to synthetic files. Its harness simulates both unprivileged and root effective UIDs, but intercepts `posix_spawn()` and `waitpid()` so it never executes `modprobe`; the stub returns success without changing synthetic sysfs. PCI enumeration also returns a synthetic match. The harness calls only `nvidia_uvm_modprobe()` and `nvidia_get_chardev_major()`; it never calls a node-creation routine or touches host device nodes.
