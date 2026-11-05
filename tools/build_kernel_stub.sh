#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(cd -- "$script_dir/.." && pwd -P)"
kernel_release="${1:-$(uname -r)}"
kernel_build="/lib/modules/${kernel_release}/build"

if [[ ! -f "${kernel_build}/Makefile" ]]; then
  printf 'kernel build tree unavailable: %s\n' "$kernel_build" >&2
  exit 2
fi

make -C "$kernel_build" M="${project_dir}/kernel-stub" modules
printf 'Built compile-only stub for kernel %s; it was not loaded or installed.\n' \
  "$kernel_release"
