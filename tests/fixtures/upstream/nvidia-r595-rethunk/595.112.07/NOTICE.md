# NVIDIA R595.112.07 source fixture

This fixture preserves upstream `src/nvidia/Makefile` and
`src/nvidia-modeset/Makefile` from NVIDIA Open GPU Kernel Modules commit
`d8257d95ae5fed364163e4df51db66df8b1ee0d2`. The core Makefile SHA-256 is
`a5b0653bd0142ca0d1ffeaac895750a3c76bd66f4d24b8ae9496bd04025112ee`; the
modeset Makefile SHA-256 is
`138c4f2777e03c68f5b2ffc1a7b31902af513315fda2b0522b93fb879db1f0a6`.
The upstream `COPYING` file is included beside it. The source tree states that
individual files are MIT-licensed except where noted otherwise.

The patches in `patches/r595.112.07/` add the compiler-supported x86
return-thunk flag to the existing conditional core and modeset compiler flags.
They do not contain binary driver code.
