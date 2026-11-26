# vendor/libbpf

Vendored copy of libbpf and the BPF UAPI headers shirudo builds against.
Normal builds use only this directory; no kernel tree or submodule is
needed. Refresh it on demand with

    make bpf-deps                       # clones bpf-next
    make bpf-deps KERNEL_SRC=/path/to/linux

which overwrites the copied files from `tools/lib/bpf/` and
`tools/include/uapi/linux/` of that tree, regenerates
`bpf/bpf_helper_defs.h` with the tree's `scripts/bpf_doc.py`, records the
source commit in `COMMIT`, and rebuilds `libbpf.a` as a check.

| Path | Origin | License |
|---|---|---|
| `bpf/*.c`, `bpf/*.h` | `tools/lib/bpf/` (verbatim, but see below) | `LGPL-2.1 OR BSD-2-Clause`; shirudo consumes the BSD branch |
| `bpf/bpf_helper_defs.h` | generated from `bpf.h` by `scripts/bpf_doc.py` | as libbpf |
| `include/uapi/linux/*.h` | `tools/include/uapi/linux/` (verbatim, but see below) | `GPL-2.0 WITH Linux-syscall-note`, `netdev.h` also `OR BSD-3-Clause`: the syscall note permits user programs to include them |
| `include/linux/*.h`, `include/asm/*.h` | shirudo-owned shims replacing the kernel's `tools/include` internals | BSD-2-Clause |
| `Makefile`, `README.md` | shirudo-owned | BSD-2-Clause |

The shims are the reason this copy builds outside the kernel tree: libbpf
reaches for a handful of `tools/include/linux` helpers (`ARRAY_SIZE`,
error pointers, byte-order conversion, the eBPF instruction constructors,
acquire/release ring-buffer accessors), all GPL-2.0-only in the kernel, so
shirudo provides its own definitions of exactly that surface. When an
update makes libbpf need a new helper, the `libbpf.a` rebuild at the end
of `bpf-deps` fails on the missing symbol; extend the shim.

`bpf/gen_loader.c` carries one local change on top of the recorded
commit: `MAX_USED_PROGS` is 64 instead of 32, as required by the
kernel-obs package. In addition `gen_loader.c` also supports reusing a
signer-selected map FD supplied through the loader context.
`bpf/btf_dump.c` preserves complete native GNU attribute spellings without
wrapping them twice, and reads an enum value at an address its size does
not divide by copying it to an aligned buffer, as it reads such an int,
where upstream reads it as a bitfield of no bits and shifts a `__u64` by
64. `include/uapi/linux/types.h` defines `__s128` and
`__u128` as the kernel's own `include/uapi/linux/types.h` does: it
shadows the system's copy, and the arm64 `asm/sigcontext.h` of current
kernel headers, which `<signal.h>` pulls in, uses `__u128`. In the
kernel tree `tools/include/linux/types.h` defines them first, which the
shims do not stand in for. `bpf/gen_loader.c`, `bpf/libbpf.c`,
`bpf/bpf_gen_internal.h` and `include/uapi/linux/bpf.h` carry the libbpf
`struct_ops`-by-name loader support so a generated loader names a
`struct_ops` map and its programs by the struct and members in the
object's BTF and stores the program FDs into the struct it updates.
`bpf-deps` overwrites these files, so
re-apply those changes after a refresh until they are upstream.

`.github/scripts/check-spdx.sh` holds every vendored `.c` and `.h` to
the licences in this table, so a refresh that brings in a file under
any other licence fails CI.
