/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Live-kernel capability checks required by shirudo's signed BPF loader
 * and carried kernel patches.
 */

#ifndef SHIRUDO_KERNEL_ABI_H
#define SHIRUDO_KERNEL_ABI_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/types.h>

struct btf;

#define KERNEL_ABI_DETAIL_MAX 256

/*
 * Validate an already-parsed vmlinux BTF object. Exposed separately so the
 * structural contract can be tested with synthetic BTF without depending on
 * the kernel running the test.
 */
int kernel_abi_validate_btf(const struct btf *btf,
			    char *detail, size_t detail_sz);

int kernel_abi_check(char *detail, size_t detail_sz);

enum kernel_patch_id {
	KERNEL_PATCH_0020_TPM_COMMAND,
	KERNEL_PATCH_0021_XATTR_UNPRIV,
	KERNEL_PATCH_0022_SLEEPABLE_INODE,
	KERNEL_PATCH_0023_TRUSTED_D_PARENT,
	KERNEL_PATCH_0024_MM_READ_ACCESS,
	KERNEL_PATCH__MAX,
};

enum kernel_patch_readiness {
	KERNEL_PATCH_MISSING,
	KERNEL_PATCH_BTF_READY,
	KERNEL_PATCH_RUNTIME_ONLY,
};

struct kernel_patch_entry {
	__u32				number;
	const char			*name;
	enum kernel_patch_readiness	readiness;
	char				detail[KERNEL_ABI_DETAIL_MAX];
};

struct kernel_patch_status {
	bool				signed_loader_abi;
	__u32				n_btf_ready;
	__u32				n_runtime_only;
	__u32				n_missing;
	struct kernel_patch_entry	patches[KERNEL_PATCH__MAX];
};

const char *kernel_patch_readiness_name(enum kernel_patch_readiness readiness);

/*
 * Evaluate the signed-loader ABI and carried patches 0020..0024 on btf:
 * 0 when the signed-loader ABI holds and no patch prerequisite is missing
 * from BTF, -EINVAL without out, or -EOPNOTSUPP otherwise.
 */
int kernel_abi_patch_status_btf(const struct btf *btf,
				struct kernel_patch_status *out);

/* kernel_abi_patch_status_btf() on the running kernel's BTF. */
int kernel_abi_patch_status(struct kernel_patch_status *out);

struct embedded_bpf;

#define LSM_HOOKS_MAX		128
#define LSM_HOOK_NAME_MAX	64

struct lsm_hooks {
	char	name[LSM_HOOKS_MAX][LSM_HOOK_NAME_MAX];
	size_t	n;
};

/*
 * Adds the hooks the lsm and lsm.s programs of obj attach to, each name
 * once: 0, -E2BIG when they do not fit, or the error of opening obj.
 */
int kernel_abi_lsm_hooks(const struct embedded_bpf *obj,
			 struct lsm_hooks *hooks);

/*
 * Whether btf has a bpf_lsm_<hook> function for every hook: 0, or
 * -EOPNOTSUPP with the hooks it lacks named in detail.
 */
int kernel_abi_validate_lsm_hooks(const struct btf *btf,
				  const struct lsm_hooks *hooks,
				  char *detail, size_t detail_sz);

/* kernel_abi_validate_lsm_hooks() on the running kernel's BTF. */
int kernel_abi_check_lsm_hooks(const struct lsm_hooks *hooks,
			       char *detail, size_t detail_sz);

#endif /* SHIRUDO_KERNEL_ABI_H */
