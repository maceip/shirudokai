/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Qualification status for the carried kernel patches 0020..0024, used
 * by test-kernel-patches and unit tests only.
 */

#ifndef SHIRUDO_TEST_KERNEL_PATCH_STATUS_H
#define SHIRUDO_TEST_KERNEL_PATCH_STATUS_H

#include <stdbool.h>

#include <shirudo/types.h>

#include "kernel_abi.h"

struct btf;

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

#endif /* SHIRUDO_TEST_KERNEL_PATCH_STATUS_H */
