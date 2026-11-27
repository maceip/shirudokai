// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Qualification status for the carried kernel patches 0020..0024. Kept
 * outside the target binary so test-only reporting does not enter the TCB.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "kernel_abi.h"
#include "kernel_patch_status.h"

#define BTF_MAX_UNWRAP	32

const char *kernel_patch_readiness_name(enum kernel_patch_readiness readiness)
{
	switch (readiness) {
	case KERNEL_PATCH_BTF_READY:
		return "btf_ready";
	case KERNEL_PATCH_RUNTIME_ONLY:
		return "runtime_only";
	case KERNEL_PATCH_MISSING:
	default:
		return "missing";
	}
}

static const struct btf_type *unwrap_type(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;
	int i;

	for (i = 0; i < BTF_MAX_UNWRAP; i++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return NULL;
		if (!btf_is_typedef(t) && !btf_is_mod(t))
			return t;
		id = t->type;
	}
	return NULL;
}

static const struct btf_member *find_member(const struct btf *btf,
					    const struct btf_type *t,
					    const char *name,
					    __u32 *index)
{
	const struct btf_member *members = btf_members(t);
	__u32 i;

	for (i = 0; i < btf_vlen(t); i++) {
		const char *member_name =
			btf__name_by_offset(btf, members[i].name_off);

		if (member_name && strcmp(member_name, name) == 0) {
			*index = i;
			return &members[i];
		}
	}
	return NULL;
}

static bool has_func(const struct btf *btf, const char *name)
{
	return btf__find_by_name_kind(btf, name, BTF_KIND_FUNC) > 0;
}

static __printf(5, 6) void
set_patch(struct kernel_patch_status *out, enum kernel_patch_id id,
	  __u32 number, const char *name,
	  const char *fmt, ...)
{
	struct kernel_patch_entry *e = &out->patches[id];
	va_list ap;

	e->number = number;
	e->name = name;
	va_start(ap, fmt);
	if (vstrsprintf(e->detail, sizeof(e->detail), fmt, ap) < 0)
		strscpy_literal(e->detail, "?");
	va_end(ap);
}

static void record_patch(struct kernel_patch_status *out,
			 enum kernel_patch_id id,
			 enum kernel_patch_readiness readiness)
{
	out->patches[id].readiness = readiness;
	if (readiness == KERNEL_PATCH_BTF_READY)
		out->n_btf_ready++;
	else if (readiness == KERNEL_PATCH_RUNTIME_ONLY)
		out->n_runtime_only++;
	else
		out->n_missing++;
}

static bool has_trusted_dentry_parent(const struct btf *btf)
{
	const struct btf_type *safe, *dentry, *ptr, *target;
	const struct btf_member *parent;
	__u32 member_idx;
	int safe_id, dentry_id;

	safe_id = btf__find_by_name_kind(btf, "dentry__safe_trusted_or_null",
					 BTF_KIND_STRUCT);
	dentry_id = btf__find_by_name_kind(btf, "dentry", BTF_KIND_STRUCT);
	if (safe_id < 0 || dentry_id < 0)
		return false;
	safe = btf__type_by_id(btf, (__u32)safe_id);
	dentry = btf__type_by_id(btf, (__u32)dentry_id);
	if (!safe || !dentry)
		return false;
	parent = find_member(btf, safe, "d_parent", &member_idx);
	if (!parent || btf_member_bitfield_size(safe, member_idx) != 0)
		return false;
	ptr = unwrap_type(btf, parent->type);
	if (!ptr || !btf_is_ptr(ptr))
		return false;
	target = unwrap_type(btf, ptr->type);
	return target == dentry;
}

static void check_sleepable_inode_patch(const struct btf *btf,
					struct kernel_patch_status *out)
{
	static const char *const sleepable_hooks[] = {
		"inode_copy_up",
		"inode_file_setattr",
		"inode_link",
		"inode_mkdir",
		"inode_remove_acl",
		"inode_set_acl",
	};
	char missing[KERNEL_ABI_DETAIL_MAX] = "";
	char fn[LSM_HOOK_NAME_MAX + 8];
	size_t i, n_missing = 0, len = 0;
	int ret;

	for (i = 0; i < ARRAY_SIZE(sleepable_hooks); i++) {
		if (strsprintf(fn, sizeof(fn), "bpf_lsm_%s",
			       sleepable_hooks[i]) >= 0 && has_func(btf, fn))
			continue;
		ret = strsprintf(missing + len, sizeof(missing) - len, "%s%s",
				 n_missing ? ", " : "", sleepable_hooks[i]);
		if (ret > 0)
			len += (size_t)ret;
		n_missing++;
	}
	if (!n_missing) {
		set_patch(out, KERNEL_PATCH_0022_SLEEPABLE_INODE, 22,
			  "sleepable_inode_hooks",
			  "6 inode LSM hooks present; whether they take sleepable programs shows only at attach");
		record_patch(out, KERNEL_PATCH_0022_SLEEPABLE_INODE,
			     KERNEL_PATCH_RUNTIME_ONLY);
		return;
	}
	set_patch(out, KERNEL_PATCH_0022_SLEEPABLE_INODE, 22,
		  "sleepable_inode_hooks", "missing LSM hook%s: %s",
		  n_missing > 1 ? "s" : "", missing);
	record_patch(out, KERNEL_PATCH_0022_SLEEPABLE_INODE,
		     KERNEL_PATCH_MISSING);
}

int kernel_abi_patch_status_btf(const struct btf *btf,
				struct kernel_patch_status *out)
{
	static const struct {
		__u32		number;
		const char	*name;
	} meta[KERNEL_PATCH__MAX] = {
		[KERNEL_PATCH_0020_TPM_COMMAND] = { 20, "tpm_command" },
		[KERNEL_PATCH_0021_XATTR_UNPRIV] = { 21, "security_bpf_xattr" },
		[KERNEL_PATCH_0022_SLEEPABLE_INODE] = {
			22, "sleepable_inode_hooks",
		},
		[KERNEL_PATCH_0023_TRUSTED_D_PARENT] = {
			23, "trusted_dentry_parent",
		},
		[KERNEL_PATCH_0024_MM_READ_ACCESS] = { 24, "mm_read_access" },
	};
	size_t i;

	if (!out)
		return -EINVAL;
	*out = (struct kernel_patch_status){};
	if (!btf) {
		for (i = 0; i < KERNEL_PATCH__MAX; i++) {
			set_patch(out, (enum kernel_patch_id)i,
				  meta[i].number, meta[i].name,
				  "kernel BTF is unavailable");
			record_patch(out, (enum kernel_patch_id)i,
				     KERNEL_PATCH_MISSING);
		}
		return -EOPNOTSUPP;
	}

	out->signed_loader_abi = kernel_abi_validate_loader_btf(btf, NULL, 0) == 0;

	if (has_func(btf, "bpf_lsm_tpm_command")) {
		set_patch(out, KERNEL_PATCH_0020_TPM_COMMAND, 20, "tpm_command",
			  "bpf_lsm_tpm_command present");
		record_patch(out, KERNEL_PATCH_0020_TPM_COMMAND,
			     KERNEL_PATCH_BTF_READY);
	} else {
		set_patch(out, KERNEL_PATCH_0020_TPM_COMMAND, 20, "tpm_command",
			  "bpf_lsm_tpm_command missing");
		record_patch(out, KERNEL_PATCH_0020_TPM_COMMAND,
			     KERNEL_PATCH_MISSING);
	}

	if (has_func(btf, "bpf_get_dentry_xattr") &&
	    has_func(btf, "bpf_get_file_xattr")) {
		set_patch(out, KERNEL_PATCH_0021_XATTR_UNPRIV, 21,
			  "security_bpf_xattr",
			  "xattr kfuncs present; the read without the caller's permission shows only at run time");
		record_patch(out, KERNEL_PATCH_0021_XATTR_UNPRIV,
			     KERNEL_PATCH_RUNTIME_ONLY);
	} else {
		set_patch(out, KERNEL_PATCH_0021_XATTR_UNPRIV, 21,
			  "security_bpf_xattr",
			  "bpf_get_dentry_xattr or bpf_get_file_xattr missing");
		record_patch(out, KERNEL_PATCH_0021_XATTR_UNPRIV,
			     KERNEL_PATCH_MISSING);
	}

	check_sleepable_inode_patch(btf, out);

	if (has_trusted_dentry_parent(btf)) {
		set_patch(out, KERNEL_PATCH_0023_TRUSTED_D_PARENT, 23,
			  "trusted_dentry_parent",
			  "dentry__safe_trusted_or_null.d_parent present");
		record_patch(out, KERNEL_PATCH_0023_TRUSTED_D_PARENT,
			     KERNEL_PATCH_BTF_READY);
	} else {
		set_patch(out, KERNEL_PATCH_0023_TRUSTED_D_PARENT, 23,
			  "trusted_dentry_parent",
			  "struct dentry__safe_trusted_or_null.d_parent missing");
		record_patch(out, KERNEL_PATCH_0023_TRUSTED_D_PARENT,
			     KERNEL_PATCH_MISSING);
	}

	if (has_func(btf, "bpf_lsm_mm_read_access")) {
		set_patch(out, KERNEL_PATCH_0024_MM_READ_ACCESS, 24,
			  "mm_read_access", "bpf_lsm_mm_read_access present");
		record_patch(out, KERNEL_PATCH_0024_MM_READ_ACCESS,
			     KERNEL_PATCH_BTF_READY);
	} else {
		set_patch(out, KERNEL_PATCH_0024_MM_READ_ACCESS, 24,
			  "mm_read_access", "bpf_lsm_mm_read_access missing");
		record_patch(out, KERNEL_PATCH_0024_MM_READ_ACCESS,
			     KERNEL_PATCH_MISSING);
	}

	return out->signed_loader_abi && out->n_missing == 0 ? 0 : -EOPNOTSUPP;
}

int kernel_abi_patch_status(struct kernel_patch_status *out)
{
	struct btf *btf;
	int ret;

	if (!out)
		return -EINVAL;
	btf = btf__load_vmlinux_btf();
	if (libbpf_get_error(btf))
		return kernel_abi_patch_status_btf(NULL, out);
	ret = kernel_abi_patch_status_btf(btf, out);
	btf__free(btf);
	return ret;
}
