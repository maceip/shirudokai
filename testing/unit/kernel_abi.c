// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "kernel_abi.h"
#include "loader.h"
#include "unit.h"

enum fixture {
	VALID,
	NO_MAP,
	NO_SHA,
	SHA_BITFIELD,
	SHA_NOT_ARRAY,
	SHA_LENGTH,
	SHA_WIDTH,
	SHA_SIGNED,
	NO_EXCL_PROG_SHA,
	EXCL_PROG_SHA_BITFIELD,
	EXCL_PROG_SHA_TYPE,
	EXCL_PROG_SHA_TARGET,
	NO_PROG_AUX,
	NO_SIG,
	SIG_TYPE,
	NO_KEYRING_SERIAL,
	KEYRING_SERIAL_WIDTH,
	NO_KEYRING_TYPE,
	KEYRING_TYPE_WIDTH,
	NO_VERDICT,
	VERDICT_SIGNED,
	NO_TPM_COMMAND,
	NO_MM_READ_ACCESS,
	TRAILING_DRIFT,
};

static struct btf *make_fixture(enum fixture fixture)
{
	int raw_u8, raw_u32, u8, u16, u32, s8, s32, index, proto;
	int sha32, sha31, sha_u16, sha_s8, byte_ptr, u32_ptr;
	int sig_struct = -1;
	struct btf *btf;
	int ret;

	btf = btf__new_empty();
	if (libbpf_get_error(btf))
		return NULL;
	raw_u8 = btf__add_int(btf, "unsigned char", 1, BTF_INT_CHAR);
	u16 = btf__add_int(btf, "u16", 2, 0);
	raw_u32 = btf__add_int(btf, "unsigned int", 4, 0);
	s8 = btf__add_int(btf, "s8", 1, BTF_INT_SIGNED);
	s32 = btf__add_int(btf, "s32", 4, BTF_INT_SIGNED);
	index = btf__add_int(btf, "index", 4, 0);
	u8 = btf__add_typedef(btf, "u8", raw_u8);
	u32 = btf__add_typedef(btf, "u32", raw_u32);
	sha32 = btf__add_array(btf, index, u8, 32);
	sha31 = btf__add_array(btf, index, u8, 31);
	sha_u16 = btf__add_array(btf, index, u16, 32);
	sha_s8 = btf__add_array(btf, index, s8, 32);
	byte_ptr = btf__add_ptr(btf, raw_u8);
	u32_ptr = btf__add_ptr(btf, u32);
	proto = btf__add_func_proto(btf, s32);
	if (raw_u8 < 0 || raw_u32 < 0 || u8 < 0 || u16 < 0 || u32 < 0 ||
	    s8 < 0 || s32 < 0 || index < 0 || sha32 < 0 || sha31 < 0 ||
	    sha_u16 < 0 || sha_s8 < 0 || byte_ptr < 0 || u32_ptr < 0 ||
	    proto < 0)
		goto err;

	if (fixture != NO_MAP) {
		ret = btf__add_struct(btf, "bpf_map", 64);
		if (ret < 0)
			goto err;
		if (fixture != NO_SHA) {
			int sha_type = sha32;
			__u32 bit_sz = 0;

			if (fixture == SHA_BITFIELD) {
				sha_type = u32;
				bit_sz = 4;
			} else if (fixture == SHA_NOT_ARRAY) {
				sha_type = u32;
			} else if (fixture == SHA_LENGTH) {
				sha_type = sha31;
			} else if (fixture == SHA_WIDTH) {
				sha_type = sha_u16;
			} else if (fixture == SHA_SIGNED) {
				sha_type = sha_s8;
			}
			if (btf__add_field(btf, "sha", sha_type, 0, bit_sz) < 0)
				goto err;
		}
		if (fixture != NO_EXCL_PROG_SHA) {
			int excl_type = byte_ptr;
			__u32 bit_sz = 0;

			if (fixture == EXCL_PROG_SHA_BITFIELD) {
				excl_type = u32;
				bit_sz = 4;
			} else if (fixture == EXCL_PROG_SHA_TYPE) {
				excl_type = u32;
			} else if (fixture == EXCL_PROG_SHA_TARGET) {
				excl_type = u32_ptr;
			}
			if (btf__add_field(btf, "excl_prog_sha", excl_type,
					   256, bit_sz) < 0)
				goto err;
		}
		if (fixture == TRAILING_DRIFT &&
		    btf__add_field(btf, "future_map_field", u32, 320, 0) < 0)
			goto err;
	}

	if (fixture == NO_PROG_AUX)
		return btf;
	if (fixture != SIG_TYPE) {
		sig_struct = btf__add_struct(btf, NULL, 8);
		if (sig_struct < 0)
			goto err;
		if (fixture != NO_KEYRING_SERIAL &&
		    btf__add_field(btf, "keyring_serial",
				   fixture == KEYRING_SERIAL_WIDTH ? s8 : s32,
				   0, 0) < 0)
			goto err;
		if (fixture != NO_KEYRING_TYPE &&
		    btf__add_field(btf, "keyring_type",
				   fixture == KEYRING_TYPE_WIDTH ? u32 : u8,
				   32, 0) < 0)
			goto err;
		if (fixture != NO_VERDICT &&
		    btf__add_field(btf, "verdict",
				   fixture == VERDICT_SIGNED ? s8 : u8,
				   40, 0) < 0)
			goto err;
	}
	ret = btf__add_struct(btf, "bpf_prog_aux", 32);
	if (ret < 0)
		goto err;
	if (fixture != NO_SIG &&
	    btf__add_field(btf, "sig",
			   fixture == SIG_TYPE ? u32 : sig_struct,
			   0, 0) < 0)
		goto err;
	if (fixture == TRAILING_DRIFT &&
	    btf__add_field(btf, "future_aux_field", u32, 64, 0) < 0)
		goto err;
	if (fixture != NO_TPM_COMMAND &&
	    btf__add_func(btf, "bpf_lsm_tpm_command", BTF_FUNC_GLOBAL,
			  proto) < 0)
		goto err;
	if (fixture != NO_MM_READ_ACCESS &&
	    btf__add_func(btf, "bpf_lsm_mm_read_access", BTF_FUNC_GLOBAL,
			  proto) < 0)
		goto err;
	return btf;

err:
	btf__free(btf);
	return NULL;
}

static void check(enum fixture fixture, int want_ok, const char *want)
{
	char detail[KERNEL_ABI_DETAIL_MAX] = {};
	struct btf *btf = make_fixture(fixture);
	int ret;

	ASSERT_TRUE(btf);
	ret = kernel_abi_validate_btf(btf, detail, sizeof(detail));
	btf__free(btf);
	if (want_ok) {
		EXPECT_EQ(ret, 0);
		return;
	}
	EXPECT_NE(ret, 0);
	UNIT_CHECK(0, str_contains(detail, want), "detail \"%s\" lacks \"%s\"",
		   detail, want);
}

static void needs_btf(void)
{
	char detail[KERNEL_ABI_DETAIL_MAX] = {};

	EXPECT_EQ(kernel_abi_validate_btf(NULL, detail, sizeof(detail)),
		  -EOPNOTSUPP);
	EXPECT_TRUE(str_contains(detail, "kernel BTF is unavailable"));
	EXPECT_EQ(kernel_abi_validate_btf(NULL, NULL, 0), -EOPNOTSUPP);
}

static void accepts_the_required_prefix(void)
{
	check(VALID, 1, NULL);
}

static void accepts_fields_past_the_prefix(void)
{
	check(TRAILING_DRIFT, 1, NULL);
}

static void needs_struct_bpf_map(void)
{
	check(NO_MAP, 0, "no struct bpf_map");
}

static void needs_map_sha(void)
{
	check(NO_SHA, 0, "bpf_map.sha is missing");
}

static void needs_map_sha_non_bitfield_and_array(void)
{
	check(SHA_BITFIELD, 0, "non-bitfield");
	check(SHA_NOT_ARRAY, 0, "u8[32]");
}

static void needs_map_sha_of_32_bytes(void)
{
	check(SHA_LENGTH, 0, "u8[32]");
}

static void needs_map_sha_of_bytes(void)
{
	check(SHA_WIDTH, 0, "u8[32]");
}

static void needs_map_sha_unsigned(void)
{
	check(SHA_SIGNED, 0, "u8[32]");
}

static void needs_excl_prog_sha(void)
{
	check(NO_EXCL_PROG_SHA, 0, "bpf_map.excl_prog_sha is missing");
}

static void needs_excl_prog_sha_non_bitfield(void)
{
	check(EXCL_PROG_SHA_BITFIELD, 0, "non-bitfield");
}

static void needs_excl_prog_sha_pointer(void)
{
	check(EXCL_PROG_SHA_TYPE, 0, "must have pointer type");
}

static void needs_excl_prog_sha_byte_pointer(void)
{
	check(EXCL_PROG_SHA_TARGET, 0, "must point to a byte");
}

static void needs_struct_bpf_prog_aux(void)
{
	check(NO_PROG_AUX, 0, "no struct bpf_prog_aux");
}

static void needs_prog_aux_sig(void)
{
	check(NO_SIG, 0, "bpf_prog_aux.sig is missing");
}

static void needs_sig_struct(void)
{
	check(SIG_TYPE, 0, "sig must have struct type");
}

static void needs_keyring_serial(void)
{
	check(NO_KEYRING_SERIAL, 0, "keyring_serial must have type s32");
}

static void needs_keyring_serial_s32(void)
{
	check(KEYRING_SERIAL_WIDTH, 0, "keyring_serial must have type s32");
}

static void needs_keyring_type(void)
{
	check(NO_KEYRING_TYPE, 0, "keyring_type must have type u8");
}

static void needs_keyring_type_u8(void)
{
	check(KEYRING_TYPE_WIDTH, 0, "keyring_type must have type u8");
}

static void needs_verdict(void)
{
	check(NO_VERDICT, 0, "verdict must have type u8");
}

static void needs_verdict_unsigned(void)
{
	check(VERDICT_SIGNED, 0, "verdict must have type u8");
}

static void needs_tpm_command(void)
{
	check(NO_TPM_COMMAND, 0, "tpm_command LSM hook is missing");
}

static void needs_mm_read_access(void)
{
	check(NO_MM_READ_ACCESS, 0, "mm_read_access LSM hook is missing");
}

/* Add the BTF symbols of carried patches 0021..0023 to an ABI fixture. */
static int add_carried_patch_btf(struct btf *btf, bool add_xattr,
				 const char *skip_inode_hook)
{
	static const char *const funcs[] = {
		"bpf_get_dentry_xattr",
		"bpf_get_file_xattr",
		"bpf_lsm_inode_copy_up",
		"bpf_lsm_inode_file_setattr",
		"bpf_lsm_inode_link",
		"bpf_lsm_inode_mkdir",
		"bpf_lsm_inode_remove_acl",
		"bpf_lsm_inode_set_acl",
	};
	int s32, proto;
	size_t i;

	s32 = btf__add_int(btf, "patch_int", 4, BTF_INT_SIGNED);
	proto = btf__add_func_proto(btf, s32);
	if (s32 < 0 || proto < 0)
		return -1;
	for (i = 0; i < ARRAY_SIZE(funcs); i++) {
		if (!add_xattr && i < 2)
			continue;
		if (skip_inode_hook && !strcmp(funcs[i], skip_inode_hook))
			continue;
		if (btf__add_func(btf, funcs[i], BTF_FUNC_GLOBAL, proto) < 0)
			return -1;
	}
	return 0;
}

static int add_self_referential_dentry(struct btf *btf)
{
	int mod, ptr, st;

	/*
	 * Point d_parent to the upcoming struct dentry id (mod + 2) so the
	 * synthetic BTF carries the self-referential struct pahole emits.
	 */
	mod = btf__add_const(btf, 1);
	if (mod < 0)
		return -1;
	ptr = btf__add_ptr(btf, mod + 2);
	st = btf__add_struct(btf, "dentry", 8);
	if (ptr < 0 || st != mod + 2)
		return -1;
	if (btf__add_field(btf, "d_parent", ptr, 0, 0) < 0)
		return -1;
	return 0;
}

static struct btf *make_patch_btf(enum fixture base, bool add_xattr,
				  const char *skip_inode_hook,
				  bool add_dentry_parent)
{
	struct btf *btf = make_fixture(base);

	if (!btf)
		return NULL;
	if (add_carried_patch_btf(btf, add_xattr, skip_inode_hook) < 0)
		goto err;
	if (add_dentry_parent && add_self_referential_dentry(btf) < 0)
		goto err;
	return btf;
err:
	btf__free(btf);
	return NULL;
}

static void patch_status_qualifies_complete_kernel(void)
{
	struct kernel_patch_status st;
	struct btf *btf;

	btf = make_patch_btf(VALID, true, NULL, true);
	ASSERT_TRUE(btf);

	EXPECT_EQ(kernel_abi_patch_status_btf(btf, &st), 0);
	EXPECT_TRUE(st.signed_loader_abi);
	EXPECT_UEQ(st.n_btf_ready, 2);
	EXPECT_UEQ(st.n_runtime_only, 3);
	EXPECT_UEQ(st.n_missing, 0);
	EXPECT_UEQ(st.patches[KERNEL_PATCH_0020_TPM_COMMAND].number, 20);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0020_TPM_COMMAND].readiness,
		  KERNEL_PATCH_BTF_READY);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0021_XATTR_UNPRIV].readiness,
		  KERNEL_PATCH_RUNTIME_ONLY);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0022_SLEEPABLE_INODE].readiness,
		  KERNEL_PATCH_RUNTIME_ONLY);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0023_TRUSTED_D_PARENT].readiness,
		  KERNEL_PATCH_RUNTIME_ONLY);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0024_MM_READ_ACCESS].readiness,
		  KERNEL_PATCH_BTF_READY);
	EXPECT_STREQ(kernel_patch_readiness_name(KERNEL_PATCH_BTF_READY),
		     "btf_ready");
	EXPECT_STREQ(kernel_patch_readiness_name(KERNEL_PATCH_RUNTIME_ONLY),
		     "runtime_only");
	EXPECT_STREQ(kernel_patch_readiness_name(KERNEL_PATCH_MISSING),
		     "missing");
	btf__free(btf);
}

static void patch_status_reports_missing_patches_on_stock_kernel(void)
{
	const char *detail;
	struct kernel_patch_status st;
	struct btf *btf;

	btf = make_patch_btf(NO_SHA, false, "bpf_lsm_inode_mkdir", false);
	ASSERT_TRUE(btf);
	EXPECT_EQ(kernel_abi_patch_status_btf(btf, &st), -EOPNOTSUPP);
	EXPECT_FALSE(st.signed_loader_abi);
	EXPECT_UEQ(st.n_btf_ready, 2);
	EXPECT_UEQ(st.n_missing, 3);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0021_XATTR_UNPRIV].readiness,
		  KERNEL_PATCH_MISSING);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0022_SLEEPABLE_INODE].readiness,
		  KERNEL_PATCH_MISSING);
	detail = st.patches[KERNEL_PATCH_0022_SLEEPABLE_INODE].detail;
	EXPECT_TRUE(str_contains(detail, "inode_mkdir"));
	EXPECT_EQ(st.patches[KERNEL_PATCH_0023_TRUSTED_D_PARENT].readiness,
		  KERNEL_PATCH_MISSING);
	btf__free(btf);

	btf = make_fixture(NO_TPM_COMMAND);
	ASSERT_TRUE(btf);
	EXPECT_EQ(kernel_abi_patch_status_btf(btf, &st), -EOPNOTSUPP);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0020_TPM_COMMAND].readiness,
		  KERNEL_PATCH_MISSING);
	btf__free(btf);

	btf = make_fixture(NO_MM_READ_ACCESS);
	ASSERT_TRUE(btf);
	EXPECT_EQ(kernel_abi_patch_status_btf(btf, &st), -EOPNOTSUPP);
	EXPECT_EQ(st.patches[KERNEL_PATCH_0024_MM_READ_ACCESS].readiness,
		  KERNEL_PATCH_MISSING);
	btf__free(btf);
}

static void patch_status_handles_null_and_live_btf(void)
{
	struct kernel_patch_status st;
	int ret;

	EXPECT_EQ(kernel_abi_patch_status_btf(NULL, NULL), -EINVAL);
	EXPECT_EQ(kernel_abi_patch_status(NULL), -EINVAL);
	EXPECT_EQ(kernel_abi_patch_status_btf(NULL, &st), -EOPNOTSUPP);
	EXPECT_FALSE(st.signed_loader_abi);
	EXPECT_UEQ(st.n_missing, KERNEL_PATCH__MAX);

	ret = kernel_abi_patch_status(&st);
	EXPECT_TRUE(ret == 0 || ret == -EOPNOTSUPP);
	EXPECT_UEQ(st.n_btf_ready + st.n_runtime_only + st.n_missing,
		   KERNEL_PATCH__MAX);
}

/* A BTF with a bpf_lsm_<hook> function for each hook but skip's. */
static struct btf *lsm_btf(const struct lsm_hooks *hooks, const char *skip)
{
	char function[LSM_HOOK_NAME_MAX + 8];
	int ret_type, proto;
	struct btf *btf;
	size_t i;

	btf = btf__new_empty();
	if (libbpf_get_error(btf))
		return NULL;
	ret_type = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	proto = btf__add_func_proto(btf, ret_type);
	if (ret_type < 0 || proto < 0)
		goto err;
	for (i = 0; i < hooks->n; i++) {
		if (skip && !strcmp(hooks->name[i], skip))
			continue;
		if (strsprintf(function, sizeof(function), "bpf_lsm_%s",
			       hooks->name[i]) < 0 ||
		    btf__add_func(btf, function, BTF_FUNC_GLOBAL, proto) < 0)
			goto err;
	}
	return btf;
err:
	btf__free(btf);
	return NULL;
}

static void hooks_of(struct lsm_hooks *hooks, const char *const *names,
		     size_t n)
{
	size_t i;

	hooks->n = 0;
	for (i = 0; i < n; i++)
		ASSERT_TRUE(strscpy(hooks->name[hooks->n++], names[i],
				    sizeof(hooks->name[0])) >= 0);
}

static void embedded_hooks(struct lsm_hooks *hooks)
{
	hooks->n = 0;
	ASSERT_EQ(kernel_abi_lsm_hooks(bpf2_blob(), hooks), 0);
	ASSERT_EQ(kernel_abi_lsm_hooks(seal_blob(), hooks), 0);
}

static bool has_hook(const struct lsm_hooks *hooks, const char *hook)
{
	size_t i;

	for (i = 0; i < hooks->n; i++)
		if (!strcmp(hooks->name[i], hook))
			return true;
	return false;
}

static void lsm_hooks_come_from_the_embedded_objects(void)
{
	static struct lsm_hooks hooks;
	size_t i, j;

	embedded_hooks(&hooks);
	EXPECT_TRUE(has_hook(&hooks, "bpf"));
	EXPECT_TRUE(has_hook(&hooks, "inode_unlink"));
	EXPECT_TRUE(has_hook(&hooks, "tpm_command"));
	EXPECT_TRUE(has_hook(&hooks, "mm_read_access"));
	EXPECT_FALSE(has_hook(&hooks, "lsm/bpf"));
	for (i = 0; i < hooks.n; i++)
		for (j = i + 1; j < hooks.n; j++)
			EXPECT_NE(strcmp(hooks.name[i], hooks.name[j]), 0);
}

static void lsm_hooks_all_present(void)
{
	static const char *const names[] = { "bpf", "file_open" };
	char detail[KERNEL_ABI_DETAIL_MAX] = {};
	static struct lsm_hooks hooks;
	struct btf *btf;

	hooks_of(&hooks, names, ARRAY_SIZE(names));
	btf = lsm_btf(&hooks, NULL);
	ASSERT_TRUE(btf);
	EXPECT_EQ(kernel_abi_validate_lsm_hooks(btf, &hooks, detail,
						sizeof(detail)), 0);
	EXPECT_STREQ(detail, "");
	btf__free(btf);
}

static void lsm_hooks_missing_are_named(void)
{
	static const char *const names[] = {
		"bpf", "file_open", "mm_read_access",
	};
	static const char *const two[] = { "bpf", "x_one", "x_two" };
	char detail[KERNEL_ABI_DETAIL_MAX] = {};
	static struct lsm_hooks hooks;
	struct btf *btf;

	hooks_of(&hooks, names, ARRAY_SIZE(names));
	btf = lsm_btf(&hooks, "mm_read_access");
	ASSERT_TRUE(btf);
	EXPECT_EQ(kernel_abi_validate_lsm_hooks(btf, &hooks, detail,
						sizeof(detail)), -EOPNOTSUPP);
	EXPECT_STREQ(detail, "kernel has no LSM hook mm_read_access; "
		     "boot a shirudo-patched kernel");
	btf__free(btf);

	hooks_of(&hooks, names, 1);
	btf = lsm_btf(&hooks, NULL);
	ASSERT_TRUE(btf);
	hooks_of(&hooks, two, ARRAY_SIZE(two));
	EXPECT_EQ(kernel_abi_validate_lsm_hooks(btf, &hooks, detail,
						sizeof(detail)), -EOPNOTSUPP);
	EXPECT_STREQ(detail, "kernel has no LSM hooks x_one, x_two; "
		     "boot a shirudo-patched kernel");
	btf__free(btf);
}

static void lsm_hooks_of_the_embedded_objects_checked(void)
{
	char detail[KERNEL_ABI_DETAIL_MAX] = {};
	static struct lsm_hooks hooks;
	struct btf *btf;

	embedded_hooks(&hooks);
	btf = lsm_btf(&hooks, NULL);
	ASSERT_TRUE(btf);
	EXPECT_EQ(kernel_abi_validate_lsm_hooks(btf, &hooks, detail,
						sizeof(detail)), 0);
	btf__free(btf);
	btf = lsm_btf(&hooks, "mm_read_access");
	ASSERT_TRUE(btf);
	EXPECT_EQ(kernel_abi_validate_lsm_hooks(btf, &hooks, detail,
						sizeof(detail)), -EOPNOTSUPP);
	EXPECT_STREQ(detail, "kernel has no LSM hook mm_read_access; "
		     "boot a shirudo-patched kernel");
	btf__free(btf);
}

static void lsm_hooks_need_btf(void)
{
	char detail[KERNEL_ABI_DETAIL_MAX] = {};
	static struct lsm_hooks hooks;

	EXPECT_EQ(kernel_abi_validate_lsm_hooks(NULL, &hooks, detail,
						sizeof(detail)), -EOPNOTSUPP);
	EXPECT_TRUE(str_contains(detail, "kernel BTF is unavailable"));
}

static const struct unit_case cases[] = {
	UNIT_CASE(needs_btf),
	UNIT_CASE(needs_tpm_command),
	UNIT_CASE(needs_mm_read_access),
	UNIT_CASE(accepts_the_required_prefix),
	UNIT_CASE(accepts_fields_past_the_prefix),
	UNIT_CASE(needs_struct_bpf_map),
	UNIT_CASE(needs_map_sha),
	UNIT_CASE(needs_map_sha_non_bitfield_and_array),
	UNIT_CASE(needs_map_sha_of_32_bytes),
	UNIT_CASE(needs_map_sha_of_bytes),
	UNIT_CASE(needs_map_sha_unsigned),
	UNIT_CASE(needs_excl_prog_sha),
	UNIT_CASE(needs_excl_prog_sha_non_bitfield),
	UNIT_CASE(needs_excl_prog_sha_pointer),
	UNIT_CASE(needs_excl_prog_sha_byte_pointer),
	UNIT_CASE(needs_struct_bpf_prog_aux),
	UNIT_CASE(needs_prog_aux_sig),
	UNIT_CASE(needs_sig_struct),
	UNIT_CASE(needs_keyring_serial),
	UNIT_CASE(needs_keyring_serial_s32),
	UNIT_CASE(needs_keyring_type),
	UNIT_CASE(needs_keyring_type_u8),
	UNIT_CASE(needs_verdict),
	UNIT_CASE(needs_verdict_unsigned),
	UNIT_CASE(patch_status_qualifies_complete_kernel),
	UNIT_CASE(patch_status_reports_missing_patches_on_stock_kernel),
	UNIT_CASE(patch_status_handles_null_and_live_btf),
	UNIT_CASE(lsm_hooks_come_from_the_embedded_objects),
	UNIT_CASE(lsm_hooks_all_present),
	UNIT_CASE(lsm_hooks_missing_are_named),
	UNIT_CASE(lsm_hooks_of_the_embedded_objects_checked),
	UNIT_CASE(lsm_hooks_need_btf),
	{}
};

UNIT_SUITE(kernel_abi, cases);
