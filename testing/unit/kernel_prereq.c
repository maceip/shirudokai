// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "io.h"
#include "kconfig.h"
#include "kernel_prereq.h"
#include "unit.h"

/* A BTF with a function of each name and nothing else of note. */
static struct btf *btf_with(const char *const *names, size_t n)
{
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
	for (i = 0; i < n; i++)
		if (btf__add_func(btf, names[i], BTF_FUNC_GLOBAL, proto) < 0)
			goto err;
	return btf;
err:
	btf__free(btf);
	return NULL;
}

static void options_of(const char *const *names, size_t n,
		       struct kernel_options *opts)
{
	struct btf *btf = btf_with(names, n);

	ASSERT_TRUE(btf);
	memset(opts, 0xff, sizeof(*opts));
	kernel_prereq_options(btf, opts);
	btf__free(btf);
}

static void options_of_a_kernel_with_all(void)
{
	static const char *const names[] = {
		"__module_address",
		"mod_verify_sig",
		"__do_fast_syscall_32",
		"hibernation_set_ops",
		"bdev_writes_blocked",
	};
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_TRUE(opts.module_sig);
	EXPECT_TRUE(opts.compat);
	EXPECT_TRUE(opts.hibernation);
	EXPECT_TRUE(opts.bdev_write_guard);
}

static void options_of_a_kernel_with_none(void)
{
	static const char *const names[] = { "vfs_read", "module" };
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_FALSE(opts.modules);
	EXPECT_FALSE(opts.module_sig);
	EXPECT_FALSE(opts.compat);
	EXPECT_FALSE(opts.hibernation);
	EXPECT_FALSE(opts.bdev_write_guard);
}

static void modules_without_signatures(void)
{
	static const char *const names[] = { "__module_address" };
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_FALSE(opts.module_sig);
}

static void compat_detected_by_syscall_table_or_exec_symbols(void)
{
	static const char *const compat_funcs[] = {
		"__do_fast_syscall_32",
		"ia32_sys_call_table",
		"compat_elf_check_arch",
		"compat_alloc_user_space",
		"get_compat_sigset",
	};
	struct kernel_options opts;
	struct btf *btf;
	int u64_id;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(compat_funcs); i++) {
		options_of(&compat_funcs[i], 1, &opts);
		EXPECT_TRUE(opts.compat);
	}

	/* ia32_sys_call_table may also appear as a BTF_KIND_VAR symbol. */
	btf = btf__new_empty();
	ASSERT_TRUE(!libbpf_get_error(btf));
	u64_id = btf__add_int(btf, "u64", 8, 0);
	ASSERT_TRUE(u64_id > 0);
	ASSERT_TRUE(btf__add_var(btf, "ia32_sys_call_table", BTF_VAR_GLOBAL_ALLOCATED,
				 u64_id) > 0);
	memset(&opts, 0, sizeof(opts));
	kernel_prereq_options(btf, &opts);
	EXPECT_TRUE(opts.compat);
	btf__free(btf);
}

static void hibernation_detected_and_gated_by_cmdline(void)
{
	static const char *const hib_funcs[] = {
		"hibernation_set_ops",
		"software_resume",
	};
	const char *res1 = "noresume resume=/dev/vda2";
	const char *res2 = "nohibernate resumewait";
	const char *sep_res = "noresume -- resume=/dev/vda2";
	const char *res_uuid = "noresume resume=UUID=1234";
	struct kernel_options with_hib = { .hibernation = true };
	struct kernel_options no_hib = { .hibernation = false };
	struct kernel_options opts;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(hib_funcs); i++) {
		options_of(&hib_funcs[i], 1, &opts);
		EXPECT_TRUE(opts.hibernation);
	}

	EXPECT_TRUE(kernel_cmdline_allows_hibernation(NULL));
	EXPECT_TRUE(kernel_cmdline_allows_hibernation(""));
	EXPECT_TRUE(kernel_cmdline_allows_hibernation("console=ttyS0 quiet"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation("quiet noresume"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation("nohibernate quiet"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation("hibernate=no"));
	EXPECT_TRUE(kernel_cmdline_allows_hibernation(res1));
	EXPECT_TRUE(kernel_cmdline_allows_hibernation(res2));
	/* Init arguments after "--" do not count as kernel parameters. */
	EXPECT_TRUE(kernel_cmdline_allows_hibernation("quiet -- noresume"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation(sep_res));

	EXPECT_TRUE(kernel_hibernation_allowed(NULL, "noresume"));
	EXPECT_FALSE(kernel_hibernation_allowed(&no_hib, "console=ttyS0"));
	EXPECT_TRUE(kernel_hibernation_allowed(&no_hib, "resume=/dev/sda2"));
	EXPECT_TRUE(kernel_hibernation_allowed(&no_hib, "resumewait"));
	EXPECT_TRUE(kernel_hibernation_allowed(&with_hib, "console=ttyS0"));
	EXPECT_TRUE(kernel_hibernation_allowed(&with_hib, NULL));
	EXPECT_FALSE(kernel_hibernation_allowed(&with_hib, "console=ttyS0 noresume"));
	EXPECT_FALSE(kernel_hibernation_allowed(&with_hib, "nohibernate"));
	EXPECT_FALSE(kernel_hibernation_allowed(&with_hib, "hibernate=no"));
	EXPECT_TRUE(kernel_hibernation_allowed(&with_hib, res_uuid));
}

static int kcfg_allow(const char *s, size_t n)
{
	return kernel_kconfig_allows_write_mounted(s, n);
}

static void bdev_write_guard_symbols_and_kconfig_text(void)
{
	static const char *const bdev_funcs[] = {
		"bdev_writes_blocked",
		"setup_bdev_allow_write_mounted",
		"bdev_may_open",
		"bdev_open_by_dev",
		"bdev_file_open_by_dev",
	};
	static const char enabled_cfg[] =
		"CONFIG_BLOCK=y\nCONFIG_BLK_DEV_WRITE_MOUNTED=y\n";
	static const char unset_cfg[] =
		"CONFIG_BLOCK=y\n# CONFIG_BLK_DEV_WRITE_MOUNTED is not set\n";
	static const char disabled_cfg[] = "CONFIG_BLK_DEV_WRITE_MOUNTED=n\n";
	static const char absent_cfg[] = "CONFIG_BLOCK=y\n";
	static const char invalid_cfg[] = "CONFIG_BLK_DEV_WRITE_MOUNTED=m\n";
	static const char nul_cfg[] = "CONFIG_BLOCK=y\0CONFIG_BLK_DEV_WRITE_MOUNTED=n\n";
	static const char tail[] = "\nCONFIG_BLK_DEV_WRITE_MOUNTED=n\n";
	char long_line[KCONFIG_LINE_MAX + 64];
	struct kernel_options opts;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(bdev_funcs); i++) {
		options_of(&bdev_funcs[i], 1, &opts);
		EXPECT_TRUE(opts.bdev_write_guard);
	}

	EXPECT_EQ(kcfg_allow(NULL, 0), -EINVAL);
	EXPECT_EQ(kcfg_allow(enabled_cfg, sizeof(enabled_cfg) - 1), 1);
	EXPECT_EQ(kcfg_allow(unset_cfg, sizeof(unset_cfg) - 1), 0);
	EXPECT_EQ(kcfg_allow(disabled_cfg, sizeof(disabled_cfg) - 1), 0);
	EXPECT_EQ(kcfg_allow(absent_cfg, sizeof(absent_cfg) - 1), -ENOENT);
	EXPECT_EQ(kcfg_allow(invalid_cfg, sizeof(invalid_cfg) - 1), -EINVAL);
	EXPECT_EQ(kcfg_allow(nul_cfg, sizeof(nul_cfg) - 1), -EINVAL);

	memset(long_line, 'x', sizeof(long_line) - sizeof(tail));
	long_line[0] = '#';
	memcpy(long_line + sizeof(long_line) - sizeof(tail), tail,
	       sizeof(tail) - 1);
	EXPECT_EQ(kcfg_allow(long_line, sizeof(long_line) - 1), 0);
}

static void write_gz_file(const char *path, const char *text)
{
	gzFile gz = gzopen(path, "wb");
	size_t len = strlen(text);

	ASSERT_TRUE(gz);
	ASSERT_EQ(gzwrite(gz, text, (__u32)len), (int)len);
	ASSERT_EQ(gzclose(gz), Z_OK);
}

static void bdev_write_mounted_files_cmdline_and_full_passing_kernel(void)
{
	static const char *const hardened_btf[] = {
		"__module_address",
		"mod_verify_sig",
		"setup_bdev_allow_write_mounted",
	};
	const char *boot_cmd =
		"bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1";
	const char *tmp = getenv("TMPDIR");
	struct kernel_options opts;
	char dir[256], gz_path[300], plain_path[300], bad_gz[300];
	int fd;

	ASSERT_TRUE(strsprintf(dir, sizeof(dir), "%s/shirudo-kcfg-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(dir));
	ASSERT_TRUE(strsprintf(gz_path, sizeof(gz_path), "%s/config.gz", dir) > 0);
	ASSERT_TRUE(strsprintf(plain_path, sizeof(plain_path), "%s/config", dir) > 0);
	ASSERT_TRUE(strsprintf(bad_gz, sizeof(bad_gz), "%s/bad.gz", dir) > 0);

	EXPECT_EQ(kernel_config_file_allows_write_mounted(NULL, false), -EINVAL);
	EXPECT_EQ(kernel_config_file_allows_write_mounted(gz_path, true), -ENOENT);

	write_gz_file(gz_path, "CONFIG_BLK_DEV_WRITE_MOUNTED=y\n");
	EXPECT_EQ(kernel_config_file_allows_write_mounted(gz_path, true), 1);
	write_gz_file(gz_path, "# CONFIG_BLK_DEV_WRITE_MOUNTED is not set\n");
	EXPECT_EQ(kernel_config_file_allows_write_mounted(gz_path, true), 0);

	fd = open(plain_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, "CONFIG_BLK_DEV_WRITE_MOUNTED=n\n",
				 sizeof("CONFIG_BLK_DEV_WRITE_MOUNTED=n\n") - 1),
		  0);
	ASSERT_EQ(close(fd), 0);
	EXPECT_EQ(kernel_config_file_allows_write_mounted(plain_path, false), 0);

	fd = open(bad_gz, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, "not-gzip", 8), 0);
	ASSERT_EQ(close(fd), 0);
	EXPECT_EQ(kernel_config_file_allows_write_mounted(bad_gz, true), -EINVAL);

	ASSERT_EQ(unlink(gz_path), 0);
	ASSERT_EQ(unlink(plain_path), 0);
	ASSERT_EQ(unlink(bad_gz), 0);
	ASSERT_EQ(rmdir(dir), 0);

	EXPECT_EQ(kernel_cmdline_write_mounted(NULL), -ENOENT);
	EXPECT_EQ(kernel_cmdline_write_mounted("quiet"), -ENOENT);
	EXPECT_EQ(kernel_cmdline_write_mounted("bdev_allow_write_mounted=1"), 1);
	EXPECT_EQ(kernel_cmdline_write_mounted("bdev_allow_write_mounted=true"), 1);
	EXPECT_EQ(kernel_cmdline_write_mounted("bdev_allow_write_mounted=on"), 1);
	EXPECT_EQ(kernel_cmdline_write_mounted("bdev_allow_write_mounted=0"), 0);
	EXPECT_EQ(kernel_cmdline_write_mounted("bdev_allow_write_mounted=false"), 0);
	EXPECT_EQ(kernel_cmdline_write_mounted("bdev_allow_write_mounted=off"), 0);
	EXPECT_EQ(kernel_cmdline_write_mounted("bdev_allow_write_mounted=bogus"), 1);
	EXPECT_EQ(kernel_cmdline_write_mounted("quiet -- bdev_allow_write_mounted=1"),
		  -ENOENT);

	/* Full passing hardened kernel: module_sig, no compat, no hibernation, bdev guard. */
	options_of(hardened_btf, ARRAY_SIZE(hardened_btf), &opts);
	EXPECT_TRUE(opts.modules && opts.module_sig);
	EXPECT_FALSE(opts.compat);
	EXPECT_FALSE(kernel_hibernation_allowed(&opts, boot_cmd));
	EXPECT_TRUE(kernel_bdev_write_mounted_protected(&opts, 0, "quiet"));
	EXPECT_TRUE(kernel_bdev_write_mounted_protected(&opts, -ENOENT, "quiet"));
	EXPECT_FALSE(kernel_bdev_write_mounted_protected(&opts, 1, "quiet"));
	EXPECT_FALSE(kernel_bdev_write_mounted_protected(&opts, -EINVAL, "quiet"));
	EXPECT_TRUE(kernel_bdev_write_mounted_protected(&opts, 1,
							"bdev_allow_write_mounted=0"));
	EXPECT_FALSE(kernel_bdev_write_mounted_protected(&opts, 0,
							 "bdev_allow_write_mounted=1"));
	EXPECT_FALSE(kernel_bdev_write_mounted_protected(&opts, 0, NULL));
	EXPECT_FALSE(kernel_bdev_write_mounted_protected(&opts, -ENOENT, NULL));
	EXPECT_FALSE(kernel_bdev_write_mounted_protected(NULL, 0, "quiet"));
	opts.bdev_write_guard = false;
	EXPECT_FALSE(kernel_bdev_write_mounted_protected(&opts, 0, "quiet"));
}

static const struct unit_case cases[] = {
	UNIT_CASE(options_of_a_kernel_with_all),
	UNIT_CASE(options_of_a_kernel_with_none),
	UNIT_CASE(modules_without_signatures),
	UNIT_CASE(compat_detected_by_syscall_table_or_exec_symbols),
	UNIT_CASE(hibernation_detected_and_gated_by_cmdline),
	UNIT_CASE(bdev_write_guard_symbols_and_kconfig_text),
	UNIT_CASE(bdev_write_mounted_files_cmdline_and_full_passing_kernel),
	{}
};

UNIT_SUITE(kernel_prereq, cases);
