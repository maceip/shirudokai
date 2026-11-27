// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

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
	};
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_TRUE(opts.module_sig);
	EXPECT_TRUE(opts.compat);
	EXPECT_TRUE(opts.hibernation);
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
}

static void modules_without_signatures(void)
{
	static const char *const names[] = { "__module_address" };
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_FALSE(opts.module_sig);
}

static void compat_detected_by_compat_funcs(void)
{
	static const char *const compat_funcs[] = {
		"__do_fast_syscall_32",
		"get_compat_sigset",
	};
	struct kernel_options opts;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(compat_funcs); i++) {
		options_of(&compat_funcs[i], 1, &opts);
		EXPECT_TRUE(opts.compat);
	}
}

static void hibernation_detected_and_gated_by_cmdline(void)
{
	static const char *const hib_funcs[] = {
		"hibernation_set_ops",
		"software_resume",
	};
	const char *res1 = "nohibernate resume=/dev/vda2";
	const char *res2 = "lockdown=integrity resumewait";
	const char *sep_res = "nohibernate -- resume=/dev/vda2";
	const char *res_uuid = "nohibernate resume=UUID=1234";
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
	EXPECT_TRUE(kernel_cmdline_allows_hibernation("quiet noresume"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation("nohibernate quiet"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation("hibernate=no"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation("lockdown=integrity"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation("lockdown=confidentiality"));
	EXPECT_TRUE(kernel_cmdline_allows_hibernation(res1));
	EXPECT_TRUE(kernel_cmdline_allows_hibernation(res2));
	/* Init arguments after "--" do not count as kernel parameters. */
	EXPECT_TRUE(kernel_cmdline_allows_hibernation("quiet -- nohibernate"));
	EXPECT_FALSE(kernel_cmdline_allows_hibernation(sep_res));

	EXPECT_TRUE(kernel_hibernation_allowed(NULL, "nohibernate"));
	EXPECT_FALSE(kernel_hibernation_allowed(&no_hib, "console=ttyS0"));
	EXPECT_TRUE(kernel_hibernation_allowed(&no_hib, "resume=/dev/sda2"));
	EXPECT_TRUE(kernel_hibernation_allowed(&no_hib, "resumewait"));
	EXPECT_TRUE(kernel_hibernation_allowed(&with_hib, "console=ttyS0"));
	EXPECT_TRUE(kernel_hibernation_allowed(&with_hib, NULL));
	EXPECT_TRUE(kernel_hibernation_allowed(&with_hib, "console=ttyS0 noresume"));
	EXPECT_FALSE(kernel_hibernation_allowed(&with_hib, "nohibernate"));
	EXPECT_FALSE(kernel_hibernation_allowed(&with_hib, "hibernate=no"));
	EXPECT_FALSE(kernel_hibernation_allowed(&with_hib, "lockdown=integrity"));
	EXPECT_FALSE(kernel_hibernation_allowed(&with_hib, "lockdown=confidentiality"));
	EXPECT_TRUE(kernel_hibernation_allowed(&with_hib, res_uuid));
}

static int fake_probe_rc;
static char fake_probe_path[64];

static int fake_bdev_open(const char *path)
{
	ASSERT_TRUE(strscpy(fake_probe_path, path,
			    sizeof(fake_probe_path)) >= 0);
	return fake_probe_rc;
}

static void bdev_write_mounted_active_probe(void)
{
	char detail[256];

	fake_probe_path[0] = '\0';
	fake_probe_rc = -EBUSY;
	EXPECT_EQ(kernel_bdev_check_dev(8, 1, fake_bdev_open,
					detail, sizeof(detail)), 0);
	EXPECT_STREQ(fake_probe_path, "/dev/block/8:1");
	EXPECT_STREQ(detail, "");

	fake_probe_rc = 0;
	EXPECT_EQ(kernel_bdev_check_dev(259, 0, fake_bdev_open,
					detail, sizeof(detail)), -EOPNOTSUPP);
	EXPECT_STREQ(fake_probe_path, "/dev/block/259:0");
	EXPECT_TRUE(str_contains(detail, "/dev/block/259:0"));
	EXPECT_TRUE(str_contains(detail, "allowed"));

	fake_probe_rc = -ENOENT;
	EXPECT_EQ(kernel_bdev_check_dev(8, 2, fake_bdev_open,
					detail, sizeof(detail)), -ENOENT);
	EXPECT_TRUE(str_contains(detail, "/dev/block/8:2"));

	fake_probe_rc = -EACCES;
	EXPECT_EQ(kernel_bdev_check_dev(8, 3, fake_bdev_open,
					detail, sizeof(detail)), -EACCES);

	fake_probe_rc = -EROFS;
	EXPECT_EQ(kernel_bdev_check_dev(8, 4, fake_bdev_open,
					detail, sizeof(detail)), -EROFS);

	fake_probe_path[0] = '\0';
	EXPECT_EQ(kernel_bdev_check_dev(0, 42, fake_bdev_open,
					detail, sizeof(detail)), -EOPNOTSUPP);
	EXPECT_STREQ(fake_probe_path, "");
	EXPECT_TRUE(str_contains(detail, "no block device"));

	EXPECT_EQ(kernel_bdev_probe_write_mounted(NULL, fake_bdev_open,
						  detail, sizeof(detail)),
		  -EINVAL);
	EXPECT_EQ(kernel_bdev_probe_write_mounted("", fake_bdev_open,
						  detail, sizeof(detail)),
		  -EINVAL);
	EXPECT_EQ(kernel_bdev_probe_write_mounted("/nonexistent/shirudo-state",
						  fake_bdev_open,
						  detail, sizeof(detail)),
		  -ENOENT);
	EXPECT_TRUE(str_contains(detail, "cannot stat"));
}

static const struct unit_case cases[] = {
	UNIT_CASE(options_of_a_kernel_with_all),
	UNIT_CASE(options_of_a_kernel_with_none),
	UNIT_CASE(modules_without_signatures),
	UNIT_CASE(compat_detected_by_compat_funcs),
	UNIT_CASE(hibernation_detected_and_gated_by_cmdline),
	UNIT_CASE(bdev_write_mounted_active_probe),
	{}
};

UNIT_SUITE(kernel_prereq, cases);
