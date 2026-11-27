// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the running kernel shows of the options the threat model assumes,
 * for the pre-flight checks of init.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <linux/btf.h>

#include <bpf/btf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "kernel_prereq.h"

static bool has_func(const struct btf *btf, const char *name)
{
	return btf && btf__find_by_name_kind(btf, name, BTF_KIND_FUNC) > 0;
}

static bool has_symbol(const struct btf *btf, const char *name)
{
	return btf && (btf__find_by_name_kind(btf, name, BTF_KIND_FUNC) > 0 ||
		       btf__find_by_name_kind(btf, name, BTF_KIND_VAR) > 0);
}

static bool is_arg_end(const char *tok, size_t len)
{
	return len == 2 && tok[0] == '-' && tok[1] == '-';
}

static const char *span_after_prefix(const char *s, size_t len,
				     const char *prefix, size_t *val_len)
{
	size_t n = strlen(prefix);

	if (len < n || memcmp(s, prefix, n))
		return NULL;
	*val_len = len - n;
	return s + n;
}

/*
 * Each name is a function or symbol only its option builds. Without the
 * option its stub, where it has one, is a static inline, which leaves no
 * BTF function.
 */
void kernel_prereq_options(const struct btf *btf, struct kernel_options *out)
{
	out->modules = has_func(btf, "__module_address");
	out->module_sig = has_func(btf, "mod_verify_sig");
	out->compat = has_symbol(btf, "__do_fast_syscall_32") ||
		      has_symbol(btf, "ia32_sys_call_table") ||
		      has_symbol(btf, "compat_elf_check_arch") ||
		      has_func(btf, "compat_alloc_user_space") ||
		      has_func(btf, "get_compat_sigset");
	out->hibernation = has_func(btf, "hibernation_set_ops") ||
			   has_func(btf, "software_resume");
}

static bool cmdline_has_resume(const char *cmdline)
{
	const char *tok;
	size_t len, vlen;

	if (!cmdline)
		return false;
	for_each_token(tok, len, cmdline, strlen(cmdline), " \t\r\n") {
		if (is_arg_end(tok, len))
			break;
		if (span_after_prefix(tok, len, "resume=", &vlen) ||
		    span_equals(tok, len, "resumewait"))
			return true;
	}
	return false;
}

bool kernel_cmdline_allows_hibernation(const char *cmdline)
{
	bool disabled = false;
	const char *tok;
	size_t len;

	if (!cmdline || cmdline_has_resume(cmdline))
		return true;
	for_each_token(tok, len, cmdline, strlen(cmdline), " \t\r\n") {
		if (is_arg_end(tok, len))
			break;
		if (span_equals(tok, len, "nohibernate") ||
		    span_equals(tok, len, "hibernate=no") ||
		    span_equals(tok, len, "lockdown=integrity") ||
		    span_equals(tok, len, "lockdown=confidentiality"))
			disabled = true;
	}
	return !disabled;
}

bool kernel_hibernation_allowed(const struct kernel_options *opts,
				const char *cmdline)
{
	if (!opts || cmdline_has_resume(cmdline))
		return true;
	return opts->hibernation && kernel_cmdline_allows_hibernation(cmdline);
}

static __printf(4, 5) int bdev_fail(char *detail, size_t detail_sz, int err,
				    const char *fmt, ...)
{
	va_list ap;

	if (detail && detail_sz) {
		va_start(ap, fmt);
		if (vstrsprintf(detail, detail_sz, fmt, ap) < 0 &&
		    strscpy(detail, "?", detail_sz) < 0)
			detail[0] = '\0';
		va_end(ap);
	}
	return err;
}

static int default_bdev_open(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 0;
	}
	return -errno;
}

int kernel_bdev_check_dev(__u32 maj, __u32 min,
			  kernel_bdev_probe_open_fn open_fn,
			  char *detail, size_t detail_sz)
{
	char dev_path[64];
	int ret;

	if (detail && detail_sz)
		detail[0] = '\0';
	if (maj == 0)
		return bdev_fail(detail, detail_sz, -EOPNOTSUPP,
				 "state directory has no block device (dev=0:%u); "
				 "cannot verify mounted block-device write protection",
				 min);
	if (strsprintf(dev_path, sizeof(dev_path), "/dev/block/%u:%u",
		       maj, min) < 0)
		return bdev_fail(detail, detail_sz, -ENAMETOOLONG,
				 "block device path too long");
	ret = open_fn ? open_fn(dev_path) : default_bdev_open(dev_path);
	if (ret == -EBUSY)
		return 0;
	if (ret == 0)
		return bdev_fail(detail, detail_sz, -EOPNOTSUPP,
				 "writes to mounted block device %s are allowed "
				 "(needs CONFIG_BLK_DEV_WRITE_MOUNTED=n and no "
				 "bdev_allow_write_mounted=1)",
				 dev_path);
	return bdev_fail(detail, detail_sz, ret,
			 "cannot probe block device %s: %s",
			 dev_path, strerror(-ret));
}

int kernel_bdev_probe_write_mounted(const char *state_dir,
				    kernel_bdev_probe_open_fn open_fn,
				    char *detail, size_t detail_sz)
{
	struct stat st;

	if (detail && detail_sz)
		detail[0] = '\0';
	if (!state_dir || !state_dir[0])
		return bdev_fail(detail, detail_sz, -EINVAL,
				 "state directory path is missing");
	if (stat(state_dir, &st) != 0) {
		int err = -errno;

		return bdev_fail(detail, detail_sz, err,
				 "cannot stat state directory %s: %s",
				 state_dir, strerror(-err));
	}
	return kernel_bdev_check_dev((__u32)major(st.st_dev),
				     (__u32)minor(st.st_dev),
				     open_fn, detail, detail_sz);
}
