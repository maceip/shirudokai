// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the running kernel shows of the options the threat model assumes,
 * for the pre-flight checks of init.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <zlib.h>

#include <linux/btf.h>

#include <bpf/btf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "io.h"
#include "kconfig.h"
#include "kernel_prereq.h"
#include "malloc.h"

#define KCONFIG_MAX	(4U << 20)

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
	out->bdev_write_guard = has_func(btf, "bdev_writes_blocked") ||
				has_func(btf, "setup_bdev_allow_write_mounted") ||
				has_func(btf, "bdev_may_open") ||
				has_func(btf, "bdev_open_by_dev") ||
				has_func(btf, "bdev_file_open_by_dev");
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
		if (span_equals(tok, len, "noresume") ||
		    span_equals(tok, len, "nohibernate") ||
		    span_equals(tok, len, "hibernate=no"))
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

int kernel_kconfig_allows_write_mounted(const char *text, size_t len)
{
	char line[KCONFIG_LINE_MAX + 1];
	int state = -ENOENT, ret;
	size_t off, n;

	if (!text)
		return -EINVAL;
	for (off = 0; off < len; off += n + 1) {
		const char *nl = memchr(text + off, '\n', len - off);
		const char *key, *value;

		n = nl ? (size_t)(nl - text) - off : len - off;
		ret = span_to_str(line, sizeof(line), text + off, n);
		if (ret == -E2BIG)
			continue;
		if (ret)
			return ret;
		if (!kconfig_line(line, &key, &value) ||
		    strcmp(key, "CONFIG_BLK_DEV_WRITE_MOUNTED"))
			continue;
		if (!strcmp(value, "y"))
			state = 1;
		else if (!strcmp(value, "n"))
			state = 0;
		else
			return -EINVAL;
	}
	return state;
}

/*
 * Inflate one complete gzip member, as /proc/config.gz serves it, without
 * gzgets(), whose read-ahead fails in zlib 1.3.2 at the member boundary.
 */
static int gunzip_kconfig(char *in, size_t len, char **out, size_t *out_len,
			  size_t *cap)
{
	size_t have = 0, size = 0, want;
	char *buf = NULL, *grown;
	int zret, ret = 0;
	z_stream z = {};

	if (inflateInit2(&z, 16 + MAX_WBITS) != Z_OK)
		return -ENOMEM;
	z.next_in = (Bytef *)in;
	z.avail_in = (uInt)len;
	do {
		if (have == size) {
			if (size >= KCONFIG_MAX) {
				ret = -EFBIG;
				break;
			}
			want = min(size ? size * 2 : 65536U, KCONFIG_MAX);
			grown = xreallocarray(buf, size ? size + 1 : 0,
					      want + 1, 1);
			if (!grown) {
				ret = -ENOMEM;
				break;
			}
			buf = grown;
			size = want;
		}
		z.next_out = (Bytef *)buf + have;
		z.avail_out = (uInt)(size - have);
		zret = inflate(&z, Z_NO_FLUSH);
		have = size - z.avail_out;
		if (zret == Z_MEM_ERROR)
			ret = -ENOMEM;
		else if (zret != Z_OK && zret != Z_STREAM_END)
			ret = -EINVAL;
	} while (!ret && zret != Z_STREAM_END);
	if (!ret && z.avail_in)
		ret = -EINVAL;
	inflateEnd(&z);
	if (ret) {
		xfree(buf, size ? size + 1 : 0);
		return ret;
	}
	buf[have] = '\0';
	*out = buf;
	*out_len = have;
	*cap = size + 1;
	return 0;
}

int kernel_config_file_allows_write_mounted(const char *path, bool gz)
{
	size_t len, text_len, cap;
	char *raw, *text;
	int ret;

	if (!path)
		return -EINVAL;
	ret = read_file(path, KCONFIG_MAX, &raw, &len);
	if (ret)
		return ret;
	if (gz) {
		ret = gunzip_kconfig(raw, len, &text, &text_len, &cap);
		xfree(raw, len + 1);
		if (ret)
			return ret;
	} else {
		text = raw;
		text_len = len;
		cap = len + 1;
	}
	ret = kernel_kconfig_allows_write_mounted(text, text_len);
	xfree(text, cap);
	return ret;
}

static int parse_kstrtobool(const char *val, size_t len)
{
	char buf[8];

	if (!len || span_to_str(buf, sizeof(buf), val, len))
		return -EINVAL;
	if (!strcmp(buf, "1") || str_equals_nocase(buf, "y") ||
	    str_equals_nocase(buf, "yes") || str_equals_nocase(buf, "true") ||
	    str_equals_nocase(buf, "on"))
		return 1;
	if (!strcmp(buf, "0") || str_equals_nocase(buf, "n") ||
	    str_equals_nocase(buf, "no") || str_equals_nocase(buf, "false") ||
	    str_equals_nocase(buf, "off"))
		return 0;
	return -EINVAL;
}

int kernel_cmdline_write_mounted(const char *cmdline)
{
	const char *tok, *val;
	int state = -ENOENT;
	size_t len, vlen;

	if (!cmdline)
		return -ENOENT;
	for_each_token(tok, len, cmdline, strlen(cmdline), " \t\r\n") {
		int parsed;

		if (is_arg_end(tok, len))
			break;
		val = span_after_prefix(tok, len, "bdev_allow_write_mounted=",
					&vlen);
		if (!val)
			continue;
		parsed = parse_kstrtobool(val, vlen);
		if (parsed < 0)
			return 1;
		state = parsed;
	}
	return state;
}

bool kernel_bdev_write_mounted_protected(const struct kernel_options *opts,
					 int kconfig_allow,
					 const char *cmdline)
{
	int cmd;

	if (!opts || !opts->bdev_write_guard)
		return false;
	cmd = kernel_cmdline_write_mounted(cmdline);
	if (cmd == 1)
		return false;
	if (cmd == 0)
		return true;
	return kconfig_allow == 0 || kconfig_allow == -ENOENT;
}
