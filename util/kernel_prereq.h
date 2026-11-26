/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the running kernel shows of the options the threat model assumes:
 * its BTF, /proc/cmdline and, where present, /proc/config.gz or
 * /boot/config-<release>.
 */

#ifndef SHIRUDO_KERNEL_PREREQ_H
#define SHIRUDO_KERNEL_PREREQ_H

#include <stdbool.h>
#include <stddef.h>

struct btf;

struct kernel_options {
	bool	modules;		/* CONFIG_MODULES */
	bool	module_sig;		/* CONFIG_MODULE_SIG */
	bool	compat;			/* CONFIG_COMPAT / IA32 / X32 */
	bool	hibernation;		/* CONFIG_HIBERNATION */
	bool	bdev_write_guard;	/* block-layer mounted-write guard */
};

/* The options btf shows, the BTF of vmlinux. */
void kernel_prereq_options(const struct btf *btf, struct kernel_options *out);

/*
 * Whether cmdline permits hibernation resume: true when NULL, when
 * resume= or resumewait is set before "--", or when none of noresume,
 * nohibernate and hibernate=no is present.
 */
bool kernel_cmdline_allows_hibernation(const char *cmdline);

/*
 * Whether hibernation resume is possible given opts and cmdline: true
 * when opts is NULL, when resume= or resumewait is set on cmdline, or
 * when hibernation is built in and cmdline allows it.
 */
bool kernel_hibernation_allowed(const struct kernel_options *opts,
				const char *cmdline);

/*
 * CONFIG_BLK_DEV_WRITE_MOUNTED in kconfig text: 1 when y, 0 when n or
 * "is not set", -ENOENT when absent, -EINVAL on NUL or another value.
 */
int kernel_kconfig_allows_write_mounted(const char *text, size_t len);

/*
 * kernel_kconfig_allows_write_mounted() on path, gunzipped first when gz
 * is set.
 */
int kernel_config_file_allows_write_mounted(const char *path, bool gz);

/*
 * bdev_allow_write_mounted= on cmdline before "--": 1 when enabled or
 * malformed, 0 when disabled, -ENOENT when absent.
 */
int kernel_cmdline_write_mounted(const char *cmdline);

/*
 * Whether writes to mounted block devices are blocked (A10): requires the
 * block-layer guard in BTF, no enabling cmdline override, and no
 * CONFIG_BLK_DEV_WRITE_MOUNTED=y without bdev_allow_write_mounted=0.
 */
bool kernel_bdev_write_mounted_protected(const struct kernel_options *opts,
					 int kconfig_allow,
					 const char *cmdline);

#endif /* SHIRUDO_KERNEL_PREREQ_H */
