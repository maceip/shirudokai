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

#include <shirudo/types.h>

struct btf;

struct kernel_options {
	bool	modules;		/* CONFIG_MODULES */
	bool	module_sig;		/* CONFIG_MODULE_SIG */
	bool	compat;			/* CONFIG_COMPAT / IA32 / X32 */
	bool	hibernation;		/* CONFIG_HIBERNATION */
};

/* The options btf shows, the BTF of vmlinux. */
void kernel_prereq_options(const struct btf *btf, struct kernel_options *out);

/*
 * Whether cmdline permits hibernation resume: true when NULL, when
 * resume= or resumewait is set before "--", or when none of
 * nohibernate, hibernate=no, lockdown=integrity and
 * lockdown=confidentiality is present.
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
 * Probe callback: attempts O_WRONLY open of path without writing.
 * Returns 0 if the open succeeded (and closes the fd), or -errno on
 * failure.
 */
typedef int (*kernel_bdev_probe_open_fn)(const char *path);

/*
 * Check mounted block-device write protection for device (maj, min) by
 * probing /dev/block/<maj>:<min> with O_WRONLY. Returns 0 when the open
 * fails with EBUSY, -EOPNOTSUPP when maj == 0 or the open succeeds, or
 * -errno otherwise. Uses open(2) when open_fn is NULL.
 */
int kernel_bdev_check_dev(__u32 maj, __u32 min,
			  kernel_bdev_probe_open_fn open_fn,
			  char *detail, size_t detail_sz);

/*
 * Resolve state_dir's st_dev and probe whether writes to its mounted
 * block device are refused (A10). Never passes when the device cannot be
 * examined.
 */
int kernel_bdev_probe_write_mounted(const char *state_dir,
				    kernel_bdev_probe_open_fn open_fn,
				    char *detail, size_t detail_sz);

#endif /* SHIRUDO_KERNEL_PREREQ_H */
