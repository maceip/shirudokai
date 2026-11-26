// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * web-worker-guard: confine labeled web workers (php-fpm, apache2, httpd,
 * nginx) against spawning shells or network fetch tools and against opening
 * executable web-script extensions (.php, .phtml, .phar, .sh) for writing.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "policy.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#define WEB_WORKER_BIT		0x1ULL
#define EACCES			13
#define FMODE_WRITE		0x2
#define NAME_MAX		255
#define GUARD_EXEC_MAX		16
#define GUARD_SUFFIX_MAX	8

#define HIT_KIND_EXEC		0
#define HIT_KIND_WRITE		1

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} activity SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} hits_by_kind SEC(".maps");

static __always_inline bool is_web_worker(void)
{
	struct task_policy *policy;

	policy = bpf_task_storage_get(&shirudo_task_policy,
				      bpf_get_current_task_btf(), NULL, 0);
	return policy && (policy->active & WEB_WORKER_BIT);
}

static __always_inline void bump_activity(void)
{
	__u32 key = 0;
	__u64 *cnt;

	cnt = bpf_map_lookup_elem(&activity, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline void bump_hit(__u32 kind)
{
	__u32 zero = 0;
	__u64 *cnt;

	cnt = bpf_map_lookup_elem(&hits, &zero);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	cnt = bpf_map_lookup_elem(&hits_by_kind, &kind);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline __u8 ascii_lower(__u8 c)
{
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	return c;
}

static __always_inline bool exec_name_denied(struct dentry *dentry)
{
	const __u8 *bytes;
	__u8 name[GUARD_EXEC_MAX] = {};
	__u32 len, part_len;

	if (!dentry)
		return true;
	bytes = dentry->d_name.name;
	len = dentry->d_name.len;
	if (!len || len > NAME_MAX)
		return true;
	part_len = len;
	if (part_len > GUARD_EXEC_MAX)
		part_len = GUARD_EXEC_MAX;
	if (bpf_probe_read_kernel(name, part_len, bytes))
		return true;

	/* Prefix matches: python*, perl5* */
	if (part_len >= 6 &&
	    name[0] == 'p' && name[1] == 'y' && name[2] == 't' &&
	    name[3] == 'h' && name[4] == 'o' && name[5] == 'n')
		return true;
	if (part_len >= 5 &&
	    name[0] == 'p' && name[1] == 'e' && name[2] == 'r' &&
	    name[3] == 'l' && name[4] == '5')
		return true;

	switch (len) {
	case 2:
		/* sh, nc */
		if (name[0] == 's' && name[1] == 'h')
			return true;
		if (name[0] == 'n' && name[1] == 'c')
			return true;
		break;
	case 3:
		/* ash, zsh, ksh, csh */
		if ((name[0] == 'a' || name[0] == 'z' ||
		     name[0] == 'k' || name[0] == 'c') &&
		    name[1] == 's' && name[2] == 'h')
			return true;
		break;
	case 4:
		/* bash, dash, tcsh, curl, wget, ncat, perl */
		if ((name[0] == 'b' || name[0] == 'd') &&
		    name[1] == 'a' && name[2] == 's' && name[3] == 'h')
			return true;
		if (name[0] == 't' && name[1] == 'c' &&
		    name[2] == 's' && name[3] == 'h')
			return true;
		if (name[0] == 'c' && name[1] == 'u' &&
		    name[2] == 'r' && name[3] == 'l')
			return true;
		if (name[0] == 'w' && name[1] == 'g' &&
		    name[2] == 'e' && name[3] == 't')
			return true;
		if (name[0] == 'n' && name[1] == 'c' &&
		    name[2] == 'a' && name[3] == 't')
			return true;
		if (name[0] == 'p' && name[1] == 'e' &&
		    name[2] == 'r' && name[3] == 'l')
			return true;
		break;
	case 5:
		/* socat */
		if (name[0] == 's' && name[1] == 'o' && name[2] == 'c' &&
		    name[3] == 'a' && name[4] == 't')
			return true;
		break;
	case 6:
		/* netcat */
		if (name[0] == 'n' && name[1] == 'e' && name[2] == 't' &&
		    name[3] == 'c' && name[4] == 'a' && name[5] == 't')
			return true;
		break;
	case 7:
		/* busybox */
		if (name[0] == 'b' && name[1] == 'u' && name[2] == 's' &&
		    name[3] == 'y' && name[4] == 'b' && name[5] == 'o' &&
		    name[6] == 'x')
			return true;
		break;
	default:
		break;
	}
	return false;
}

static __always_inline bool write_ext_denied(struct dentry *dentry)
{
	const __u8 *bytes;
	__u8 tail[GUARD_SUFFIX_MAX] = {};
	__u32 len, part_len, at;
	__u8 c0, c1, c2, c3, c4, c5;

	if (!dentry)
		return true;
	bytes = dentry->d_name.name;
	len = dentry->d_name.len;
	if (!len || len > NAME_MAX)
		return true;
	part_len = len;
	if (part_len > GUARD_SUFFIX_MAX)
		part_len = GUARD_SUFFIX_MAX;
	if (bpf_probe_read_kernel(tail, part_len, bytes + len - part_len))
		return true;

	/* .sh */
	if (part_len >= 3) {
		at = (part_len - 3) & (GUARD_SUFFIX_MAX - 1);
		c0 = tail[at];
		c1 = ascii_lower(tail[(at + 1) & (GUARD_SUFFIX_MAX - 1)]);
		c2 = ascii_lower(tail[(at + 2) & (GUARD_SUFFIX_MAX - 1)]);
		if (c0 == '.' && c1 == 's' && c2 == 'h')
			return true;
	}

	/* .php, .pht */
	if (part_len >= 4) {
		at = (part_len - 4) & (GUARD_SUFFIX_MAX - 1);
		c0 = tail[at];
		c1 = ascii_lower(tail[(at + 1) & (GUARD_SUFFIX_MAX - 1)]);
		c2 = ascii_lower(tail[(at + 2) & (GUARD_SUFFIX_MAX - 1)]);
		c3 = ascii_lower(tail[(at + 3) & (GUARD_SUFFIX_MAX - 1)]);
		if (c0 == '.' && c1 == 'p' && c2 == 'h' &&
		    (c3 == 'p' || c3 == 't'))
			return true;
	}

	/* .phar, .php[0-9] */
	if (part_len >= 5) {
		at = (part_len - 5) & (GUARD_SUFFIX_MAX - 1);
		c0 = tail[at];
		c1 = ascii_lower(tail[(at + 1) & (GUARD_SUFFIX_MAX - 1)]);
		c2 = ascii_lower(tail[(at + 2) & (GUARD_SUFFIX_MAX - 1)]);
		c3 = ascii_lower(tail[(at + 3) & (GUARD_SUFFIX_MAX - 1)]);
		c4 = ascii_lower(tail[(at + 4) & (GUARD_SUFFIX_MAX - 1)]);
		if (c0 == '.' && c1 == 'p' && c2 == 'h' &&
		    c3 == 'a' && c4 == 'r')
			return true;
		if (c0 == '.' && c1 == 'p' && c2 == 'h' && c3 == 'p' &&
		    c4 >= '0' && c4 <= '9')
			return true;
	}

	/* .phtml */
	if (part_len >= 6) {
		at = (part_len - 6) & (GUARD_SUFFIX_MAX - 1);
		c0 = tail[at];
		c1 = ascii_lower(tail[(at + 1) & (GUARD_SUFFIX_MAX - 1)]);
		c2 = ascii_lower(tail[(at + 2) & (GUARD_SUFFIX_MAX - 1)]);
		c3 = ascii_lower(tail[(at + 3) & (GUARD_SUFFIX_MAX - 1)]);
		c4 = ascii_lower(tail[(at + 4) & (GUARD_SUFFIX_MAX - 1)]);
		c5 = ascii_lower(tail[(at + 5) & (GUARD_SUFFIX_MAX - 1)]);
		if (c0 == '.' && c1 == 'p' && c2 == 'h' && c3 == 't' &&
		    c4 == 'm' && c5 == 'l')
			return true;
	}

	return false;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(web_worker_exec, struct linux_binprm *bprm, int ret)
{
	struct dentry *dentry;

	if (ret)
		return ret;
	if (!is_web_worker())
		return 0;
	bump_activity();
	dentry = bprm->file ? bprm->file->f_path.dentry : NULL;
	if (exec_name_denied(dentry)) {
		bump_hit(HIT_KIND_EXEC);
		return -EACCES;
	}
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(web_worker_file_open, struct file *file, int ret)
{
	if (ret || !(file->f_mode & FMODE_WRITE))
		return ret;
	if (!is_web_worker())
		return 0;
	bump_activity();
	if (write_ext_denied(file->f_path.dentry)) {
		bump_hit(HIT_KIND_WRITE);
		return -EACCES;
	}
	return 0;
}
