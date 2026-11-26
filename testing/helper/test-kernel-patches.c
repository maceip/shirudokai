// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Qualification probes for the carried kernel patches 0020..0024:
 *   status [--btf <path>]   BTF readiness table for 0020..0024
 *   tpm <dev>               0020: header bounds and lsm/tpm_command
 *   xattr-unpriv <f> <d> <x> 0021: unprivileged security.bpf.* label reads
 *   sleepable-inode <dir>   0022 & 0023: sleepable inode hooks and d_parent
 *   mm-read <pid>           0024: read-only /proc/<pid> mm access under root
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/fs.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "kernel_abi.h"

#define REGISTER_NV_INDEX	0x01818e00U
#define TPM2_ST_NO_SESSIONS	0x8001U
#define TPM2_ST_SESSIONS	0x8002U
#define TPM2_CC_NV_EXTEND	0x00000136U
#define TPM2_CC_GET_RANDOM	0x0000017bU

static int fail_errno(const char *step, int err)
{
	fprintf(stderr, "%s: errno=%d (%s)\n", step, err, strerror(err));
	return 1;
}

static bool denied_errno(int err)
{
	return err == EACCES || err == EPERM;
}

static void put_be16(__u8 *dst, __u16 val)
{
	dst[0] = (__u8)(val >> 8);
	dst[1] = (__u8)val;
}

static void put_be32(__u8 *dst, __u32 val)
{
	dst[0] = (__u8)(val >> 24);
	dst[1] = (__u8)(val >> 16);
	dst[2] = (__u8)(val >> 8);
	dst[3] = (__u8)val;
}

static int cmd_status(const char *btf_path)
{
	struct kernel_patch_status st = {};
	struct btf *btf = NULL;
	size_t i;
	int ret;

	if (btf_path) {
		btf = btf__parse(btf_path, NULL);
		if (libbpf_get_error(btf))
			return fail_errno("btf__parse", (int)-libbpf_get_error(btf));
		ret = kernel_abi_patch_status_btf(btf, &st);
		btf__free(btf);
	} else {
		ret = kernel_abi_patch_status(&st);
	}
	printf("signed_loader_abi=%s\n", st.signed_loader_abi ? "yes" : "no");
	for (i = 0; i < ARRAY_SIZE(st.patches); i++) {
		const struct kernel_patch_entry *p = &st.patches[i];

		printf("%04u %s %s\n", p->number, p->name,
		       kernel_patch_readiness_name(p->readiness));
	}
	return ret == 0 ? 0 : 1;
}

static size_t build_nv_extend(__u8 buf[64], __u32 declared_len)
{
	memset(buf, 0, 64);
	put_be16(buf, TPM2_ST_SESSIONS);
	put_be32(buf + 2, declared_len);
	put_be32(buf + 6, TPM2_CC_NV_EXTEND);
	put_be32(buf + 10, REGISTER_NV_INDEX);
	put_be32(buf + 14, REGISTER_NV_INDEX);
	put_be32(buf + 18, 9);
	put_be32(buf + 22, 0x40000009U);
	buf[30] = 1;
	return 33;
}

static int expect_tpm_write_err(const char *dev, int flags, const __u8 *buf,
				size_t len, bool want_einval, const char *step)
{
	ssize_t n;
	int fd, err;

	fd = open(dev, O_RDWR | O_CLOEXEC | flags);
	if (fd < 0)
		return fail_errno(step, errno);
	n = write(fd, buf, len);
	err = n < 0 ? errno : 0;
	close(fd);
	if (n >= 0) {
		fprintf(stderr, "%s: write unexpectedly succeeded (%zd)\n",
			step, n);
		return 1;
	}
	if (want_einval ? err != EINVAL : !denied_errno(err))
		return fail_errno(step, err);
	return 0;
}

static int cmd_tpm(const char *dev)
{
	__u8 buf[64], rsp[64];
	size_t cmd_len;
	ssize_t n;
	int fd;

	memset(buf, 0, sizeof(buf));
	put_be16(buf, TPM2_ST_NO_SESSIONS);
	put_be32(buf + 2, 6);
	if (expect_tpm_write_err(dev, 0, buf, 6, true, "short_write"))
		return 1;
	if (expect_tpm_write_err(dev, 0, buf, 10, true, "underflow_header"))
		return 1;

	cmd_len = build_nv_extend(buf, 33);
	if (expect_tpm_write_err(dev, 0, buf, cmd_len, false, "nv_extend_sync"))
		return 1;
	if (expect_tpm_write_err(dev, O_NONBLOCK, buf, cmd_len, false,
				 "nv_extend_async"))
		return 1;
	if (expect_tpm_write_err(dev, 0, buf, 48, false, "nv_extend_trailing"))
		return 1;

	memset(buf, 0, sizeof(buf));
	put_be16(buf, TPM2_ST_NO_SESSIONS);
	put_be32(buf + 2, 12);
	put_be32(buf + 6, TPM2_CC_GET_RANDOM);
	put_be16(buf + 10, 8);
	fd = open(dev, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail_errno("get_random_open", errno);
	n = write(fd, buf, 12);
	if (n != 12) {
		int err = n < 0 ? errno : EIO;

		close(fd);
		return fail_errno("get_random_write", err);
	}
	n = read(fd, rsp, sizeof(rsp));
	close(fd);
	if (n < 10)
		return fail_errno("get_random_read", n < 0 ? errno : EIO);
	printf("ok\n");
	return 0;
}

static int xattr_unpriv_child(const char *wonly, const char *wxdir,
			      const char *noread)
{
	char probe[PATH_MAX];
	int fd;

	setfsuid(65534);
	if (setfsuid(-1) != 65534)
		return fail_errno("setfsuid", EPERM);

	fd = open(wonly, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		fprintf(stderr, "wonly_read: caller unexpectedly has MAY_READ\n");
		return 1;
	}
	if (errno != EACCES)
		return fail_errno("wonly_read", errno);

	fd = open(wonly, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		fprintf(stderr, "wonly_write: seal bypassed without MAY_READ\n");
		return 1;
	}
	if (!denied_errno(errno))
		return fail_errno("wonly_write", errno);

	fd = open(wxdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		fprintf(stderr, "wxdir_read: caller unexpectedly has MAY_READ\n");
		return 1;
	}
	if (strsprintf(probe, sizeof(probe), "%s/probe", wxdir) < 0)
		return 1;
	fd = open(probe, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd >= 0) {
		close(fd);
		unlink(probe);
		fprintf(stderr, "wxdir_creat: seal bypassed on d_parent\n");
		return 1;
	}
	if (!denied_errno(errno))
		return fail_errno("wxdir_creat", errno);

	if (removexattr(noread, "security.bpf.shirudo") == 0) {
		fprintf(stderr, "noread_removexattr: removed seal label\n");
		return 1;
	}
	if (!denied_errno(errno))
		return fail_errno("noread_removexattr", errno);
	return 0;
}

static int cmd_xattr_unpriv(const char *wonly, const char *wxdir,
			    const char *noread)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return fail_errno("fork", errno);
	if (pid == 0)
		_exit(xattr_unpriv_child(wonly, wxdir, noread));
	if (waitpid(pid, &status, 0) != pid)
		return fail_errno("waitpid", errno);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return 1;
	printf("ok\n");
	return 0;
}

static int join_path(char out[PATH_MAX], const char *dir, const char *leaf)
{
	return strsprintf(out, PATH_MAX, "%s/%s", dir, leaf) < 0 ? -ENAMETOOLONG : 0;
}

static int check_acl_hooks(const char *root)
{
	/* Minimal 28-byte little-endian POSIX ACL v2 (user::rw-,group::r--,other::r--). */
	static const __u8 acl_v2[28] = {
		0x02, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff,
		0x04, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff,
		0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff,
	};
	char plain[PATH_MAX], f_set[PATH_MAX], f_rm[PATH_MAX];

	if (join_path(plain, root, "plain_file") ||
	    join_path(f_set, root, "f_acl_set") ||
	    join_path(f_rm, root, "f_acl_rm"))
		return 1;

	if (setxattr(plain, "system.posix_acl_access", acl_v2,
		     sizeof(acl_v2), 0) != 0) {
		if (errno != EOPNOTSUPP)
			return fail_errno("plain_acl_probe", errno);
		if (setxattr(f_set, "system.posix_acl_access", acl_v2,
			     sizeof(acl_v2), 0) == 0) {
			fprintf(stderr, "acl_set: unexpectedly allowed\n");
			return 1;
		}
		return 0;
	}
	if (setxattr(f_set, "system.posix_acl_access", acl_v2,
		     sizeof(acl_v2), 0) == 0 || !denied_errno(errno))
		return fail_errno("inode_set_acl", errno);
	if (removexattr(f_rm, "system.posix_acl_access") == 0 ||
	    !denied_errno(errno))
		return fail_errno("inode_remove_acl", errno);
	return 0;
}

static int cmd_sleepable_inode(const char *root)
{
	char p1[PATH_MAX], p2[PATH_MAX];
	int fd, flags = 0, err;

	if (join_path(p1, root, "d_mkdir/sub") ||
	    (mkdir(p1, 0700) == 0 || !denied_errno(errno)))
		return fail_errno("inode_mkdir", errno);

	if (join_path(p1, root, "d_creat/entry"))
		return 1;
	fd = open(p1, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd >= 0) {
		close(fd);
		return fail_errno("inode_create", 0);
	}
	if (!denied_errno(errno))
		return fail_errno("inode_create", errno);

	if (join_path(p1, root, "d_sym/sym") ||
	    (symlink("target", p1) == 0 || !denied_errno(errno)))
		return fail_errno("inode_symlink", errno);

	if (join_path(p1, root, "d_mknod/fifo") ||
	    (mknod(p1, S_IFIFO | 0600, 0) == 0 || !denied_errno(errno)))
		return fail_errno("inode_mknod", errno);

	if (join_path(p1, root, "plain_file") ||
	    join_path(p2, root, "d_link/hard") ||
	    (link(p1, p2) == 0 || !denied_errno(errno)))
		return fail_errno("inode_link_dst", errno);

	if (join_path(p1, root, "f_link") ||
	    join_path(p2, root, "plain_dir/hard") ||
	    (link(p1, p2) == 0 || !denied_errno(errno)))
		return fail_errno("inode_link_src", errno);

	if (join_path(p1, root, "f_flags"))
		return 1;
	fd = open(p1, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return fail_errno("inode_file_setattr_open", errno);
	err = ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0 ? 0 : errno;
	close(fd);
	if (!denied_errno(err))
		return fail_errno("inode_file_setattr", err);

	if (check_acl_hooks(root))
		return 1;
	printf("ok\n");
	return 0;
}

static int cmd_mm_read(const char *pid_str)
{
	static const char *const entries[] = {
		"environ",
		"maps",
		"smaps",
		"auxv",
		"pagemap",
	};
	char self_path[PATH_MAX], proc_path[PATH_MAX];
	size_t i;
	int fd;

	fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return fail_errno("self_maps", errno);
	close(fd);

	for (i = 0; i < ARRAY_SIZE(entries); i++) {
		if (strsprintf(self_path, sizeof(self_path), "/proc/self/%s",
			       entries[i]) < 0 ||
		    strsprintf(proc_path, sizeof(proc_path), "/proc/%s/%s",
			       pid_str, entries[i]) < 0)
			return 1;
		if (access(self_path, F_OK) != 0)
			continue;
		fd = open(proc_path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			close(fd);
			fprintf(stderr, "mm_read: %s opened without authority\n",
				proc_path);
			return 1;
		}
		if (!denied_errno(errno))
			return fail_errno(entries[i], errno);
	}
	printf("ok\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "status"))
		return cmd_status(NULL);
	if (argc == 4 && !strcmp(argv[1], "status") && !strcmp(argv[2], "--btf"))
		return cmd_status(argv[3]);
	if (argc == 3 && !strcmp(argv[1], "tpm"))
		return cmd_tpm(argv[2]);
	if (argc == 5 && !strcmp(argv[1], "xattr-unpriv"))
		return cmd_xattr_unpriv(argv[2], argv[3], argv[4]);
	if (argc == 3 && !strcmp(argv[1], "sleepable-inode"))
		return cmd_sleepable_inode(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "mm-read"))
		return cmd_mm_read(argv[2]);

	fprintf(stderr,
		"usage: %s status [--btf <path>] | tpm <dev> | "
		"xattr-unpriv <wonly> <wxdir> <noread> | "
		"sleepable-inode <root> | mm-read <pid>\n",
		argv[0]);
	return 2;
}
