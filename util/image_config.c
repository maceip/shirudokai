// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "image_config.h"
#include "io.h"
#include "malloc.h"

static const char *const relative[IMAGE_PATH_COUNT] = {
	[IMAGE_ETC] = "etc/shirudo/bpm",
	[IMAGE_REGISTRIES] = "etc/shirudo/bpm/registries.d",
	[IMAGE_REPOSITORY_KEYS] = "etc/shirudo/bpm/keys",
	[IMAGE_TREE_CONF] = "etc/shirudo/bpm/upatch-tree.conf",
	[IMAGE_NODE_LABELS] = "etc/shirudo/node.labels",
	[IMAGE_TRUSTED_KEYS] = "keys/trusted",
	[IMAGE_REVOKED_KEYS] = "keys/revoked",
};

static struct config effective;
static bool active;
static int config_fd = -1;

bool image_config_active(void)
{
	return active;
}

int image_config_get(struct config *out)
{
	if (!active)
		return 0;
	*out = effective;
	return 1;
}

int image_config_root_fd(void)
{
	return config_fd;
}

/*
 * What the config image holds is opened from its verified root and
 * never through a path: a path, /proc/<pid>/fd included, is root's to
 * mount over before the exec.
 */
int image_open(enum image_path which, int flags)
{
	if (which >= IMAGE_PATH_COUNT || config_fd < 0)
		return -ENOENT;
	return open_beneath(config_fd, relative[which], flags);
}

int image_open_relative(const char *path, int flags)
{
	if (config_fd < 0 || !path || path[0] == '/' || str_contains(path, ".."))
		return -EINVAL;
	return open_beneath(config_fd, path, flags);
}

/* The image's shirudo.conf, read through its root. */
static int config_load_root(struct config *cfg, int root_fd)
{
	int fd, ret;

	fd = open_beneath(root_fd, "etc/shirudo/shirudo.conf", O_RDONLY);
	if (fd < 0)
		return fd;
	ret = config_load_fd(cfg, fd, "config image shirudo.conf");
	close(fd);
	return ret;
}

static int validate_tree(int root_fd, dev_t device, __u32 depth,
			 __u32 *entries)
{
	struct dirent *entry;
	struct stat st;
	DIR *dir;
	int fd, ret = 0;

	if (depth > 32)
		return -ELOOP;
	fd = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	dir = fdopendir(fd);
	if (!dir) {
		ret = -errno;
		close(fd);
		return ret;
	}
	for (;;) {
		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			if (errno)
				ret = -errno;
			break;
		}
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if (++*entries > 65536) {
			ret = -E2BIG;
			break;
		}
		if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
			ret = -errno;
			break;
		}
		if (st.st_dev != device ||
		    (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) {
			ret = -EPERM;
			break;
		}
		if (S_ISDIR(st.st_mode)) {
			int child = openat(fd, entry->d_name,
					   O_RDONLY | O_DIRECTORY | O_CLOEXEC |
						   O_NOFOLLOW);

			if (child < 0) {
				ret = -errno;
				break;
			}
			ret = validate_tree(child, device, depth + 1, entries);
			close(child);
			if (ret)
				break;
		}
	}
	closedir(dir);
	return ret;
}

static int validate_settings(int root_fd)
{
	char *line = NULL;
	size_t capacity = 0;
	FILE *file;
	ssize_t length;
	int fd, ret = 0;

	fd = open_beneath(root_fd, "etc/shirudo/shirudo.conf", O_RDONLY);
	if (fd < 0)
		return fd;
	file = fdopen(fd, "r");
	if (!file) {
		ret = -errno;
		close(fd);
		return ret;
	}
	while ((length = getline(&line, &capacity, file)) >= 0) {
		char *p = line, *end, *value;

		if (length > 1023 || strlen(line) != (size_t)length) {
			ret = -E2BIG;
			break;
		}
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || !*p)
			continue;
		value = strchr(p, '=');
		if (!value) {
			ret = -EINVAL;
			break;
		}
		*value++ = 0;
		end = p + strlen(p);
		while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
		*end = 0;
		if (!strcmp(p, "eventlog.max_bytes") ||
		    !strcmp(p, "security.epoch")) {
			__u64 number;

			while (*value == ' ' || *value == '\t')
				value++;
			end = value + strlen(value);
			while (end > value && (end[-1] == ' ' ||
					       end[-1] == '\t' || end[-1] == '\r' ||
			       end[-1] == '\n'))
				end--;
			if (parse_u64(value, end - value, ~0ULL, &number)) {
				ret = -EINVAL;
				break;
			}
		} else if (!str_has_prefix(p, "map_export.")) {
			ret = -EPERM;
			break;
		}
	}
	if (ferror(file) && !ret)
		ret = -EIO;
	libc_free(line);
	fclose(file);
	return ret;
}

int image_config_validate(int root_fd)
{
	struct config candidate __cleanup(config_clear);
	__u32 entries = 0;
	struct stat st;
	int ret;

	if (fstat(root_fd, &st))
		return -errno;
	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;
	ret = validate_tree(root_fd, st.st_dev, 0, &entries);
	if (!ret)
		ret = validate_settings(root_fd);
	if (!ret) {
		ret = config_load_root(&candidate, root_fd);
		if (!ret && (!candidate.map_export_valid ||
			     !candidate.tls_classical_hosts_valid ||
			     !candidate.security_epoch_valid))
			ret = -EINVAL;
	}
	return ret;
}

int image_config_read_epoch(int root_fd, __u64 *epoch)
{
	struct config candidate __cleanup(config_clear);
	int ret;

	if (!epoch)
		return -EINVAL;
	*epoch = 0;
	ret = config_load_root(&candidate, root_fd);
	if (!ret && !candidate.security_epoch_valid)
		ret = -EINVAL;
	if (!ret)
		*epoch = candidate.security_epoch;
	return ret;
}

int image_config_set(const struct config *bootstrap,
		     int root_fd)
{
	struct config candidate __cleanup(config_clear);
	int fd = -1, ret;

	candidate = *bootstrap;
	if (root_fd >= 0) {
		ret = image_config_validate(root_fd);
		if (ret)
			return ret;
		fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 3);
		if (fd < 0)
			return -errno;
		ret = config_load_root(&candidate, fd);
		if (ret || !candidate.map_export_valid ||
		    !candidate.tls_classical_hosts_valid ||
		    !candidate.security_epoch_valid) {
			close(fd);
			return ret ? ret : -EINVAL;
		}
		memcpy(candidate.tpm_owner_auth, bootstrap->tpm_owner_auth,
		       sizeof(candidate.tpm_owner_auth));
		candidate.tpm_owner_auth_len = bootstrap->tpm_owner_auth_len;
		memcpy(candidate.tpm_tcti, bootstrap->tpm_tcti,
		       sizeof(candidate.tpm_tcti));
		memcpy(candidate.tls_classical_hosts,
		       bootstrap->tls_classical_hosts,
		       sizeof(candidate.tls_classical_hosts));
		candidate.tls_classical_hosts_valid =
			bootstrap->tls_classical_hosts_valid;
	}
	if (config_fd >= 0)
		close(config_fd);
	config_fd = fd;
	effective = candidate;
	active = true;
	return 0;
}

void image_config_clear(void)
{
	if (config_fd >= 0)
		close(config_fd);
	config_fd = -1;
	active = false;
	memzero_explicit(&effective, sizeof(effective));
}
