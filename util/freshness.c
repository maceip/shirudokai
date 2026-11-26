// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Monotonic security.epoch floor for signed configuration updates.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "freshness.h"
#include "io.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

#define FRESHNESS_FILE_MAX	64

int freshness_read_floor(const char *path, __u64 *floor)
{
	char *buf = NULL;
	size_t len = 0, trim;
	int fd, ret;

	if (!path || !floor)
		return -EINVAL;
	*floor = 0;
	fd = open_trusted(path, O_RDONLY);
	if (fd == -ENOENT)
		return 0;
	if (fd < 0)
		return fd;
	ret = read_fd(fd, "config epoch floor", FRESHNESS_FILE_MAX, &buf, &len);
	close(fd);
	if (ret)
		return ret == -E2BIG ? -EUCLEAN : ret;
	trim = len;
	if (trim > 0 && buf[trim - 1] == '\n')
		trim--;
	if (trim > 0 && buf[trim - 1] == '\r')
		trim--;
	if (!trim || parse_u64(buf, trim, UINT64_MAX, floor)) {
		pr_err("freshness: corrupt epoch floor %s", path);
		ret = -EUCLEAN;
	}
	xfree(buf, len + 1);
	return ret;
}

int freshness_verify(const char *path, __u64 candidate_epoch)
{
	__u64 floor = 0;
	int ret;

	ret = freshness_read_floor(path, &floor);
	if (ret)
		return ret;
	if (candidate_epoch < floor) {
		pr_err("freshness: refusing config rollback: security.epoch %llu is older than floor %llu",
		       candidate_epoch, floor);
		return -ESTALE;
	}
	return 0;
}

int freshness_advance(const char *path, __u64 candidate_epoch)
{
	__u64 floor = 0;
	char text[32];
	int len, ret;

	ret = freshness_read_floor(path, &floor);
	if (ret)
		return ret;
	if (candidate_epoch < floor) {
		pr_err("freshness: refusing config rollback: security.epoch %llu is older than floor %llu",
		       candidate_epoch, floor);
		return -ESTALE;
	}
	if (candidate_epoch == floor &&
	    (candidate_epoch == 0 || path_exists(path)))
		return 0;
	len = strsprintf(text, sizeof(text), "%llu\n", candidate_epoch);
	if (len < 0)
		return -EINVAL;
	return seal_write_file(path, text, (size_t)len, 0600);
}
