// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Monotonic security.epoch floor for signed configuration updates.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "freshness.h"
#include "io.h"
#include "log.h"
#include "malloc.h"
#include "seal.h"

#define FRESHNESS_FILE_MAX	64
#define FRESHNESS_EPOCH_NAME	"epoch"

static int parse_floor_fd(int fd, const char *what, __u64 *floor)
{
	size_t len = 0, trim;
	char *buf = NULL;
	int ret;

	ret = read_fd(fd, "config epoch floor", FRESHNESS_FILE_MAX, &buf, &len);
	if (ret)
		return ret == -E2BIG || ret == -EFBIG ? -EUCLEAN : ret;
	trim = len;
	if (trim > 0 && buf[trim - 1] == '\n')
		trim--;
	if (trim > 0 && buf[trim - 1] == '\r')
		trim--;
	if (!trim || parse_u64(buf, trim, UINT64_MAX, floor)) {
		pr_err("freshness: corrupt epoch floor %s", what);
		ret = -EUCLEAN;
	}
	xfree(buf, len + 1);
	return ret;
}

static int read_floor_path(const char *path, __u64 *floor, bool *present)
{
	int fd, ret;

	if (!path || !floor)
		return -EINVAL;
	*floor = 0;
	if (present)
		*present = false;
	fd = seal_open_read(path);
	if (fd == -ENOENT)
		return 0;
	if (fd < 0)
		return fd;
	if (present)
		*present = true;
	ret = parse_floor_fd(fd, path, floor);
	close(fd);
	return ret;
}

static int read_floor_at(int dir_fd, __u64 *floor, bool *present)
{
	int fd, ret;

	if (dir_fd < 0 || !floor)
		return -EINVAL;
	*floor = 0;
	if (present)
		*present = false;
	fd = seal_open_child(dir_fd, FRESHNESS_EPOCH_NAME,
			     O_RDONLY | O_NONBLOCK);
	if (fd == -ENOENT)
		return 0;
	if (fd < 0)
		return fd;
	if (present)
		*present = true;
	ret = parse_floor_fd(fd, FRESHNESS_EPOCH_NAME, floor);
	close(fd);
	return ret;
}

static int check_epoch(__u64 candidate_epoch, __u64 floor)
{
	if (candidate_epoch < floor) {
		pr_err("freshness: refusing config rollback: security.epoch %llu is older than floor %llu",
		       candidate_epoch, floor);
		return -ESTALE;
	}
	return 0;
}

int freshness_read_floor(const char *path, __u64 *floor)
{
	return read_floor_path(path, floor, NULL);
}

int freshness_read_floor_at(int dir_fd, __u64 *floor)
{
	return read_floor_at(dir_fd, floor, NULL);
}

int freshness_verify(const char *path, __u64 candidate_epoch)
{
	__u64 floor = 0;
	int ret;

	ret = freshness_read_floor(path, &floor);
	if (ret)
		return ret;
	return check_epoch(candidate_epoch, floor);
}

int freshness_verify_at(int dir_fd, __u64 candidate_epoch)
{
	__u64 floor = 0;
	int ret;

	ret = freshness_read_floor_at(dir_fd, &floor);
	if (ret)
		return ret;
	return check_epoch(candidate_epoch, floor);
}

int freshness_advance(const char *path, __u64 candidate_epoch)
{
	bool present = false;
	__u64 floor = 0;
	char text[32];
	int len, ret;

	ret = read_floor_path(path, &floor, &present);
	if (ret)
		return ret;
	ret = check_epoch(candidate_epoch, floor);
	if (ret)
		return ret;
	if (candidate_epoch == floor && (!candidate_epoch || present))
		return 0;
	len = strsprintf(text, sizeof(text), "%llu\n", candidate_epoch);
	if (len < 0)
		return -EINVAL;
	return seal_write_file_mode(path, text, (size_t)len, 0600);
}

int freshness_advance_at(int dir_fd, __u64 candidate_epoch)
{
	bool present = false;
	__u64 floor = 0;
	char text[32];
	int len, ret;

	ret = read_floor_at(dir_fd, &floor, &present);
	if (ret)
		return ret;
	ret = check_epoch(candidate_epoch, floor);
	if (ret)
		return ret;
	if (candidate_epoch == floor && (!candidate_epoch || present))
		return 0;
	len = strsprintf(text, sizeof(text), "%llu\n", candidate_epoch);
	if (len < 0)
		return -EINVAL;
	return seal_replace_locked_at(dir_fd, FRESHNESS_EPOCH_NAME, text,
				      (size_t)len, 0600);
}
