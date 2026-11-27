// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "config.h"
#include "freshness.h"
#include "unit.h"

static void rm_rf(const char *dir)
{
	char cmd[512];

	if (strsprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir) >= 0)
		EXPECT_EQ(system(cmd), 0);
}

static int write_raw(const char *path, const char *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ssize_t n;

	if (fd < 0)
		return -errno;
	n = write(fd, data, len);
	close(fd);
	return n == (ssize_t)len ? 0 : -EIO;
}

static void missing_floor_reads_as_zero_and_allows_initial_epoch(void)
{
	char tmpl[] = "/tmp/shirudo-unit-freshness-XXXXXX";
	char path[512];
	__u64 floor = 99;
	char *dir;

	dir = mkdtemp(tmpl);
	ASSERT_TRUE(dir);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/epoch", dir) > 0);

	EXPECT_EQ(freshness_read_floor(path, &floor), 0);
	EXPECT_EQ(floor, 0u);
	EXPECT_EQ(freshness_verify(path, 0), 0);
	EXPECT_EQ(freshness_verify(path, 42), 0);
	EXPECT_EQ(freshness_advance(path, 0), 0);
	EXPECT_NE(access(path, F_OK), 0);

	rm_rf(dir);
}

static void advance_persists_floor_and_rejects_rollback(void)
{
	char tmpl[] = "/tmp/shirudo-unit-freshness-XXXXXX";
	struct stat st = {};
	char path[512];
	__u64 floor = 0;
	mode_t old_mask;
	char *dir;

	dir = mkdtemp(tmpl);
	ASSERT_TRUE(dir);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/epoch", dir) > 0);

	old_mask = umask(0077);
	umask(0);
	ASSERT_EQ(freshness_advance(path, 10), 0);
	umask(old_mask);
	ASSERT_EQ(stat(path, &st), 0);
	EXPECT_EQ(st.st_mode & 0777, 0600u);
	ASSERT_EQ(freshness_read_floor(path, &floor), 0);
	EXPECT_EQ(floor, 10u);

	EXPECT_EQ(freshness_verify(path, 10), 0);
	EXPECT_EQ(freshness_verify(path, 11), 0);
	EXPECT_EQ(freshness_verify(path, 9), -ESTALE);
	EXPECT_EQ(freshness_verify(path, 0), -ESTALE);
	EXPECT_EQ(freshness_advance(path, 9), -ESTALE);

	/* Equal epoch is idempotent; higher epoch advances floor. */
	EXPECT_EQ(freshness_advance(path, 10), 0);
	ASSERT_EQ(freshness_advance(path, UINT64_MAX), 0);
	ASSERT_EQ(freshness_read_floor(path, &floor), 0);
	EXPECT_EQ(floor, UINT64_MAX);
	EXPECT_EQ(freshness_verify(path, UINT64_MAX - 1), -ESTALE);
	EXPECT_EQ(freshness_verify(path, UINT64_MAX), 0);

	rm_rf(dir);
}

static void descriptor_floor_helpers_persist_and_reject_rollback(void)
{
	char tmpl[] = "/tmp/shirudo-unit-freshness-at-XXXXXX";
	char path[512];
	__u64 floor = 99;
	int dir_fd;
	char *dir;

	dir = mkdtemp(tmpl);
	ASSERT_TRUE(dir);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/epoch", dir) > 0);
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(dir_fd >= 0);

	EXPECT_EQ(freshness_read_floor_at(-1, &floor), -EINVAL);
	EXPECT_EQ(freshness_read_floor_at(dir_fd, NULL), -EINVAL);
	EXPECT_EQ(freshness_read_floor_at(dir_fd, &floor), 0);
	EXPECT_EQ(floor, 0u);
	EXPECT_EQ(freshness_verify_at(dir_fd, 0), 0);
	EXPECT_EQ(freshness_verify_at(dir_fd, 7), 0);
	EXPECT_EQ(freshness_advance_at(dir_fd, 0), 0);
	EXPECT_NE(access(path, F_OK), 0);

	ASSERT_EQ(freshness_advance_at(dir_fd, 7), 0);
	ASSERT_EQ(freshness_read_floor_at(dir_fd, &floor), 0);
	EXPECT_EQ(floor, 7u);
	EXPECT_EQ(freshness_verify_at(dir_fd, 7), 0);
	EXPECT_EQ(freshness_verify_at(dir_fd, 8), 0);
	EXPECT_EQ(freshness_verify_at(dir_fd, 6), -ESTALE);
	EXPECT_EQ(freshness_advance_at(dir_fd, 6), -ESTALE);
	EXPECT_EQ(freshness_advance_at(dir_fd, 7), 0);
	ASSERT_EQ(freshness_advance_at(dir_fd, UINT64_MAX), 0);
	ASSERT_EQ(freshness_read_floor_at(dir_fd, &floor), 0);
	EXPECT_EQ(floor, UINT64_MAX);
	EXPECT_EQ(freshness_verify_at(dir_fd, UINT64_MAX - 1), -ESTALE);

	ASSERT_EQ(write_raw(path, "bad\n", strlen("bad\n")), 0);
	EXPECT_EQ(freshness_read_floor_at(dir_fd, &floor), -EUCLEAN);
	EXPECT_EQ(freshness_verify_at(dir_fd, UINT64_MAX), -EUCLEAN);
	EXPECT_EQ(freshness_advance_at(dir_fd, UINT64_MAX), -EUCLEAN);

	close(dir_fd);
	rm_rf(dir);
}

static void corrupt_floor_fails_closed_with_euclean(void)
{
	char tmpl[] = "/tmp/shirudo-unit-freshness-XXXXXX";
	char path[512];
	__u64 floor = 0;
	char *dir;

	dir = mkdtemp(tmpl);
	ASSERT_TRUE(dir);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/epoch", dir) > 0);

	ASSERT_EQ(write_raw(path, "", 0), 0);
	EXPECT_EQ(freshness_read_floor(path, &floor), -EUCLEAN);
	EXPECT_EQ(freshness_verify(path, 1), -EUCLEAN);

	ASSERT_EQ(write_raw(path, "not-a-number\n",
			    strlen("not-a-number\n")), 0);
	EXPECT_EQ(freshness_read_floor(path, &floor), -EUCLEAN);

	ASSERT_EQ(write_raw(path, "-5\n", strlen("-5\n")), 0);
	EXPECT_EQ(freshness_read_floor(path, &floor), -EUCLEAN);

	rm_rf(dir);
}

static void config_parses_security_epoch_and_flags_bad_values(void)
{
	char tmpl[] = "/tmp/shirudo-unit-freshness-cfg-XXXXXX";
	struct config cfg __cleanup(config_clear) = {};
	char path[512];
	char *dir;

	dir = mkdtemp(tmpl);
	ASSERT_TRUE(dir);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/shirudo.conf", dir) > 0);

	ASSERT_EQ(write_raw(path, "security.epoch = 20261126\n",
			    strlen("security.epoch = 20261126\n")), 0);
	ASSERT_EQ(config_load_path(&cfg, path), 0);
	EXPECT_TRUE(cfg.security_epoch_valid);
	EXPECT_EQ(cfg.security_epoch, 20261126u);

	ASSERT_EQ(write_raw(path, "security.epoch = -1\n",
			    strlen("security.epoch = -1\n")), 0);
	ASSERT_EQ(config_load_path(&cfg, path), 0);
	EXPECT_TRUE(!cfg.security_epoch_valid);

	ASSERT_EQ(write_raw(path, "security.unknown = 1\n",
			    strlen("security.unknown = 1\n")), 0);
	ASSERT_EQ(config_load_path(&cfg, path), 0);
	EXPECT_TRUE(!cfg.security_epoch_valid);

	rm_rf(dir);
}

static const struct unit_case cases[] = {
	UNIT_CASE(missing_floor_reads_as_zero_and_allows_initial_epoch),
	UNIT_CASE(advance_persists_floor_and_rejects_rollback),
	UNIT_CASE(descriptor_floor_helpers_persist_and_reject_rollback),
	UNIT_CASE(corrupt_floor_fails_closed_with_euclean),
	UNIT_CASE(config_parses_security_epoch_and_flags_bad_values),
	{}
};

UNIT_SUITE(freshness, cases);
