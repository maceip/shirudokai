// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/enforcement.h>
#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/tpm.h>

#include "image_bootstrap.h"
#include "image_config.h"
#include "io.h"
#include "paths.h"
#include "unit.h"

#define TEST_ROOT_HEX \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static struct image_bootstrap boot;

static int fd_with(const char *text, size_t len)
{
	int fd;

	fd = memfd_create("bootstrap", MFD_CLOEXEC);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, text, len), 0);
	return fd;
}

static int parse_text(const char *text, bool initial)
{
	size_t len = strlen(text);
	int fd, ret;

	fd = fd_with(text, len);
	ret = image_bootstrap_read_fd(fd, &boot, initial);
	EXPECT_TRUE(fcntl(fd, F_GETFD) >= 0);
	ASSERT_EQ(close(fd), 0);
	return ret;
}

static int parse_fresh(const char *text, bool initial)
{
	memset(&boot, 0, sizeof(boot));
	return parse_text(text, initial);
}

static void make_temp_dir(char path[256])
{
	const char *tmp = getenv("TMPDIR");

	ASSERT_TRUE(strsprintf(path, 256, "%s/shirudo-boot-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(path));
}

static void validates_image_paths(void)
{
	EXPECT_TRUE(image_path_valid("/var/lib/shirudo/runtime"));
	EXPECT_TRUE(image_path_valid("/run/shirudo/runtime/keys/cert.der"));
	EXPECT_FALSE(image_path_valid(NULL));
	EXPECT_FALSE(image_path_valid(""));
	EXPECT_FALSE(image_path_valid("/"));
	EXPECT_FALSE(image_path_valid("relative/path"));
	EXPECT_FALSE(image_path_valid("/var/../etc/passwd"));
	EXPECT_FALSE(image_path_valid("/var/./image"));
	EXPECT_FALSE(image_path_valid("/var//image"));
	EXPECT_FALSE(image_path_valid("/var/.."));
}

static void initrd_reads_runtime_and_refuses_enforcement_mode(void)
{
	static const char *const rejected[] = {
		"runtime.image = /var/lib/shirudo/runtime\n"
		"runtime.root_hash = " TEST_ROOT_HEX "\n"
		"enforcement.mode = strict\n",
		"runtime.image = /var/lib/shirudo/runtime\n"
		"runtime.root_hash = " TEST_ROOT_HEX "\n"
		"enforcement.mode = shared\n",
		"runtime.image = /var/lib/shirudo/runtime\n"
		"runtime.root_hash = " TEST_ROOT_HEX "\n"
		"enforcement.other = strict\n",
	};
	size_t i;

	EXPECT_EQ(parse_fresh("# initrd bootstrap\n"
			      "runtime.image = /var/lib/shirudo/runtime\n"
			      "runtime.root_hash = " TEST_ROOT_HEX "\n",
			      true), 0);
	EXPECT_STREQ(boot.runtime, "/var/lib/shirudo/runtime");
	EXPECT_TRUE(boot.have_root);
	EXPECT_EQ(boot.runtime_root[0], 0x01);
	EXPECT_EQ(boot.runtime_root[31], 0xef);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_STRICT);
	EXPECT_FALSE(boot.have_enforcement);

	for (i = 0; i < ARRAY_SIZE(rejected); i++)
		EXPECT_EQ(parse_fresh(rejected[i], true), -EINVAL);
}

static void runtime_defaults_to_strict_and_accepts_strict_or_shared(void)
{
	EXPECT_EQ(parse_fresh("config.image = /var/lib/shirudo/images/base\n"
			      "config.pcr = 15\n", false), 0);
	EXPECT_STREQ(boot.config, "/var/lib/shirudo/images/base");
	EXPECT_TRUE(boot.have_pcr);
	EXPECT_UEQ(boot.pcr, 15);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_STRICT);
	EXPECT_FALSE(boot.have_enforcement);

	EXPECT_EQ(parse_fresh("config.nvpcr = " TPM_CONFIG_NVPCR_NAME "\n"
			      "  enforcement.mode = strict\t\n", false), 0);
	EXPECT_TRUE(boot.have_pcr);
	EXPECT_UEQ(boot.pcr, TPM_CONFIG_NVPCR_INDEX);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_STRICT);
	EXPECT_TRUE(boot.have_enforcement);

	EXPECT_EQ(parse_fresh("config.pcr = 12\n"
			      "enforcement.mode = shared\n", false), 0);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_SHARED);
	EXPECT_TRUE(boot.have_enforcement);
}

static void runtime_reread_resets_enforcement_mode(void)
{
	ASSERT_EQ(parse_fresh("enforcement.mode = shared\n", false), 0);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_SHARED);
	EXPECT_TRUE(boot.have_enforcement);

	ASSERT_EQ(parse_text("config.pcr = 14\n", false), 0);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_STRICT);
	EXPECT_FALSE(boot.have_enforcement);
}

static void runtime_refuses_unknown_or_repeated_enforcement_mode(void)
{
	static const char *const bad_modes[] = {
		"enforcement.mode = loose\n",
		"enforcement.mode = Shared\n",
		"enforcement.mode = STRICT\n",
		"enforcement.mode =\n",
		"enforcement.unknown = shared\n",
		"enforcement.mode = strict\nenforcement.mode = shared\n",
		"enforcement.mode = shared\nenforcement.mode = shared\n",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(bad_modes); i++)
		EXPECT_EQ(parse_fresh(bad_modes[i], false), -EINVAL);
}

static void runtime_refuses_runtime_keys_and_bad_settings(void)
{
	static const char *const bad_runtime[] = {
		"runtime.image = /var/lib/shirudo/runtime\n",
		"runtime.root_hash = " TEST_ROOT_HEX "\n",
		"config.unknown = 1\n",
		"config.pcr = 9\n",
		"config.pcr = 11\n",
		"config.pcr = 24\n",
		"config.nvpcr = other\n",
		"missing_equals_sign\n",
	};
	char embedded_nul[] = "enforcement.mode = shared\0extra\n";
	size_t i;
	int fd;

	for (i = 0; i < ARRAY_SIZE(bad_runtime); i++)
		EXPECT_EQ(parse_fresh(bad_runtime[i], false), -EINVAL);

	fd = fd_with(embedded_nul, sizeof(embedded_nul) - 1);
	memset(&boot, 0, sizeof(boot));
	EXPECT_EQ(image_bootstrap_read_fd(fd, &boot, false), -EINVAL);
	ASSERT_EQ(close(fd), 0);
}

static void runtime_collects_and_bounds_verification_keys(void)
{
	char lines[4096] = {};
	size_t len = 0, i;
	int ret;

	for (i = 0; i < KEYS_MAX; i++) {
		ret = strsprintf(lines + len, sizeof(lines) - len,
				 "config.verification_key = " RUNTIME_DIR
				 "/keys/c-%zu.der\n", i);
		ASSERT_TRUE(ret > 0);
		len += (size_t)ret;
	}
	EXPECT_EQ(parse_fresh(lines, false), 0);
	EXPECT_UEQ(boot.n_certificates, KEYS_MAX);

	ret = strsprintf(lines + len, sizeof(lines) - len,
			 "config.verification_key = " RUNTIME_DIR
			 "/keys/extra.der\n");
	ASSERT_TRUE(ret > 0);
	EXPECT_EQ(parse_fresh(lines, false), -E2BIG);

	EXPECT_EQ(parse_fresh("config.verification_key = " RUNTIME_DIR
			      "/keys/a.der\n"
			      "config.verification_key = " RUNTIME_DIR
			      "/keys/a.der\n", false), -EEXIST);

	EXPECT_EQ(parse_fresh("config.verification_key = /etc/shirudo/a.der\n",
			      false), -EPERM);
}

static void write_config_conf(int root_fd, const char *text)
{
	int fd;

	fd = openat(root_fd, "etc/shirudo/shirudo.conf",
		    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, text, strlen(text)), 0);
	ASSERT_EQ(close(fd), 0);
}

static void config_image_refuses_enforcement_mode(void)
{
	static const char *const bad_configs[] = {
		"enforcement.mode = shared\n",
		"enforcement.mode = strict\n",
		"enforcement.other = strict\n",
		"eventlog.max_bytes = 4096\nenforcement.mode = shared\n",
	};
	char dir[256];
	int root_fd;
	size_t i;

	make_temp_dir(dir);
	root_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(root_fd >= 0);
	ASSERT_EQ(mkdirat(root_fd, "etc", 0755), 0);
	ASSERT_EQ(mkdirat(root_fd, "etc/shirudo", 0755), 0);

	write_config_conf(root_fd, "eventlog.max_bytes = 4096\n");
	EXPECT_EQ(image_config_validate(root_fd), 0);

	for (i = 0; i < ARRAY_SIZE(bad_configs); i++) {
		write_config_conf(root_fd, bad_configs[i]);
		EXPECT_EQ(image_config_validate(root_fd), -EPERM);
	}

	ASSERT_EQ(unlinkat(root_fd, "etc/shirudo/shirudo.conf", 0), 0);
	ASSERT_EQ(unlinkat(root_fd, "etc/shirudo", AT_REMOVEDIR), 0);
	ASSERT_EQ(unlinkat(root_fd, "etc", AT_REMOVEDIR), 0);
	ASSERT_EQ(close(root_fd), 0);
	ASSERT_EQ(rmdir(dir), 0);
}

static void reads_from_path_and_keeps_caller_fd_open(void)
{
	static const char content[] =
		"config.pcr = 13\nenforcement.mode = shared\n";
	char dir[256], path[300];
	int fd;

	make_temp_dir(dir);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/shirudo.conf", dir) > 0);
	memset(&boot, 0, sizeof(boot));
	EXPECT_EQ(image_bootstrap_read(path, &boot, false), -ENOENT);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, content, sizeof(content) - 1), 0);
	ASSERT_EQ(lseek(fd, 7, SEEK_SET), 7);

	memset(&boot, 0, sizeof(boot));
	EXPECT_EQ(image_bootstrap_read(path, &boot, false), 0);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_SHARED);
	EXPECT_UEQ(boot.pcr, 13);

	memset(&boot, 0, sizeof(boot));
	EXPECT_EQ(image_bootstrap_read_fd(fd, &boot, false), 0);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_SHARED);
	EXPECT_TRUE(fcntl(fd, F_GETFD) >= 0);

	memset(&boot, 0, sizeof(boot));
	EXPECT_EQ(image_bootstrap_read_fd(fd, &boot, false), 0);
	EXPECT_UEQ(boot.enforcement, ENFORCEMENT_SHARED);

	ASSERT_EQ(close(fd), 0);
	ASSERT_EQ(unlink(path), 0);
	ASSERT_EQ(rmdir(dir), 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(validates_image_paths),
	UNIT_CASE(initrd_reads_runtime_and_refuses_enforcement_mode),
	UNIT_CASE(runtime_defaults_to_strict_and_accepts_strict_or_shared),
	UNIT_CASE(runtime_reread_resets_enforcement_mode),
	UNIT_CASE(runtime_refuses_unknown_or_repeated_enforcement_mode),
	UNIT_CASE(runtime_refuses_runtime_keys_and_bad_settings),
	UNIT_CASE(runtime_collects_and_bounds_verification_keys),
	UNIT_CASE(config_image_refuses_enforcement_mode),
	UNIT_CASE(reads_from_path_and_keeps_caller_fd_open),
	{}
};

UNIT_SUITE(image_bootstrap, cases);
