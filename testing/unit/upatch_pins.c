// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "paths.h"
#include "unit.h"
#include "upatch_pins.h"

/*
 * readdir() fails only when the kernel or the libc makes it fail, which a
 * test cannot ask for, so these count the reads down and report EIO for the
 * one after the last, as a read that fails partway through does. opendir()
 * opens the directory of the case, because the pin path that the readers
 * resolve is not a directory the test may write. The readers call
 * readdir64, which readdir is with _FILE_OFFSET_BITS=64.
 */
static char test_dir[PATH_MAX];
static int reads_left = -1;

DIR *__real_opendir(const char *path);
DIR *__wrap_opendir(const char *path);
DIR *__wrap_opendir(const char *path)
{
	return __real_opendir(test_dir[0] ? test_dir : path);
}

struct dirent *__real_readdir64(DIR *d);
struct dirent *__wrap_readdir64(DIR *d);
struct dirent *__wrap_readdir64(DIR *d)
{
	if (reads_left == 0) {
		errno = EIO;
		return NULL;
	}
	if (reads_left > 0)
		reads_left--;
	return __real_readdir64(d);
}

static void read_entries_of(const char *dir, int reads)
{
	ASSERT_TRUE(strscpy(test_dir, dir, sizeof(test_dir)) >= 0);
	reads_left = reads;
}

static void read_entries_of_no_dir(void)
{
	test_dir[0] = '\0';
	reads_left = -1;
}

static void names_are_parsed_strictly(void)
{
	static const char * const ignored[] = {
		"link_", "link_07", "link_1x", "link_-1", "link_+1",
		"link_4294967296", "link_ 1", "links", "xdp_prog_",
		"xdp_prog_01", "xdp_prog_a", "tcx_prog_", "tcx_prog_01",
		"tcx_prog_a", "test", "maps", "serializers",
		".", "..",
	};
	struct upatch_pins pins = {};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ignored); i++)
		upatch_pins_note(&pins, ignored[i]);
	EXPECT_FALSE(pins.has_link);
	EXPECT_UEQ(pins.nr_links, 0);
	EXPECT_UEQ(pins.nr_xdp_progs, 0);
	EXPECT_UEQ(pins.nr_tcx_progs, 0);
	EXPECT_FALSE(upatch_pins_loaded(&pins));
}

static void lowest_index_is_kept_in_any_order(void)
{
	struct upatch_pins pins = {};

	upatch_pins_note(&pins, "link_7");
	upatch_pins_note(&pins, "link_4294967295");
	upatch_pins_note(&pins, "link_2");
	upatch_pins_note(&pins, "xdp_prog_3");
	upatch_pins_note(&pins, "xdp_prog_1");
	upatch_pins_note(&pins, "tcx_prog_5");
	upatch_pins_note(&pins, "tcx_prog_2");
	EXPECT_UEQ(pins.nr_links, 3);
	EXPECT_UEQ(pins.first_link, 2);
	EXPECT_UEQ(pins.nr_xdp_progs, 2);
	EXPECT_UEQ(pins.first_xdp_prog, 1);
	EXPECT_UEQ(pins.nr_tcx_progs, 2);
	EXPECT_UEQ(pins.first_tcx_prog, 2);
}

static void loaded_needs_the_first_link_or_a_program(void)
{
	struct upatch_pins pins = {};

	upatch_pins_note(&pins, "link_1");
	EXPECT_FALSE(upatch_pins_loaded(&pins));
	upatch_pins_note(&pins, "link_0");
	EXPECT_TRUE(upatch_pins_loaded(&pins));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link");
	EXPECT_TRUE(upatch_pins_loaded(&pins));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "xdp_prog_4");
	EXPECT_TRUE(upatch_pins_loaded(&pins));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "tcx_prog_0");
	EXPECT_TRUE(upatch_pins_loaded(&pins));
}

static void complete_means_every_link(void)
{
	struct upatch_pins pins = {};

	EXPECT_TRUE(upatch_pins_complete(&pins, 0));
	EXPECT_FALSE(upatch_pins_complete(&pins, 1));
	upatch_pins_note(&pins, "link");
	EXPECT_TRUE(upatch_pins_complete(&pins, 1));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link_0");
	EXPECT_FALSE(upatch_pins_complete(&pins, 1));
	EXPECT_FALSE(upatch_pins_complete(&pins, 2));
	upatch_pins_note(&pins, "link_1");
	EXPECT_TRUE(upatch_pins_complete(&pins, 2));
	EXPECT_FALSE(upatch_pins_complete(&pins, 3));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link_1");
	upatch_pins_note(&pins, "link_2");
	EXPECT_FALSE(upatch_pins_complete(&pins, 2));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link_0");
	upatch_pins_note(&pins, "link_2");
	EXPECT_FALSE(upatch_pins_complete(&pins, 2));
}

static void absent_upatch_has_no_pins(void)
{
	struct upatch_pins pins = { .has_link = true };

	EXPECT_EQ(upatch_pins_read("shirudo-unit-no-such-upatch", &pins),
		  -ENOENT);
	EXPECT_FALSE(pins.has_link);
	EXPECT_EQ(upatch_loaded_pins("shirudo-unit-no-such-upatch"), 0);
}

static void xdp_program_pins_have_one_name(void)
{
	char pin[PATH_MAX], small[8];
	size_t len;

	ASSERT_EQ(upatch_xdp_prog_pin(pin, sizeof(pin), "fw", 3), 0);
	len = strlen(pin);
	ASSERT_TRUE(len > strlen("/xdp_prog_3"));
	EXPECT_STREQ(pin + len - strlen("/xdp_prog_3"), "/xdp_prog_3");
	EXPECT_EQ(upatch_xdp_prog_pin(small, sizeof(small), "fw", 3),
		  -ENAMETOOLONG);
	ASSERT_EQ(upatch_tcx_prog_pin(pin, sizeof(pin), "fw", 3), 0);
	len = strlen(pin);
	ASSERT_TRUE(len > strlen("/tcx_prog_3"));
	EXPECT_STREQ(pin + len - strlen("/tcx_prog_3"), "/tcx_prog_3");
	EXPECT_EQ(upatch_tcx_prog_pin(small, sizeof(small), "fw", 3),
		  -ENAMETOOLONG);
}

static void an_unpinned_xdp_program_does_not_open(void)
{
	__u32 id = 0;

	EXPECT_TRUE(upatch_xdp_prog_open("shirudo-unit-no-such-upatch", 0,
					 &id) < 0);
	EXPECT_EQ(id, 0);
}

static void link_pins_read_back_as_links(void)
{
	struct upatch_pins pins = {};
	char pin[64], small[8];

	ASSERT_EQ(upatch_link_pin(pin, sizeof(pin), "/d", 4294967295U), 0);
	EXPECT_STREQ(pin, "/d/link_4294967295");
	upatch_pins_note(&pins, pin + strlen("/d/"));
	EXPECT_UEQ(pins.nr_links, 1);
	EXPECT_UEQ(pins.last_link, 4294967295U);
	EXPECT_EQ(upatch_link_pin(small, sizeof(small), "/d", 10),
		  -ENAMETOOLONG);
}

static void payload_of_absent_upatch_is_enoent(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	char name[PATH_MAX];

	EXPECT_EQ(upatch_pin_payload("shirudo-unit-no-such-upatch", payload),
		  -ENOENT);
	memset(name, 'a', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	EXPECT_EQ(upatch_pin_payload(name, payload), -ENAMETOOLONG);
}

static int count_pinned(const char *name, void *ctx)
{
	(*(int *)ctx)++;
	return 0;
}

static void no_pin_directory_is_no_upatch(void)
{
	int seen = 0;

	if (access(BPFFS_UPATCHES_DIR, F_OK) == 0)
		unit_skip("this host has a shirudo pin directory");
	EXPECT_EQ(upatch_each_pinned(count_pinned, &seen), 0);
	EXPECT_EQ(seen, 0);
}

static int count_link(__u32 index, const char *pin, void *ctx)
{
	(*(int *)ctx)++;
	return 0;
}

static void make_entry(const char *dir, const char *name)
{
	char path[PATH_MAX];
	int fd;

	ASSERT_EQ(path_join(path, sizeof(path), dir, name), 0);
	fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	close(fd);
}

static void drop_entry(const char *dir, const char *name)
{
	char path[PATH_MAX];

	ASSERT_EQ(path_join(path, sizeof(path), dir, name), 0);
	ASSERT_EQ(unlink(path), 0);
}

static void pin_entries_are_walked(void)
{
	char dir[] = "/tmp/shirudo-unit-pins-XXXXXX";
	static const char * const entries[] = { "link_0", "link_2", "alpha" };
	struct upatch_pins pins = {};
	size_t i;
	int seen = 0;

	ASSERT_TRUE(mkdtemp(dir));
	for (i = 0; i < ARRAY_SIZE(entries); i++)
		make_entry(dir, entries[i]);

	read_entries_of(dir, -1);
	EXPECT_EQ(upatch_pins_read("shirudo-unit-pins", &pins), 0);
	EXPECT_UEQ(pins.nr_links, 2);
	EXPECT_UEQ(pins.first_link, 0);
	EXPECT_UEQ(pins.last_link, 2);
	EXPECT_EQ(upatch_each_link("shirudo-unit-pins", count_link, &seen), 0);
	EXPECT_UEQ(seen, 2);
	seen = 0;
	EXPECT_EQ(upatch_each_pinned(count_pinned, &seen), 0);
	EXPECT_UEQ(seen, ARRAY_SIZE(entries));
	read_entries_of_no_dir();

	for (i = 0; i < ARRAY_SIZE(entries); i++)
		drop_entry(dir, entries[i]);
	ASSERT_EQ(rmdir(dir), 0);
}

static void a_failed_readdir_is_an_error(void)
{
	char dir[] = "/tmp/shirudo-unit-pins-XXXXXX";
	struct upatch_pins pins = {};
	int seen = 0;

	ASSERT_TRUE(mkdtemp(dir));
	/* Read the "." and ".." of the empty directory, then fail. */
	read_entries_of(dir, 2);
	EXPECT_EQ(upatch_pins_read("shirudo-unit-pins", &pins), -EIO);
	EXPECT_UEQ(pins.nr_links, 0);
	reads_left = 2;
	EXPECT_EQ(upatch_loaded_pins("shirudo-unit-pins"), -EIO);
	reads_left = 2;
	EXPECT_EQ(upatch_each_link("shirudo-unit-pins", count_link, &seen),
		  -EIO);
	EXPECT_UEQ(seen, 0);
	reads_left = 2;
	EXPECT_EQ(upatch_each_pinned(count_pinned, &seen), -EIO);
	EXPECT_UEQ(seen, 0);
	read_entries_of_no_dir();
	ASSERT_EQ(rmdir(dir), 0);
}

static void a_failed_read_leaves_no_pins(void)
{
	char dir[] = "/tmp/shirudo-unit-pins-XXXXXX";
	static const char * const entries[] = { "link", "link_0", "link_1" };
	struct upatch_pins pins = {};
	size_t i;

	ASSERT_TRUE(mkdtemp(dir));
	for (i = 0; i < ARRAY_SIZE(entries); i++)
		make_entry(dir, entries[i]);

	/* Four reads succeed, "." and ".." among them: two pins at least. */
	read_entries_of(dir, 4);
	EXPECT_EQ(upatch_pins_read("shirudo-unit-pins", &pins), -EIO);
	EXPECT_FALSE(pins.has_link);
	EXPECT_UEQ(pins.nr_links, 0);
	EXPECT_FALSE(upatch_pins_loaded(&pins));
	read_entries_of_no_dir();

	for (i = 0; i < ARRAY_SIZE(entries); i++)
		drop_entry(dir, entries[i]);
	ASSERT_EQ(rmdir(dir), 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(names_are_parsed_strictly),
	UNIT_CASE(lowest_index_is_kept_in_any_order),
	UNIT_CASE(loaded_needs_the_first_link_or_a_program),
	UNIT_CASE(complete_means_every_link),
	UNIT_CASE(absent_upatch_has_no_pins),
	UNIT_CASE(xdp_program_pins_have_one_name),
	UNIT_CASE(an_unpinned_xdp_program_does_not_open),
	UNIT_CASE(link_pins_read_back_as_links),
	UNIT_CASE(payload_of_absent_upatch_is_enoent),
	UNIT_CASE(no_pin_directory_is_no_upatch),
	UNIT_CASE(pin_entries_are_walked),
	UNIT_CASE(a_failed_readdir_is_an_error),
	UNIT_CASE(a_failed_read_leaves_no_pins),
	{}
};

UNIT_SUITE(upatch_pins, cases);
