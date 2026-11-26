// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "malloc.h"
#include "reproducer_check.h"
#include "unit.h"

static void reproducer_passes_when_exploit_hits_and_benign_is_clean(void)
{
	struct reproducer_snapshot before = {
		.counters = { .activity = 10, .hits = 1, .observed = 1 },
		.missed_runs = 2,
		.stack_ids = { 10 },
		.nr_stack_ids = 1,
	};
	struct reproducer_snapshot after_exp = {
		.counters = { .activity = 15, .hits = 4, .observed = 4 },
		.missed_runs = 2,
		.stack_ids = { 300, 10, 42, 300 },
		.nr_stack_ids = 4,
	};
	struct reproducer_snapshot after_ben = {
		.counters = { .activity = 35, .hits = 4, .observed = 4 },
		.missed_runs = 2,
		.stack_ids = { 300, 10, 42 },
		.nr_stack_ids = 3,
	};
	struct reproducer_verdict v;

	ASSERT_EQ(reproducer_evaluate(&before, &after_exp, &after_ben, &v), 0);
	EXPECT_TRUE(v.ok);
	EXPECT_TRUE(v.exploit_detected);
	EXPECT_TRUE(v.benign_clean);
	EXPECT_TRUE(v.no_missed_runs);
	EXPECT_TRUE(v.counters_monotonic);
	EXPECT_UEQ(v.exploit_activity_delta, 5);
	EXPECT_UEQ(v.exploit_hits_delta, 3);
	EXPECT_UEQ(v.exploit_observed_delta, 3);
	EXPECT_UEQ(v.benign_activity_delta, 20);
	EXPECT_UEQ(v.benign_hits_delta, 0);
	EXPECT_UEQ(v.missed_runs_delta, 0);
	ASSERT_UEQ(v.nr_stack_ids, 2);
	EXPECT_UEQ(v.stack_ids[0], 42);
	EXPECT_UEQ(v.stack_ids[1], 300);
}

static void reproducer_fails_on_zero_exploit_hits_benign_hit_or_miss(void)
{
	struct reproducer_snapshot before = {
		.counters = { .activity = 1, .hits = 0 },
		.missed_runs = 0,
	};
	struct reproducer_snapshot exp = {
		.counters = { .activity = 5, .hits = 0 },
		.missed_runs = 0,
	};
	struct reproducer_snapshot ben = {
		.counters = { .activity = 9, .hits = 0 },
		.missed_runs = 0,
	};
	struct reproducer_verdict v;

	/* No exploit hits -> fail. */
	ASSERT_EQ(reproducer_evaluate(&before, &exp, &ben, &v), 0);
	EXPECT_FALSE(v.ok);
	EXPECT_FALSE(v.exploit_detected);
	EXPECT_TRUE(v.benign_clean);
	EXPECT_TRUE(v.no_missed_runs);

	/* Benign false positive -> fail. */
	exp.counters.hits = 2;
	ben.counters.hits = 3;
	ASSERT_EQ(reproducer_evaluate(&before, &exp, &ben, &v), 0);
	EXPECT_FALSE(v.ok);
	EXPECT_TRUE(v.exploit_detected);
	EXPECT_FALSE(v.benign_clean);
	EXPECT_UEQ(v.benign_hits_delta, 1);

	/* Missed runs during evaluation -> fail. */
	ben.counters.hits = 2;
	ben.missed_runs = 1;
	ASSERT_EQ(reproducer_evaluate(&before, &exp, &ben, &v), 0);
	EXPECT_FALSE(v.ok);
	EXPECT_TRUE(v.exploit_detected);
	EXPECT_TRUE(v.benign_clean);
	EXPECT_FALSE(v.no_missed_runs);
	EXPECT_UEQ(v.missed_runs_delta, 1);

	/* Counter regression -> fail without unsigned wraparound. */
	before.counters.hits = 5;
	ASSERT_EQ(reproducer_evaluate(&before, &exp, &ben, &v), 0);
	EXPECT_FALSE(v.ok);
	EXPECT_FALSE(v.counters_monotonic);
	EXPECT_UEQ(v.exploit_hits_delta, 0);
}

static void snapshot_json_parses_flat_and_nested_and_rejects_bad_input(void)
{
	static const char flat[] =
		"{\"activity\":12,\"hits\":3,\"enforced\":0,\"observed\":3,"
		"\"missed_runs\":0,\"stack_ids\":[11,22]}";
	static const char nested[] =
		"{\"counters\":{\"activity\":20,\"hits\":4,\"enforced\":4,"
		"\"observed\":0},\"missed_runs\":1,\"stack_ids\":[99]}";
	static const char both[] =
		"{\"activity\":1,\"counters\":{\"activity\":1}}";
	static const char neg[] =
		"{\"activity\":-1,\"hits\":0,\"enforced\":0,\"observed\":0}";
	struct reproducer_snapshot snap;
	char tmpl[] = "/tmp/shirudo-repro-XXXXXX";
	int fd;

	ASSERT_EQ(reproducer_snapshot_parse_json(flat, strlen(flat), &snap), 0);
	EXPECT_UEQ(snap.counters.activity, 12);
	EXPECT_UEQ(snap.counters.hits, 3);
	EXPECT_UEQ(snap.counters.observed, 3);
	EXPECT_UEQ(snap.missed_runs, 0);
	ASSERT_UEQ(snap.nr_stack_ids, 2);
	EXPECT_UEQ(snap.stack_ids[0], 11);
	EXPECT_UEQ(snap.stack_ids[1], 22);

	ASSERT_EQ(reproducer_snapshot_parse_json(nested, strlen(nested), &snap),
		  0);
	EXPECT_UEQ(snap.counters.enforced, 4);
	EXPECT_UEQ(snap.missed_runs, 1);
	ASSERT_UEQ(snap.nr_stack_ids, 1);
	EXPECT_UEQ(snap.stack_ids[0], 99);

	EXPECT_EQ(reproducer_snapshot_parse_json(both, strlen(both), &snap),
		  -EINVAL);
	EXPECT_EQ(reproducer_snapshot_parse_json(neg, strlen(neg), &snap),
		  -EINVAL);
	EXPECT_EQ(reproducer_snapshot_parse_json("{}", 2, &snap), -EINVAL);

	fd = mkstemp(tmpl);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ((ssize_t)strlen(flat),
		  write(fd, flat, strlen(flat)));
	close(fd);
	ASSERT_EQ(reproducer_snapshot_read_file(tmpl, &snap), 0);
	EXPECT_UEQ(snap.counters.hits, 3);
	unlink(tmpl);
}

static void verdict_json_and_text_are_deterministic(void)
{
	struct reproducer_snapshot before = {};
	struct reproducer_snapshot exp = {
		.counters = { .activity = 4, .hits = 2, .observed = 2 },
		.stack_ids = { 77 },
		.nr_stack_ids = 1,
	};
	struct reproducer_verdict v;
	char *jbuf = NULL, *tbuf = NULL;
	size_t jcap = 0, tlen = 0;
	FILE *mem;

	ASSERT_EQ(reproducer_evaluate(&before, &exp, NULL, &v), 0);
	ASSERT_EQ(reproducer_verdict_json("cve-shield", &v, &jbuf, &jcap), 0);
	ASSERT_TRUE(jbuf);
	EXPECT_TRUE(str_contains(jbuf, "\"verdict\":\"pass\""));
	EXPECT_TRUE(str_contains(jbuf, "\"exploit_hits\":2"));
	EXPECT_TRUE(str_contains(jbuf, "\"stack_ids\":[77]"));
	xfree(jbuf, jcap);

	mem = open_memstream(&tbuf, &tlen);
	ASSERT_TRUE(mem);
	reproducer_verdict_print(mem, "cve-shield", &v);
	ASSERT_EQ(fclose(mem), 0);
	EXPECT_TRUE(str_contains(tbuf, "Verdict:               PASS"));
	EXPECT_TRUE(str_contains(tbuf, "Captured stack IDs:    77"));
	libc_free(tbuf);

	/* Invalid or unpinned upatch name fails cleanly in test-run runner. */
	EXPECT_EQ(reproducer_run_test_prog("../bad", "shield_counters", NULL,
					   "/nonexistent", NULL, &v), -EINVAL);
	EXPECT_TRUE(reproducer_run_test_prog("absent-shield", "shield_counters",
					     NULL, "/nonexistent", NULL,
					     &v) < 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(reproducer_passes_when_exploit_hits_and_benign_is_clean),
	UNIT_CASE(reproducer_fails_on_zero_exploit_hits_benign_hit_or_miss),
	UNIT_CASE(snapshot_json_parses_flat_and_nested_and_rejects_bad_input),
	UNIT_CASE(verdict_json_and_text_are_deterministic),
	{}
};

UNIT_SUITE(reproducer_check, cases);
