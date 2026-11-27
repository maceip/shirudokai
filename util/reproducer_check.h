/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pre-enforce shield reproducer verification: evaluate observe/test-run
 * telemetry snapshots around an exploit reproducer and a benign workload,
 * and run pinned UPATCH_PROG_ROLE_TEST_RUN programs against test inputs.
 */

#ifndef SHIRUDO_UTIL_REPRODUCER_CHECK_H
#define SHIRUDO_UTIL_REPRODUCER_CHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <shirudo/misc.h>
#include "../bpf/lib/shield.h"

#define REPRODUCER_MAX_STACK_IDS	64u
#define REPRODUCER_INPUT_MAX		65535u

struct reproducer_snapshot {
	struct shield_counters	counters;
	__u64			missed_runs;
	__u32			stack_ids[REPRODUCER_MAX_STACK_IDS];
	__u32			nr_stack_ids;
};

struct reproducer_verdict {
	bool	ok;
	bool	exploit_detected;
	bool	benign_clean;
	bool	no_missed_runs;
	bool	counters_monotonic;
	__u64	exploit_activity_delta;
	__u64	exploit_hits_delta;
	__u64	exploit_enforced_delta;
	__u64	exploit_observed_delta;
	__u64	benign_activity_delta;
	__u64	benign_hits_delta;
	__u64	benign_enforced_delta;
	__u64	benign_observed_delta;
	__u64	missed_runs_delta;
	__u32	stack_ids[REPRODUCER_MAX_STACK_IDS];
	__u32	nr_stack_ids;
	bool	test_run_executed;
	__u32	test_run_retval;
	bool	has_benign_test_run;
	__u32	benign_test_run_retval;
};

int reproducer_evaluate(const struct reproducer_snapshot *before,
			const struct reproducer_snapshot *after_exploit,
			const struct reproducer_snapshot *after_benign,
			struct reproducer_verdict *out);

int reproducer_snapshot_parse_json(const char *data, size_t len,
				   struct reproducer_snapshot *out);
int reproducer_snapshot_read_file(const char *path,
				  struct reproducer_snapshot *out);
int reproducer_capture_snapshot(const char *upatch_name,
				const char *counters_map,
				const char *stack_map,
				struct reproducer_snapshot *out);
int reproducer_snapshot_json(const struct reproducer_snapshot *snap,
			     char **out_buf, size_t *out_cap);
int reproducer_snapshot_write_file(const struct reproducer_snapshot *snap,
				   const char *path);
int reproducer_snapshot_files_identical(const char *path_a, const char *path_b,
					bool *identical);

int reproducer_run_test_prog(const char *upatch_name,
			     const char *counters_map,
			     const char *stack_map,
			     const char *test_input_path,
			     const char *benign_input_path,
			     struct reproducer_verdict *out);

int reproducer_verdict_json(const char *upatch_name,
			    const struct reproducer_verdict *v,
			    char **out_buf, size_t *out_cap);
void reproducer_verdict_print(FILE *fp, const char *upatch_name,
			      const struct reproducer_verdict *v);

#endif /* SHIRUDO_UTIL_REPRODUCER_CHECK_H */
