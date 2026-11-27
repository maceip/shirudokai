// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pre-enforce shield reproducer verification harness.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "io.h"
#include "json.h"
#include "malloc.h"
#include "paths.h"
#include "reproducer_check.h"
#include "upatch.h"
#include "upatch_maps.h"
#include "upatch_resolve.h"

#define SNAPSHOT_FILE_MAX	(1024u * 1024u)

static bool stack_id_present(const __u32 *ids, __u32 count, __u32 want)
{
	__u32 i;

	for (i = 0; i < count; i++) {
		if (ids[i] == want)
			return true;
	}
	return false;
}

static int u32_cmp(const void *a, const void *b)
{
	__u32 left = *(const __u32 *)a;
	__u32 right = *(const __u32 *)b;

	return (left > right) - (left < right);
}

static void collect_new_stack_ids(const struct reproducer_snapshot *before,
				  const struct reproducer_snapshot *after,
				  struct reproducer_verdict *out)
{
	__u32 n_before = min(before->nr_stack_ids, REPRODUCER_MAX_STACK_IDS);
	__u32 n_after = min(after->nr_stack_ids, REPRODUCER_MAX_STACK_IDS);
	__u32 i;

	out->nr_stack_ids = 0;
	for (i = 0; i < n_after; i++) {
		__u32 id = after->stack_ids[i];

		if (stack_id_present(before->stack_ids, n_before, id) ||
		    stack_id_present(out->stack_ids, out->nr_stack_ids, id))
			continue;
		if (out->nr_stack_ids < REPRODUCER_MAX_STACK_IDS)
			out->stack_ids[out->nr_stack_ids++] = id;
	}
	if (out->nr_stack_ids > 1)
		qsort(out->stack_ids, out->nr_stack_ids,
		      sizeof(out->stack_ids[0]), u32_cmp);
}

static bool counters_ordered(const struct shield_counters *a,
			     const struct shield_counters *b)
{
	return b->activity >= a->activity &&
	       b->hits >= a->hits &&
	       b->enforced >= a->enforced &&
	       b->observed >= a->observed;
}

int reproducer_evaluate(const struct reproducer_snapshot *before,
			const struct reproducer_snapshot *after_exploit,
			const struct reproducer_snapshot *after_benign,
			struct reproducer_verdict *out)
{
	const struct reproducer_snapshot *benign = after_benign;

	if (!before || !after_exploit || !benign || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	collect_new_stack_ids(before, after_exploit, out);

	if (!counters_ordered(&before->counters, &after_exploit->counters) ||
	    !counters_ordered(&after_exploit->counters, &benign->counters) ||
	    after_exploit->missed_runs < before->missed_runs ||
	    benign->missed_runs < after_exploit->missed_runs) {
		out->counters_monotonic = false;
		return 0;
	}

	out->counters_monotonic = true;
	out->exploit_activity_delta =
		after_exploit->counters.activity - before->counters.activity;
	out->exploit_hits_delta =
		after_exploit->counters.hits - before->counters.hits;
	out->exploit_enforced_delta =
		after_exploit->counters.enforced - before->counters.enforced;
	out->exploit_observed_delta =
		after_exploit->counters.observed - before->counters.observed;

	out->benign_activity_delta =
		benign->counters.activity - after_exploit->counters.activity;
	out->benign_hits_delta =
		benign->counters.hits - after_exploit->counters.hits;
	out->benign_enforced_delta =
		benign->counters.enforced - after_exploit->counters.enforced;
	out->benign_observed_delta =
		benign->counters.observed - after_exploit->counters.observed;

	out->missed_runs_delta = benign->missed_runs - before->missed_runs;

	out->exploit_detected = out->exploit_hits_delta > 0;
	out->benign_clean = out->benign_hits_delta == 0;
	out->no_missed_runs = out->missed_runs_delta == 0;
	out->ok = out->exploit_detected && out->benign_clean &&
		  out->no_missed_runs;
	return 0;
}

struct stack_parse_ctx {
	__s64	elem;
	__u32	ids[REPRODUCER_MAX_STACK_IDS];
	__u32	nr_ids;
};

static int on_stack_id_elem(void *ctx)
{
	struct stack_parse_ctx *sc = ctx;

	if (sc->elem < 0 || (__u64)sc->elem > UINT32_MAX)
		return -ERANGE;
	if (sc->nr_ids >= REPRODUCER_MAX_STACK_IDS)
		return -E2BIG;
	sc->ids[sc->nr_ids++] = (__u32)sc->elem;
	return 0;
}

static int nonneg_u64(__s64 val, __u64 *out)
{
	if (val < 0)
		return -EINVAL;
	*out = (__u64)val;
	return 0;
}

int reproducer_snapshot_parse_json(const char *data, size_t len,
				   struct reproducer_snapshot *out)
{
	__s64 c_activity = 0, c_hits = 0, c_enforced = 0, c_observed = 0;
	__s64 activity = 0, hits = 0, enforced = 0, observed = 0;
	struct stack_parse_ctx sc = {};
	struct json_array stack_arr = {
		.on_elem = on_stack_id_elem,
		.ctx = &sc,
	};
	struct json_field stack_elem[] = {
		{ "", JSON_T_INT, &sc.elem, 0, 0, NULL, 0 },
	};
	struct json_field counter_fields[] = {
		{ "activity", JSON_T_INT, &c_activity, 0, 0, NULL, 0 },
		{ "hits", JSON_T_INT, &c_hits, 0, 0, NULL, 0 },
		{ "enforced", JSON_T_INT, &c_enforced, 0, 0, NULL, 0 },
		{ "observed", JSON_T_INT, &c_observed, 0, 0, NULL, 0 },
	};
	__s64 missed_runs = 0;
	struct json_field fields[] = {
		{ "activity", JSON_T_INT, &activity, 0, 0, NULL, 0 },
		{ "hits", JSON_T_INT, &hits, 0, 0, NULL, 0 },
		{ "enforced", JSON_T_INT, &enforced, 0, 0, NULL, 0 },
		{ "observed", JSON_T_INT, &observed, 0, 0, NULL, 0 },
		{ "counters", JSON_T_OBJECT, NULL, 0, 0,
		  counter_fields, ARRAY_SIZE(counter_fields) },
		{ "missed_runs", JSON_T_INT, &missed_runs, 0, 0, NULL, 0 },
		{ "stack_ids", JSON_T_ARRAY, &stack_arr, 0, 0,
		  stack_elem, ARRAY_SIZE(stack_elem) },
	};
	struct reproducer_snapshot snap = {};
	bool flat_seen, obj_seen;
	int ret;

	if (!data || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	ret = json_parse(data, len, fields, ARRAY_SIZE(fields));
	if (ret)
		return ret;

	flat_seen = fields[0].seen || fields[1].seen || fields[2].seen ||
		    fields[3].seen;
	obj_seen = fields[4].seen != 0;
	if ((flat_seen && obj_seen) || (!flat_seen && !obj_seen))
		return -EINVAL;

	if (obj_seen) {
		if (nonneg_u64(c_activity, &snap.counters.activity) ||
		    nonneg_u64(c_hits, &snap.counters.hits) ||
		    nonneg_u64(c_enforced, &snap.counters.enforced) ||
		    nonneg_u64(c_observed, &snap.counters.observed))
			return -EINVAL;
	} else {
		if (nonneg_u64(activity, &snap.counters.activity) ||
		    nonneg_u64(hits, &snap.counters.hits) ||
		    nonneg_u64(enforced, &snap.counters.enforced) ||
		    nonneg_u64(observed, &snap.counters.observed))
			return -EINVAL;
	}
	if (nonneg_u64(missed_runs, &snap.missed_runs))
		return -EINVAL;
	snap.nr_stack_ids = sc.nr_ids;
	if (sc.nr_ids)
		memcpy(snap.stack_ids, sc.ids,
		       (size_t)sc.nr_ids * sizeof(sc.ids[0]));
	*out = snap;
	return 0;
}

int reproducer_snapshot_read_file(const char *path,
				  struct reproducer_snapshot *out)
{
	char *buf = NULL;
	size_t len = 0;
	int ret;

	if (!path || !out)
		return -EINVAL;
	ret = read_file(path, SNAPSHOT_FILE_MAX, &buf, &len);
	if (ret)
		return ret;
	ret = reproducer_snapshot_parse_json(buf, len, out);
	xfree(buf, len + 1);
	return ret;
}

static int read_counters_pin(const char *upatch_name, const char *map_name,
			     struct shield_counters *out)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	char pin[PATH_MAX];
	__u32 zero = 0;
	int fd, ret;

	memset(out, 0, sizeof(*out));
	if (!upatch_name_valid(upatch_name) || !upatch_map_name_valid(map_name))
		return -EINVAL;
	if (upatch_pin_path(pin, sizeof(pin), upatch_name, "maps", map_name,
			    NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = bpf_map_get_info_by_fd(fd, &info, &info_len);
	if (ret) {
		ret = -errno;
		goto out;
	}
	if (info.key_size != sizeof(__u32) ||
	    info.value_size != sizeof(struct shield_counters)) {
		ret = -EINVAL;
		goto out;
	}
	if (info.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		int nr_cpus = upatch_nproc_possible();
		size_t stride = DIV_ROUND_UP(sizeof(struct shield_counters), 8) * 8;
		size_t buf_sz;
		__u8 *percpu;
		int cpu;

		if (nr_cpus <= 0) {
			ret = nr_cpus < 0 ? nr_cpus : -EINVAL;
			goto out;
		}
		buf_sz = size_mul((size_t)nr_cpus, stride);
		percpu = xcalloc(1, buf_sz);
		if (!percpu) {
			ret = -ENOMEM;
			goto out;
		}
		ret = bpf_map_lookup_elem(fd, &zero, percpu) ? -errno : 0;
		if (!ret) {
			for (cpu = 0; cpu < nr_cpus; cpu++) {
				struct shield_counters c;

				memcpy(&c, percpu + (size_t)cpu * stride,
				       sizeof(c));
				out->activity += c.activity;
				out->hits += c.hits;
				out->enforced += c.enforced;
				out->observed += c.observed;
			}
		}
		xfree(percpu, buf_sz);
		goto out;
	}
	if (info.type != BPF_MAP_TYPE_ARRAY) {
		ret = -EINVAL;
		goto out;
	}
	ret = bpf_map_lookup_elem(fd, &zero, out) ? -errno : 0;
out:
	close(fd);
	return ret;
}

static int read_stack_ids_pin(const char *upatch_name, const char *map_name,
			      struct reproducer_snapshot *snap)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	__u32 cur_key = 0, next_key = 0;
	bool has_cur = false;
	char pin[PATH_MAX];
	int fd, ret = 0;

	snap->nr_stack_ids = 0;
	if (!map_name)
		return 0;
	if (!upatch_name_valid(upatch_name) || !upatch_map_name_valid(map_name))
		return -EINVAL;
	if (upatch_pin_path(pin, sizeof(pin), upatch_name, "maps", map_name,
			    NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	if (bpf_map_get_info_by_fd(fd, &info, &info_len)) {
		ret = -errno;
		goto out;
	}
	if ((info.type != BPF_MAP_TYPE_HASH &&
	     info.type != BPF_MAP_TYPE_PERCPU_HASH &&
	     info.type != BPF_MAP_TYPE_LRU_HASH &&
	     info.type != BPF_MAP_TYPE_LRU_PERCPU_HASH) ||
	    info.key_size != sizeof(__u32) ||
	    info.value_size != sizeof(__u64)) {
		ret = -EINVAL;
		goto out;
	}
	while (snap->nr_stack_ids < REPRODUCER_MAX_STACK_IDS) {
		int err = bpf_map_get_next_key(fd, has_cur ? &cur_key : NULL,
					       &next_key);

		if (err) {
			if (errno != ENOENT)
				ret = -errno;
			break;
		}
		snap->stack_ids[snap->nr_stack_ids++] = next_key;
		cur_key = next_key;
		has_cur = true;
	}
	if (!ret && snap->nr_stack_ids == REPRODUCER_MAX_STACK_IDS) {
		if (bpf_map_get_next_key(fd, &cur_key, &next_key) == 0)
			ret = -E2BIG;
		else if (errno != ENOENT)
			ret = -errno;
	}
out:
	close(fd);
	return ret;
}

int reproducer_capture_snapshot(const char *upatch_name,
				const char *counters_map,
				const char *stack_map,
				struct reproducer_snapshot *out)
{
	__u32 nr_counted = 0;
	__u64 missed = 0;
	int ret;

	if (!upatch_name || !upatch_name_valid(upatch_name) ||
	    !upatch_map_name_valid(counters_map) ||
	    (stack_map && !upatch_map_name_valid(stack_map)) || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	ret = read_counters_pin(upatch_name, counters_map, &out->counters);
	if (ret)
		return ret;
	ret = read_stack_ids_pin(upatch_name, stack_map, out);
	if (ret)
		return ret;
	ret = upatch_missed_runs(upatch_name, &nr_counted, &missed);
	if (ret && ret != -ENOENT)
		return ret;
	out->missed_runs = missed;
	return 0;
}

int reproducer_snapshot_json(const struct reproducer_snapshot *snap,
			     char **out_buf, size_t *out_cap)
{
	struct json_emit e = { .max = JSON_MAX_BYTES };
	__u32 i, n;

	if (!snap || !out_buf || !out_cap)
		return -EINVAL;
	*out_buf = NULL;
	*out_cap = 0;

	json_obj_open(&e);
	json_kv_u64(&e, "activity", snap->counters.activity);
	json_kv_u64(&e, "hits", snap->counters.hits);
	json_kv_u64(&e, "enforced", snap->counters.enforced);
	json_kv_u64(&e, "observed", snap->counters.observed);
	json_kv_u64(&e, "missed_runs", snap->missed_runs);
	json_arr_open(&e, "stack_ids");
	n = min(snap->nr_stack_ids, REPRODUCER_MAX_STACK_IDS);
	for (i = 0; i < n; i++)
		json_u64_value(&e, snap->stack_ids[i]);
	json_arr_close(&e);
	json_obj_close(&e);

	if (e.err) {
		xfree(e.buf, e.cap);
		return e.err;
	}
	*out_buf = e.buf;
	*out_cap = e.cap;
	return 0;
}

int reproducer_snapshot_write_file(const struct reproducer_snapshot *snap,
				   const char *path)
{
	char *buf = NULL;
	size_t cap = 0;
	int fd, ret;

	if (!snap || !path || !path[0])
		return -EINVAL;
	ret = reproducer_snapshot_json(snap, &buf, &cap);
	if (ret)
		return ret;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	ret = write_complete(fd, buf, strlen(buf));
	if (!ret)
		ret = write_complete(fd, "\n", 1);
	if (close(fd) && !ret)
		ret = -errno;
out:
	xfree(buf, cap);
	return ret;
}

int reproducer_snapshot_files_identical(const char *path_a, const char *path_b,
					bool *identical)
{
	struct stat st_a, st_b;
	char *buf_a = NULL, *buf_b = NULL;
	size_t len_a = 0, len_b = 0;
	int ret;

	if (!path_a || !path_b || !identical)
		return -EINVAL;
	*identical = false;
	if (strcmp(path_a, path_b) == 0) {
		*identical = true;
		return 0;
	}
	if (stat(path_a, &st_a) || stat(path_b, &st_b))
		return 0;
	if (st_a.st_dev == st_b.st_dev && st_a.st_ino == st_b.st_ino) {
		*identical = true;
		return 0;
	}
	if (st_a.st_size != st_b.st_size)
		return 0;
	ret = read_file(path_a, SNAPSHOT_FILE_MAX, &buf_a, &len_a);
	if (ret)
		return ret;
	ret = read_file(path_b, SNAPSHOT_FILE_MAX, &buf_b, &len_b);
	if (!ret)
		*identical = len_a == len_b &&
			     (!len_a || memcmp(buf_a, buf_b, len_a) == 0);
	xfree(buf_a, len_a + 1);
	if (buf_b)
		xfree(buf_b, len_b + 1);
	return ret;
}

static int run_input_once(int prog_fd, const char *input_path, __u32 *retval)
{
	__u8 *buf = NULL;
	size_t len = 0;
	int ret;

	ret = read_file(input_path, REPRODUCER_INPUT_MAX, &buf, &len);
	if (ret)
		return ret;
	ret = prog_test_run(prog_fd, buf, (__u32)len, retval);
	xfree(buf, len + 1);
	return ret;
}

int reproducer_run_test_prog(const char *upatch_name,
			     const char *counters_map,
			     const char *stack_map,
			     const char *test_input_path,
			     const char *benign_input_path,
			     struct reproducer_verdict *out)
{
	struct reproducer_snapshot before = {}, after_exp = {}, after_ben = {};
	__u32 exp_ret = 0, ben_ret = 0;
	struct bpf_prog_info pinfo = {};
	__u32 plen = sizeof(pinfo);
	char test_pin[PATH_MAX];
	int prog_fd, ret;

	if (!upatch_name || !upatch_name_valid(upatch_name) ||
	    !upatch_map_name_valid(counters_map) ||
	    (stack_map && !upatch_map_name_valid(stack_map)) ||
	    !test_input_path || !test_input_path[0] ||
	    !benign_input_path || !benign_input_path[0] || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	if (upatch_pin_path(test_pin, sizeof(test_pin), upatch_name, "test",
			    NULL))
		return -ENAMETOOLONG;
	prog_fd = bpf_obj_get(test_pin);
	if (prog_fd < 0)
		return -errno;
	ret = bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen);
	if (ret) {
		ret = -errno;
		goto out;
	}
	if (pinfo.type != BPF_PROG_TYPE_SYSCALL) {
		ret = -ESTALE;
		goto out;
	}
	ret = reproducer_capture_snapshot(upatch_name, counters_map, stack_map,
					  &before);
	if (ret)
		goto out;
	ret = run_input_once(prog_fd, test_input_path, &exp_ret);
	if (ret)
		goto out;
	ret = reproducer_capture_snapshot(upatch_name, counters_map, stack_map,
					  &after_exp);
	if (ret)
		goto out;
	ret = run_input_once(prog_fd, benign_input_path, &ben_ret);
	if (ret)
		goto out;
	ret = reproducer_capture_snapshot(upatch_name, counters_map, stack_map,
					  &after_ben);
	if (ret)
		goto out;
	ret = reproducer_evaluate(&before, &after_exp, &after_ben, out);
	out->has_benign_test_run = true;
	out->benign_test_run_retval = ben_ret;
	out->test_run_executed = true;
	out->test_run_retval = exp_ret;
out:
	close(prog_fd);
	return ret;
}

int reproducer_verdict_json(const char *upatch_name,
			    const struct reproducer_verdict *v,
			    char **out_buf, size_t *out_cap)
{
	struct json_emit e = { .max = JSON_MAX_BYTES };
	__u32 i;

	if (!v || !out_buf || !out_cap)
		return -EINVAL;
	*out_buf = NULL;
	*out_cap = 0;

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	if (upatch_name && upatch_name[0])
		json_kv_string_lossy(&e, "upatch", upatch_name);
	else
		json_kv_null(&e, "upatch");
	json_kv_string(&e, "verdict", v->ok ? "pass" : "fail");
	json_kv_bool(&e, "ok", v->ok);

	json_obj_open_key(&e, "checks");
	json_kv_bool(&e, "exploit_detected", v->exploit_detected);
	json_kv_bool(&e, "benign_clean", v->benign_clean);
	json_kv_bool(&e, "no_missed_runs", v->no_missed_runs);
	json_kv_bool(&e, "counters_monotonic", v->counters_monotonic);
	json_obj_close(&e);

	json_obj_open_key(&e, "deltas");
	json_kv_u64(&e, "exploit_activity", v->exploit_activity_delta);
	json_kv_u64(&e, "exploit_hits", v->exploit_hits_delta);
	json_kv_u64(&e, "exploit_enforced", v->exploit_enforced_delta);
	json_kv_u64(&e, "exploit_observed", v->exploit_observed_delta);
	json_kv_u64(&e, "benign_activity", v->benign_activity_delta);
	json_kv_u64(&e, "benign_hits", v->benign_hits_delta);
	json_kv_u64(&e, "benign_enforced", v->benign_enforced_delta);
	json_kv_u64(&e, "benign_observed", v->benign_observed_delta);
	json_kv_u64(&e, "missed_runs", v->missed_runs_delta);
	json_obj_close(&e);

	json_arr_open(&e, "stack_ids");
	for (i = 0; i < v->nr_stack_ids; i++)
		json_u64_value(&e, v->stack_ids[i]);
	json_arr_close(&e);

	if (v->test_run_executed) {
		json_obj_open_key(&e, "test_run");
		json_kv_int(&e, "exploit_retval", (__s32)v->test_run_retval);
		if (v->has_benign_test_run)
			json_kv_int(&e, "benign_retval",
				    (__s32)v->benign_test_run_retval);
		else
			json_kv_null(&e, "benign_retval");
		json_obj_close(&e);
	} else {
		json_kv_null(&e, "test_run");
	}
	json_obj_close(&e);

	if (e.err) {
		xfree(e.buf, e.cap);
		return e.err;
	}
	*out_buf = e.buf;
	*out_cap = e.cap;
	return 0;
}

void reproducer_verdict_print(FILE *fp, const char *upatch_name,
			      const struct reproducer_verdict *v)
{
	__u32 i;

	if (!fp || !v)
		return;
	if (upatch_name && upatch_name[0]) {
		char clean[UPATCH_NAME_MAX + 1];

		if (strscpy(clean, upatch_name, sizeof(clean)) < 0)
			strscpy_literal(clean, "?");
		text_sanitize(clean, strlen(clean), false);
		fprintf(fp, "Upatch:                %s\n", clean);
	}
	fprintf(fp, "Verdict:               %s\n", v->ok ? "PASS" : "FAIL");
	fprintf(fp, "Checks:\n");
	fprintf(fp, "  Exploit detected:    %s (hits_delta=%llu, activity_delta=%llu, observed_delta=%llu, enforced_delta=%llu)\n",
		v->exploit_detected ? "ok" : "fail",
		(__u64)v->exploit_hits_delta,
		(__u64)v->exploit_activity_delta,
		(__u64)v->exploit_observed_delta,
		(__u64)v->exploit_enforced_delta);
	fprintf(fp, "  Benign clean:        %s (hits_delta=%llu, activity_delta=%llu)\n",
		v->benign_clean ? "ok" : "fail",
		(__u64)v->benign_hits_delta,
		(__u64)v->benign_activity_delta);
	fprintf(fp, "  No missed runs:      %s (missed_runs_delta=%llu)\n",
		v->no_missed_runs ? "ok" : "fail",
		(__u64)v->missed_runs_delta);
	fprintf(fp, "  Counters monotonic:  %s\n",
		v->counters_monotonic ? "ok" : "fail");
	fprintf(fp, "Captured stack IDs:    ");
	if (!v->nr_stack_ids) {
		fprintf(fp, "(none)\n");
	} else {
		for (i = 0; i < v->nr_stack_ids; i++)
			fprintf(fp, "%s%u", i ? ", " : "", v->stack_ids[i]);
		fprintf(fp, "\n");
	}
	if (v->test_run_executed) {
		fprintf(fp, "Test run:\n");
		fprintf(fp, "  Exploit retval:      %d\n",
			(__s32)v->test_run_retval);
		if (v->has_benign_test_run)
			fprintf(fp, "  Benign retval:       %d\n",
				(__s32)v->benign_test_run_retval);
	}
}
