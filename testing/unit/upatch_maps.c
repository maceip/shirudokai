// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Unit tests for util/upatch_maps.c: BTF-typed and untyped ringbuf record
 * formatting and bounded one-shot batch consumption without kernel ringbufs.
 */

#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <string.h>

#include <bpf/btf.h>

#include <shirudo/string.h>

#include "unit.h"
#include "json.h"
#include "malloc.h"
#include "upatch_maps.h"

struct sample_event {
	__u32	pid;
	__s32	err;
	__u32	action;
	char	comm[8];
	__u16	ports[2];
};

static struct btf *build_event_btf(__u32 *event_type_id)
{
	struct btf *btf;
	int u32_id, s32_id, u16_id, char_id, comm_arr_id, port_arr_id;
	int enum_id, struct_id, ptr_id, map_struct_id;

	btf = btf__new_empty();
	ASSERT_TRUE(btf);

	u32_id = btf__add_int(btf, "__u32", 4, 0);
	s32_id = btf__add_int(btf, "__s32", 4, BTF_INT_SIGNED);
	u16_id = btf__add_int(btf, "__u16", 2, 0);
	char_id = btf__add_int(btf, "char", 1, BTF_INT_CHAR);
	ASSERT_TRUE(u32_id > 0 && s32_id > 0 && u16_id > 0 && char_id > 0);

	enum_id = btf__add_enum(btf, "event_action", 4);
	ASSERT_TRUE(enum_id > 0);
	ASSERT_EQ(btf__add_enum_value(btf, "ACT_ALLOW", 0), 0);
	ASSERT_EQ(btf__add_enum_value(btf, "ACT_DENY", 1), 0);

	comm_arr_id = btf__add_array(btf, u32_id, char_id, 8);
	port_arr_id = btf__add_array(btf, u32_id, u16_id, 2);
	ASSERT_TRUE(comm_arr_id > 0 && port_arr_id > 0);

	struct_id = btf__add_struct(btf, "sample_event",
				    sizeof(struct sample_event));
	ASSERT_TRUE(struct_id > 0);
	ASSERT_EQ(btf__add_field(btf, "pid", u32_id, 0, 0), 0);
	ASSERT_EQ(btf__add_field(btf, "err", s32_id, 32, 0), 0);
	ASSERT_EQ(btf__add_field(btf, "action", enum_id, 64, 0), 0);
	ASSERT_EQ(btf__add_field(btf, "comm", comm_arr_id, 96, 0), 0);
	ASSERT_EQ(btf__add_field(btf, "ports", port_arr_id, 160, 0), 0);

	ptr_id = btf__add_ptr(btf, struct_id);
	map_struct_id = btf__add_struct(btf, "", 8);
	ASSERT_TRUE(ptr_id > 0 && map_struct_id > 0);
	ASSERT_EQ(btf__add_field(btf, "value", ptr_id, 0, 0), 0);
	ASSERT_TRUE(btf__add_var(btf, "events", BTF_VAR_GLOBAL_ALLOCATED,
				 map_struct_id) > 0);

	*event_type_id = (__u32)struct_id;
	return btf;
}

static void ringbuf_btf_resolve_and_format(void)
{
	struct sample_event ev = {
		.pid	= 4242,
		.err	= -13,
		.action	= 1,
		.comm	= "sshd",
		.ports	= { 22, 443 },
	};
	struct ringbuf_record_spec spec = {};
	__u32 event_type_id = 0, resolved_id;
	char upatch[64] = {}, map[64] = {}, btf_type[64] = {};
	char comm[32] = {}, act[32] = {};
	__s64 size = 0, pid = 0, err_v = 0;
	struct json_field val_fields[] = {
		{ .key = "pid",    .type = JSON_T_INT,    .dst = &pid },
		{ .key = "err",    .type = JSON_T_INT,    .dst = &err_v },
		{ .key = "action", .type = JSON_T_STRING, .dst = act,  .dst_cap = sizeof(act) },
		{ .key = "comm",   .type = JSON_T_STRING, .dst = comm, .dst_cap = sizeof(comm) },
	};
	struct json_field top_fields[] = {
		{
			.key = "upatch", .type = JSON_T_STRING,
			.dst = upatch, .dst_cap = sizeof(upatch),
		},
		{
			.key = "map", .type = JSON_T_STRING,
			.dst = map, .dst_cap = sizeof(map),
		},
		{ .key = "size", .type = JSON_T_INT, .dst = &size },
		{
			.key = "btf_type", .type = JSON_T_STRING,
			.dst = btf_type, .dst_cap = sizeof(btf_type),
		},
		{
			.key = "value", .type = JSON_T_OBJECT,
			.sub = val_fields, .n_sub = ARRAY_SIZE(val_fields),
		},
	};
	char *json_out = NULL, *text_out = NULL;
	struct btf *btf;

	btf = build_event_btf(&event_type_id);
	resolved_id = ringbuf_resolve_btf_value_type(btf, "events", 0);
	ASSERT_EQ(resolved_id, event_type_id);
	ASSERT_EQ(ringbuf_resolve_btf_value_type(btf, "missing", 0), 0u);
	ASSERT_EQ(ringbuf_resolve_btf_value_type(btf, "events", 99u), 99u);

	spec.upatch = "guard-demo";
	spec.map = "events";
	spec.btf = btf;
	spec.value_type_id = resolved_id;

	ASSERT_EQ(ringbuf_format_record(&spec, &ev, sizeof(ev), true,
					&json_out), 0);
	ASSERT_TRUE(json_out);
	ASSERT_EQ(json_parse(json_out, strlen(json_out), top_fields,
			     ARRAY_SIZE(top_fields)), 0);
	ASSERT_STREQ(upatch, "guard-demo");
	ASSERT_STREQ(map, "events");
	ASSERT_EQ(size, (__s64)sizeof(ev));
	ASSERT_STREQ(btf_type, "struct sample_event");
	ASSERT_EQ(pid, 4242);
	ASSERT_EQ(err_v, -13);
	ASSERT_STREQ(act, "ACT_DENY");
	ASSERT_STREQ(comm, "sshd");
	ASSERT_TRUE(str_contains(json_out, "\"ports\":[22,443]"));
	xstrfree(json_out);

	ASSERT_EQ(ringbuf_format_record(&spec, &ev, sizeof(ev), false,
					&text_out), 0);
	ASSERT_TRUE(text_out);
	ASSERT_TRUE(str_contains(text_out,
				 "events (24 B): { pid=4242, err=-13, action=ACT_DENY"));
	xstrfree(text_out);

	btf__free(btf);
}

static void ringbuf_untyped_and_short_records(void)
{
	const __u8 raw[6] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02 };
	struct ringbuf_record_spec spec = {
		.upatch	= "raw-demo",
		.map	= "rb",
	};
	char hex[32] = {};
	__s64 size = -1;
	struct json_field fields[] = {
		{ .key = "size",     .type = JSON_T_INT,    .dst = &size },
		{ .key = "data_hex", .type = JSON_T_STRING, .dst = hex, .dst_cap = sizeof(hex) },
	};
	char *json_out = NULL, *text_out = NULL;
	__u32 event_type_id = 0;
	struct btf *btf;

	ASSERT_EQ(ringbuf_format_record(&spec, raw, sizeof(raw), true,
					&json_out), 0);
	ASSERT_EQ(json_parse(json_out, strlen(json_out), fields,
			     ARRAY_SIZE(fields)), 0);
	ASSERT_EQ(size, 6);
	ASSERT_STREQ(hex, "deadbeef0102");
	xstrfree(json_out);

	ASSERT_EQ(ringbuf_format_record(&spec, raw, sizeof(raw), false,
					&text_out), 0);
	ASSERT_STREQ(text_out, "rb (6 B): 0xdeadbeef0102");
	xstrfree(text_out);

	/* Sample shorter than BTF struct falls back to hex without over-read. */
	btf = build_event_btf(&event_type_id);
	spec.btf = btf;
	spec.value_type_id = event_type_id;
	ASSERT_EQ(ringbuf_format_record(&spec, raw, sizeof(raw), false,
					&text_out), 0);
	ASSERT_STREQ(text_out, "rb (6 B): 0xdeadbeef0102");
	xstrfree(text_out);

	ASSERT_EQ(ringbuf_format_record(&spec, raw,
					RINGBUF_MAX_SAMPLE_BYTES + 1,
					false, &text_out), -E2BIG);
	btf__free(btf);
}

static void ringbuf_batch_bounding_and_validation(void)
{
	struct ringbuf_record_spec spec = {
		.upatch	= "cap-demo",
		.map	= "events",
	};
	struct ringbuf_batch batch = {
		.max_records	= 2,
		.json		= true,
	};
	__u32 v1 = 1, v2 = 2, v3 = 3;

	ASSERT_EQ(ringbuf_consume_record(&spec, &v1, sizeof(v1), &batch), 0);
	ASSERT_EQ(ringbuf_consume_record(&spec, &v2, sizeof(v2), &batch), 0);
	ASSERT_FALSE(batch.truncated);
	ASSERT_UEQ(batch.n_records, 2u);

	ASSERT_EQ(ringbuf_consume_record(&spec, &v3, sizeof(v3), &batch), 0);
	ASSERT_TRUE(batch.truncated);
	ASSERT_UEQ(batch.n_records, 2u);
	ringbuf_batch_free(&batch);

	/* Parameter bounds and missing pin checks need no kernel ringbuf. */
	ASSERT_EQ(upatch_ringbuf_read("../bad", NULL, 10, 0, false, &batch),
		  -EINVAL);
	ASSERT_EQ(upatch_ringbuf_read("ok-name", NULL, 0, 0, false, &batch),
		  -EINVAL);
	ASSERT_EQ(upatch_ringbuf_read("ok-name", NULL,
				      RINGBUF_MAX_RECORDS_LIMIT + 1, 0,
				      false, &batch), -EINVAL);
	ASSERT_EQ(upatch_ringbuf_read("ok-name", NULL, 10,
				      RINGBUF_MAX_TIMEOUT_MS + 1,
				      false, &batch), -EINVAL);
	ASSERT_EQ(upatch_ringbuf_read("ok-name", "bad/map", 10, 0,
				      false, &batch), -EINVAL);
}

struct shield_stats_val {
	__u64	hits;
	__u64	activity;
};

static void shield_hits_summary_percpu_and_struct(void)
{
	struct shield_hits_summary sum = {};
	struct map_entry entries[2] = {};
	struct map_view v = {};
	__u32 k0 = 0, k1 = 1;
	__u8 cpu_u32_0[16] = {}, cpu_u32_1[16] = {};
	struct shield_stats_val st_cpu[2] = {
		{ .hits = 11, .activity = 100 },
		{ .hits = 29, .activity = 250 },
	};
	__u32 c0 = 7, c1 = 9, a0 = 30, a1 = 12, poison = 0xdeadbeef;
	int u32_id, s32_id, u64_id, st_id;
	struct btf *btf;

	memcpy(cpu_u32_0, &c0, 4);
	memcpy(cpu_u32_0 + 4, &poison, 4);
	memcpy(cpu_u32_0 + 8, &c1, 4);
	memcpy(cpu_u32_1, &a0, 4);
	memcpy(cpu_u32_1 + 8, &a1, 4);

	btf = btf__new_empty();
	ASSERT_TRUE(btf);
	u32_id = btf__add_int(btf, "__u32", 4, 0);
	s32_id = btf__add_int(btf, "__s32", 4, BTF_INT_SIGNED);
	u64_id = btf__add_int(btf, "__u64", 8, 0);
	st_id = btf__add_struct(btf, "shield_stats_val", sizeof(st_cpu[0]));
	ASSERT_TRUE(u32_id > 0 && s32_id > 0 && u64_id > 0 && st_id > 0);
	ASSERT_EQ(btf__add_field(btf, "hits", u64_id, 0, 0), 0);
	ASSERT_EQ(btf__add_field(btf, "activity", u64_id, 64, 0), 0);

	entries[0].key = &k0;
	entries[0].value = cpu_u32_0;
	entries[1].key = &k1;
	entries[1].value = cpu_u32_1;

	v.type = BPF_MAP_TYPE_PERCPU_ARRAY;
	v.type_name = "percpu_array";
	v.key_size = 4;
	v.value_size = 4;
	v.value_stride = 8;
	v.max_entries = 1;
	v.n_entries = 1;
	v.n_cpus = 2;
	v.btf = btf;
	v.key_type_id = (__u32)u32_id;
	v.value_type_id = (__u32)u32_id;
	v.entries = entries;

	/* Standard per-CPU `hits` and `activity` maps sum across CPUs. */
	memcpy(v.name, "hits", 5);
	ASSERT_EQ(upatch_shield_hits_summary(&v, &sum), 0);
	ASSERT_TRUE(sum.has_hits && !sum.has_activity);
	ASSERT_UEQ(sum.hits, 16u);

	memcpy(v.name, "activity", 9);
	entries[0].value = cpu_u32_1;
	ASSERT_EQ(upatch_shield_hits_summary(&v, &sum), 0);
	ASSERT_TRUE(!sum.has_hits && sum.has_activity);
	ASSERT_UEQ(sum.activity, 42u);
	entries[0].value = cpu_u32_0;

	/* Non-shield map names return -ENOENT, preserving generic policy. */
	memcpy(v.name, "hits_total", 11);
	ASSERT_EQ(upatch_shield_hits_summary(&v, &sum), -ENOENT);

	/* Signed values and non-per-CPU maps are rejected. */
	memcpy(v.name, "hits", 5);
	v.value_type_id = (__u32)s32_id;
	ASSERT_EQ(upatch_shield_hits_summary(&v, &sum), -EOPNOTSUPP);
	v.value_type_id = (__u32)u32_id;
	v.type = BPF_MAP_TYPE_ARRAY;
	ASSERT_EQ(upatch_shield_hits_summary(&v, &sum), -EOPNOTSUPP);
	v.type = BPF_MAP_TYPE_PERCPU_ARRAY;

	/* 2-slot scalar `shield_stats` array exports hits + activity. */
	memcpy(v.name, "shield_stats", 13);
	v.max_entries = 2;
	v.n_entries = 2;
	ASSERT_EQ(upatch_shield_hits_summary(&v, &sum), 0);
	ASSERT_TRUE(sum.has_hits && sum.has_activity);
	ASSERT_UEQ(sum.hits, 16u);
	ASSERT_UEQ(sum.activity, 42u);

	/* BTF struct `shield_stats` sums both fields across CPUs. */
	entries[0].value = st_cpu;
	v.max_entries = 1;
	v.n_entries = 1;
	v.value_size = sizeof(st_cpu[0]);
	v.value_stride = sizeof(st_cpu[0]);
	v.value_type_id = (__u32)st_id;
	ASSERT_EQ(upatch_shield_hits_summary(&v, &sum), 0);
	ASSERT_TRUE(sum.has_hits && sum.has_activity);
	ASSERT_UEQ(sum.hits, 40u);
	ASSERT_UEQ(sum.activity, 350u);

	btf__free(btf);
}

static void map_name_and_btf_formatting_guards(void)
{
	struct map_view v = {};
	__u32 second = 99;
	char *cell;
	int u32_id, st_id;
	struct btf *btf;

	EXPECT_TRUE(upatch_nproc_possible() > 0);

	EXPECT_TRUE(upatch_map_name_valid("events"));
	EXPECT_TRUE(upatch_map_name_valid(".rodata"));
	EXPECT_TRUE(upatch_map_name_valid("__serial_buf"));
	EXPECT_TRUE(upatch_map_name_valid("shield_counters"));
	EXPECT_TRUE(upatch_map_name_valid("shield_stack_ids"));
	EXPECT_FALSE(upatch_map_name_valid(NULL));
	EXPECT_FALSE(upatch_map_name_valid(""));
	EXPECT_FALSE(upatch_map_name_valid("."));
	EXPECT_FALSE(upatch_map_name_valid(".."));
	EXPECT_FALSE(upatch_map_name_valid("../bad"));
	EXPECT_FALSE(upatch_map_name_valid("bad/map"));
	EXPECT_FALSE(upatch_map_name_valid("bad-hyphen"));
	EXPECT_FALSE(upatch_map_name_valid("seventeen_chars17"));

	EXPECT_EQ(upatch_maps_read("ok-upatch", "..", 0, 0, &v), -EINVAL);
	EXPECT_EQ(upatch_maps_read("../bad", "events", 0, 0, &v), -EINVAL);

	/*
	 * When member 0 lies past bytes_size and member 1 lies within (e.g.
	 * out-of-order union/struct BTF offsets), btf_format_value omits a
	 * leading comma before the first emitted member.
	 */
	btf = btf__new_empty();
	ASSERT_TRUE(btf);
	u32_id = btf__add_int(btf, "__u32", 4, 0);
	st_id = btf__add_struct(btf, "reordered", 8);
	ASSERT_TRUE(u32_id > 0 && st_id > 0);
	ASSERT_EQ(btf__add_field(btf, "tail", u32_id, 32, 0), 0);
	ASSERT_EQ(btf__add_field(btf, "head", u32_id, 0, 0), 0);

	v.btf = btf;
	cell = upatch_map_format_cell(&v, (__u32)st_id, &second,
				      sizeof(second), "struct reordered");
	ASSERT_TRUE(cell);
	EXPECT_STREQ(cell, "{ head=99 }");
	xstrfree(cell);
	btf__free(btf);
}

static const struct unit_case cases[] = {
	UNIT_CASE(ringbuf_btf_resolve_and_format),
	UNIT_CASE(ringbuf_untyped_and_short_records),
	UNIT_CASE(ringbuf_batch_bounding_and_validation),
	UNIT_CASE(shield_hits_summary_percpu_and_struct),
	UNIT_CASE(map_name_and_btf_formatting_guards),
	{}
};

UNIT_SUITE(upatch_maps, cases);
