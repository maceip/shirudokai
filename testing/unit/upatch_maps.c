// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Unit tests for util/upatch_maps.c: BTF-typed and untyped ringbuf record
 * formatting and bounded one-shot batch consumption without kernel ringbufs.
 */

#include <errno.h>
#include <linux/btf.h>
#include <string.h>

#include <bpf/btf.h>

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
	ASSERT_TRUE(strstr(json_out, "\"ports\":[22,443]"));
	xstrfree(json_out);

	ASSERT_EQ(ringbuf_format_record(&spec, &ev, sizeof(ev), false,
					&text_out), 0);
	ASSERT_TRUE(text_out);
	ASSERT_TRUE(strstr(text_out,
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

static const struct unit_case cases[] = {
	UNIT_CASE(ringbuf_btf_resolve_and_format),
	UNIT_CASE(ringbuf_untyped_and_short_records),
	UNIT_CASE(ringbuf_batch_bounding_and_validation),
	{}
};

UNIT_SUITE(upatch_maps, cases);
