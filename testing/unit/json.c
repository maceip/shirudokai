// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdint.h>

#include <shirudo/string.h>

#include "json.h"
#include "malloc.h"
#include "unit.h"

/* What an eventlog-shaped schema extracts from one document. */
struct doc {
	char digest[65];
	char type[64];
	__s64 schema;
	int names;
	char first_name[64];
	char name[64];
	int events;
	char last_type[32];
	char ev_type[32];
	char ev_digest[65];
};

static int name_on_elem(void *ctx)
{
	struct doc *d = ctx;

	if (!d->names++ &&
	    strscpy(d->first_name, d->name, sizeof(d->first_name)) < 0)
		return -E2BIG;
	return 0;
}

static int event_on_elem(void *ctx)
{
	struct doc *d = ctx;

	if (strscpy(d->last_type, d->ev_type, sizeof(d->last_type)) < 0)
		return -E2BIG;
	d->events++;
	return 0;
}

static int parse_len(const char *text, size_t len, struct doc *d)
{
	struct json_array event_sink = { event_on_elem, d };
	struct json_array name_sink = { name_on_elem, d };
	struct json_field name_sub[] = {
		{ "", JSON_T_STRING, d->name, sizeof(d->name),
		  0, NULL, 0 },
	};
	struct json_field event_sub[] = {
		{ "type", JSON_T_STRING, d->ev_type,
		  sizeof(d->ev_type), 0, NULL, 0 },
		{ "digest", JSON_T_STRING, d->ev_digest,
		  sizeof(d->ev_digest), 0, NULL, 0 },
	};
	struct json_field f[] = {
		{ "schema", JSON_T_INT, &d->schema, 0, 0, NULL, 0 },
		{ "type", JSON_T_STRING, d->type, sizeof(d->type),
		  0, NULL, 0 },
		{ "digest", JSON_T_STRING, d->digest,
		  sizeof(d->digest), 0, NULL, 0 },
		{ "names", JSON_T_ARRAY, &name_sink, 0, 0,
		  name_sub, ARRAY_SIZE(name_sub) },
		{ "events", JSON_T_ARRAY, &event_sink, 0, 0,
		  event_sub, ARRAY_SIZE(event_sub) },
		/* An empty schema slot must be ignored, not dereferenced. */
		{ NULL, 0, NULL, 0, 0, NULL, 0 },
	};

	memset(d, 0, sizeof(*d));
	d->schema = -1;
	return json_parse(text, len, f, ARRAY_SIZE(f));
}

static int parse(const char *text, struct doc *d)
{
	return parse_len(text, strlen(text), d);
}

static void extracts_scalars_and_skips_nested_sets(void)
{
	struct doc d;

	ASSERT_EQ(parse("{\"schema\":1,\"digest\":\"abcdef\",\"type\":\"init\","
			"\"set\":[{\"name\":\"x\"}]}", &d), 0);
	EXPECT_STREQ(d.digest, "abcdef");
	EXPECT_STREQ(d.type, "init");
	EXPECT_EQ(d.schema, 1);
}

static void skips_unknown_keys_and_objects(void)
{
	struct doc d;

	ASSERT_EQ(parse("{\"a\":{\"b\":[1,2,3]},\"digest\":\"ff\",\"c\":true}",
			&d), 0);
	EXPECT_STREQ(d.digest, "ff");
	ASSERT_EQ(parse("{\"unknown\":true,\"digest\":\"ff\"}", &d), 0);
	EXPECT_STREQ(d.digest, "ff");
}

static void discarded_key_does_not_dispatch(void)
{
	struct doc d;

	ASSERT_EQ(parse("{\"a\":{\"digest\":123,\"type\":true},"
			"\"digest\":\"ff\",\"type\":\"init\"}", &d), 0);
	EXPECT_STREQ(d.digest, "ff");
	EXPECT_STREQ(d.type, "init");
}

/*
 * A value read as a C string would end at the NUL and pass checks meant
 * for the whole value; a key would be dispatched as its prefix.
 */
static void escaped_nul_is_refused(void)
{
	struct doc d;

	EXPECT_EQ(parse("{\"digest\":\"ab\\u0000cd\"}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"digest\\u0000x\":\"ff\"}", &d), -EINVAL);
	ASSERT_EQ(parse("{\"digest\":\"ab\\u0041\"}", &d), 0);
	EXPECT_STREQ(d.digest, "abA");
}

static void malformed_documents_are_refused(void)
{
	struct doc d;

	EXPECT_EQ(parse("{\"digest\":\"abc", &d), -EINVAL);
	EXPECT_EQ(parse("{\"digest\":\"a\"}xyz", &d), -EINVAL);
	EXPECT_EQ(parse("{\"digest\":123}", &d), -EINVAL);
}

static void overlong_string_is_enospc(void)
{
	char text[256], big[201];
	struct doc d;

	memset(big, '0', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	ASSERT_TRUE(strsprintf(text, sizeof(text), "{\"digest\":\"%s\"}",
			       big) > 0);
	EXPECT_EQ(parse(text, &d), -ENOSPC);
}

static void deep_nesting_is_e2big(void)
{
	char text[256];
	size_t n = 0;
	struct doc d;

	for (int i = 0; i < 40; i++) {
		memcpy(text + n, "{\"a\":", 5);
		n += 5;
	}
	text[n++] = '1';
	memset(text + n, '}', 40);
	n += 40;
	EXPECT_EQ(parse_len(text, n, &d), -E2BIG);
}

static void garbage_fails_cleanly(void)
{
	static char buf[4096];
	__u64 x = 0x9e3779b97f4a7c15ULL;
	struct doc d;

	for (int r = 0; r < 64; r++) {
		for (size_t i = 0; i < sizeof(buf); i++) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			buf[i] = (char)x;
		}
		EXPECT_TRUE(parse_len(buf, sizeof(buf), &d) <= 0);
	}
}

static void empty_object_parses(void)
{
	struct doc d;

	EXPECT_EQ(parse("{}", &d), 0);
}

static void string_array_dispatches_each_element(void)
{
	struct doc d;

	ASSERT_EQ(parse("{\"names\":[\"alpha\",\"beta\",\"gamma\"]}", &d), 0);
	EXPECT_EQ(d.names, 3);
	EXPECT_STREQ(d.first_name, "alpha");
	ASSERT_EQ(parse("{\"names\":[]}", &d), 0);
	EXPECT_EQ(d.names, 0);
}

static void object_array_uses_element_schema(void)
{
	struct doc d;

	ASSERT_EQ(parse("{\"events\":[{\"type\":\"init\",\"digest\":\"00\"},"
			"{\"type\":\"upatch_load\",\"digest\":\"ff\"}]}", &d), 0);
	EXPECT_EQ(d.events, 2);
	EXPECT_STREQ(d.last_type, "upatch_load");
}

static void nested_array_then_trailing_scalar(void)
{
	struct doc d;

	ASSERT_EQ(parse("{\"events\":[{\"type\":\"init\",\"digest\":\"aa\","
			"\"set\":[{\"name\":\"x\"}]}],\"digest\":\"top\"}", &d), 0);
	EXPECT_STREQ(d.digest, "top");
	EXPECT_EQ(d.events, 1);
	EXPECT_STREQ(d.last_type, "init");
}

struct nested {
	struct json_field *meta, *tag_field;
	int meta_seen[4], tag_seen[4];
	char id[8], tag[8];
	int n;
};

static int nested_on_elem(void *ctx)
{
	struct nested *x = ctx;

	if (x->n < 4) {
		x->meta_seen[x->n] = x->meta->seen;
		x->tag_seen[x->n] = x->tag_field->seen;
	}
	x->n++;
	return 0;
}

static int parse_nested(const char *text, struct nested *x)
{
	struct json_array sink = { nested_on_elem, x };
	struct json_field meta_sub[] = {
		{ "tag", JSON_T_STRING, x->tag, sizeof(x->tag), 0, NULL, 0 },
	};
	struct json_field item_sub[] = {
		{ "id", JSON_T_STRING, x->id, sizeof(x->id), 0, NULL, 0 },
		{ "meta", JSON_T_OBJECT, NULL, 0, 0, meta_sub,
		  ARRAY_SIZE(meta_sub) },
	};
	struct json_field f[] = {
		{ "items", JSON_T_ARRAY, &sink, 0, 0, item_sub,
		  ARRAY_SIZE(item_sub) },
	};
	int ret;

	memset(x, 0, sizeof(*x));
	x->meta = &item_sub[1];
	x->tag_field = &meta_sub[0];
	ret = json_parse(text, strlen(text), f, ARRAY_SIZE(f));
	x->meta = NULL;
	x->tag_field = NULL;
	return ret;
}

/*
 * A field an element or a document leaves out is not given, however
 * deep in the schema it sits and whatever the one before gave.
 */
static void seen_flags_are_the_elements_own(void)
{
	static const char second[] = "{}";
	static const char first[] = "{\"o\":{\"k\":\"v\"}}";
	char k[8];
	struct json_field sub[] = {
		{ "k", JSON_T_STRING, k, sizeof(k), 0, NULL, 0 },
	};
	struct json_field top[] = {
		{ "o", JSON_T_OBJECT, NULL, 0, 0, sub, ARRAY_SIZE(sub) },
	};
	struct nested x;

	ASSERT_EQ(parse_nested("{\"items\":[{\"id\":\"a\",\"meta\":"
			       "{\"tag\":\"x\"}},{\"id\":\"b\"}]}", &x), 0);
	ASSERT_EQ(x.n, 2);
	EXPECT_EQ(x.meta_seen[0], 1);
	EXPECT_EQ(x.tag_seen[0], 1);
	EXPECT_EQ(x.meta_seen[1], 0);
	EXPECT_EQ(x.tag_seen[1], 0);

	ASSERT_EQ(json_parse(first, strlen(first), top, ARRAY_SIZE(top)), 0);
	EXPECT_EQ(sub[0].seen, 1);
	ASSERT_EQ(json_parse(second, strlen(second), top, ARRAY_SIZE(top)), 0);
	EXPECT_EQ(top[0].seen, 0);
	EXPECT_EQ(sub[0].seen, 0);
}

static void declared_key_takes_one_value(void)
{
	static const char nested[] = "{\"o\":{\"k\":\"v\"},\"o\":{}}";
	char k[8];
	struct json_field sub[] = {
		{ "k", JSON_T_STRING, k, sizeof(k), 0, NULL, 0 },
	};
	struct json_field top[] = {
		{ "o", JSON_T_OBJECT, NULL, 0, 0, sub, ARRAY_SIZE(sub) },
	};
	struct doc d;

	EXPECT_EQ(parse("{\"type\":\"a\",\"type\":\"b\"}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"type\":\"a\",\"type\":null}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"schema\":1,\"schema\":1}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"names\":[\"a\"],\"names\":[\"b\"]}", &d),
		  -EINVAL);
	EXPECT_EQ(parse("{\"events\":[{\"type\":\"a\",\"type\":\"b\"}]}", &d),
		  -EINVAL);
	EXPECT_EQ(json_parse(nested, strlen(nested), top, ARRAY_SIZE(top)),
		  -EINVAL);

	EXPECT_EQ(parse("{\"type\":null,\"type\":\"b\"}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"type\":null,\"type\":null}", &d), -EINVAL);
	ASSERT_EQ(parse("{\"x\":1,\"x\":{},\"type\":\"t\"}", &d), 0);
	EXPECT_STREQ(d.type, "t");
	ASSERT_EQ(parse("{\"events\":[{\"type\":\"a\"},{\"type\":\"b\"}]}",
			&d), 0);
	EXPECT_EQ(d.events, 2);
}

static int count_int_elem(void *ctx)
{
	int *count = ctx;

	(*count)++;
	return 0;
}

static void malformed_arrays_are_refused(void)
{
	__s64 val = 0;
	int count = 0;
	struct json_array int_sink = { count_int_elem, &count };
	struct json_field int_elem[] = {
		{ "", JSON_T_INT, &val, 0, 0, NULL, 0 },
	};
	struct json_field int_arr[] = {
		{ "nums", JSON_T_ARRAY, &int_sink, 0, 0, int_elem,
		  ARRAY_SIZE(int_elem) },
	};
	static const char nums_null[] = "{\"nums\":[1,null]}";
	struct doc d;

	EXPECT_EQ(parse("{\"names\":[123]}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"names\":[null]}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"names\":[\"a\",null]}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"names\":[\"a\",\"b\"", &d), -EINVAL);
	EXPECT_EQ(parse("{\"names\":[{\"\":\"a\"}]}", &d), -EINVAL);
	EXPECT_EQ(json_parse(nums_null, strlen(nums_null), int_arr,
			     ARRAY_SIZE(int_arr)), -EINVAL);
	EXPECT_EQ(count, 1);
}

/*
 * An element that is not an object would land in the first field of
 * the element schema, a type in place of a whole record.
 */
static void object_array_takes_objects_only(void)
{
	struct doc d;

	EXPECT_EQ(parse("{\"events\":[\"init\"]}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"events\":[1]}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"events\":[null]}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"events\":[{\"type\":\"a\"},true]}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"events\":[[]]}", &d), -EINVAL);
	ASSERT_EQ(parse("{\"events\":[{},{\"type\":\"a\"}]}", &d), 0);
	EXPECT_EQ(d.events, 2);
}

static void integer_takes_json_integers_only(void)
{
	static const char *const bad[] = {
		"1.9", "1e9", "1E9", "7-3", "1+1", "-", ".", "01", "-01", "1.",
		".5", "1e", "--1", "0x1", "+1",
	};
	char text[64];
	struct doc d;

	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		ASSERT_TRUE(strsprintf(text, sizeof(text), "{\"schema\":%s}",
				       bad[i]) > 0);
		EXPECT_EQ(parse(text, &d), -EINVAL);
	}
}

static void integer_holds_any_s64_and_no_more(void)
{
	struct doc d;

	ASSERT_EQ(parse("{\"schema\":-9223372036854775808}", &d), 0);
	EXPECT_EQ(d.schema, INT64_MIN);
	ASSERT_EQ(parse("{\"schema\":9223372036854775807}", &d), 0);
	EXPECT_EQ(d.schema, INT64_MAX);
	ASSERT_EQ(parse("{\"schema\":-0}", &d), 0);
	EXPECT_EQ(d.schema, 0);
	EXPECT_EQ(parse("{\"schema\":9223372036854775808}", &d), -EINVAL);
	EXPECT_EQ(parse("{\"schema\":-9223372036854775809}", &d), -EINVAL);
}

static void discarded_number_follows_the_grammar(void)
{
	static const char *const bad[] = { "1.", "01", "1e+", "-.5", "1.e5" };
	char text[64];
	struct doc d;

	ASSERT_EQ(parse("{\"x\":[1.5e+10,-0.0E-1,2e5,0],\"schema\":2}", &d), 0);
	EXPECT_EQ(d.schema, 2);
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		ASSERT_TRUE(strsprintf(text, sizeof(text),
				       "{\"x\":%s,\"schema\":2}", bad[i]) > 0);
		EXPECT_EQ(parse(text, &d), -EINVAL);
	}
}

/*
 * Whatever the parser takes, the emitter writes back: a value it would
 * refuse to write must not be read in the first place.
 */
static void malformed_utf8_is_refused(void)
{
	static const char *const bad[] = {
		"\xc0\xaf", "\xc0\x80", "\xe0\x80\xaf", "\xed\xa0\x80",
		"\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff", "\x80",
		"a\xc3", "\xe2\x82z",
	};
	char text[64];
	struct doc d;
	size_t i;

	ASSERT_EQ(parse("{\"type\":\"caf\xc3\xa9 \xf0\x9f\x90\x9d\"}", &d), 0);
	EXPECT_STREQ(d.type, "caf\xc3\xa9 \xf0\x9f\x90\x9d");
	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		ASSERT_TRUE(strsprintf(text, sizeof(text),
				       "{\"type\":\"%s\"}", bad[i]) > 0);
		EXPECT_EQ(parse(text, &d), -EINVAL);
		ASSERT_TRUE(strsprintf(text, sizeof(text),
				       "{\"x\":\"%s\",\"type\":\"t\"}",
				       bad[i]) > 0);
		EXPECT_EQ(parse(text, &d), -EINVAL);
		ASSERT_TRUE(strsprintf(text, sizeof(text),
				       "{\"%s\":1,\"type\":\"t\"}", bad[i]) > 0);
		EXPECT_EQ(parse(text, &d), -EINVAL);
	}
	EXPECT_EQ(parse("{\"type\":\"\xe2\x82", &d), -EINVAL);
}

static int emit_string(const char *val, char *buf, size_t cap)
{
	struct json_emit e = { .buf = buf, .cap = cap };

	json_obj_open(&e);
	json_kv_string(&e, "v", val);
	json_obj_close(&e);
	return e.err;
}

static void emitter_takes_well_formed_utf8_only(void)
{
	static const char *const bad[] = {
		"\xc0\xaf", "\xc0\x80", "\xe0\x80\xaf", "\xed\xa0\x80",
		"\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff", "a\xc3",
		"\xe2\x82z",
	};
	char buf[64];
	size_t i;

	ASSERT_EQ(emit_string("caf\xc3\xa9 \xf0\x9f\x90\x9d", buf,
			      sizeof(buf)), 0);
	EXPECT_STREQ(buf, "{\"v\":\"caf\xc3\xa9 \xf0\x9f\x90\x9d\"}");
	for (i = 0; i < ARRAY_SIZE(bad); i++)
		EXPECT_EQ(emit_string(bad[i], buf, sizeof(buf)), -EILSEQ);
}

static void emitter_takes_a_string_of_its_length(void)
{
	struct json_emit e;
	char buf[64];

	e = (struct json_emit){ .buf = buf, .cap = sizeof(buf) };
	json_obj_open(&e);
	json_kv_string_n(&e, "v", "a\"bc", 3);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
	EXPECT_STREQ(buf, "{\"v\":\"a\\\"b\"}");

	e = (struct json_emit){ .buf = buf, .cap = sizeof(buf) };
	json_obj_open(&e);
	json_kv_string_n(&e, "v", "a\0b", 3);
	EXPECT_EQ(e.err, -EILSEQ);

	e = (struct json_emit){ .buf = buf, .cap = sizeof(buf) };
	json_obj_open(&e);
	json_kv_string_n(&e, "v", "a\xc3", 2);
	EXPECT_EQ(e.err, -EILSEQ);
}

/* All 64 bits of a __u64, as a member and as an array element. */
static void emitter_writes_any_u64(void)
{
	struct json_emit e = { .max = 256 };
	struct json_emit full = {};
	char buf[16];

	json_obj_open(&e);
	json_kv_u64(&e, "max", ~0ULL);
	json_kv_u64(&e, "zero", 0);
	json_arr_open(&e, "a");
	json_u64_value(&e, 1ULL << 63);
	json_u64_value(&e, 7);
	json_arr_close(&e);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
	EXPECT_STREQ(e.buf, "{\"max\":18446744073709551615,\"zero\":0,"
		     "\"a\":[9223372036854775808,7]}");
	xfree(e.buf, e.cap);

	full.buf = buf;
	full.cap = sizeof(buf);
	json_obj_open(&full);
	json_kv_u64(&full, "v", ~0ULL);
	EXPECT_EQ(full.err, -ENOSPC);
	json_kv_u64(&full, "w", 1);
	EXPECT_EQ(full.err, -ENOSPC);
}

static void emitter_grows_up_to_its_max(void)
{
	struct json_emit deep = { .max = 1u << 20 };
	struct json_emit big = { .max = 1u << 20 };
	struct json_emit small = { .max = 64 };
	char text[6000];
	int i;

	memset(text, 'x', sizeof(text) - 1);
	text[sizeof(text) - 1] = '\0';
	json_obj_open(&big);
	json_kv_string(&big, "v", text);
	json_obj_close(&big);
	ASSERT_EQ(big.err, 0);
	EXPECT_EQ(big.len, sizeof(text) - 1 + 8);
	EXPECT_EQ(big.buf[big.len], '\0');
	xfree(big.buf, big.cap);

	json_obj_open(&small);
	json_kv_string(&small, "v", text);
	json_obj_close(&small);
	EXPECT_EQ(small.err, -E2BIG);
	xfree(small.buf, small.cap);

	for (i = 0; i < 150; i++)
		json_arr_open_value(&deep);
	for (i = 0; i < 150; i++)
		json_arr_close(&deep);
	EXPECT_EQ(deep.err, 0);
	xfree(deep.buf, deep.cap);
}

static void lossy_writes_replace_bad_bytes(void)
{
	char buf[128];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	json_obj_open(&e);
	json_key_lossy(&e, "k\xc3", 2);
	json_str_lossy(&e, "a\xff\x62\0c\xc0\xaf\xc3\xa9", 9);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
	EXPECT_STREQ(buf, "{\"k\\ufffd\":"
		     "\"a\\ufffdb\\ufffdc\\ufffd\\ufffd\xc3\xa9\"}");
}

static void lossy_member_has_a_strict_key(void)
{
	char buf[64];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	json_obj_open(&e);
	json_kv_string_lossy(&e, "release", "7.0\xff");
	json_kv_string_lossy(&e, "b", "");
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
	EXPECT_STREQ(buf, "{\"release\":\"7.0\\ufffd\",\"b\":\"\"}");

	e = (struct json_emit){ .buf = buf, .cap = sizeof(buf) };
	json_obj_open(&e);
	json_kv_string_lossy(&e, "k\xff", "v");
	json_obj_close(&e);
	EXPECT_EQ(e.err, -EILSEQ);
}

struct trace {
	char	buf[512];
	size_t	len;
};

static int trace_put(struct trace *t, const char *s)
{
	size_t n = strlen(s);

	if (t->len + n >= sizeof(t->buf))
		return -E2BIG;
	memcpy(t->buf + t->len, s, n + 1);
	t->len += n;
	return 0;
}

static int trace_open(void *ctx, bool array)
{
	return trace_put(ctx, array ? "[" : "{");
}

static int trace_close(void *ctx, bool array)
{
	return trace_put(ctx, array ? "]" : "}");
}

static int trace_key(void *ctx, const char *key)
{
	return trace_put(ctx, "k:") ?: trace_put(ctx, key) ?: trace_put(ctx, " ");
}

static int trace_string(void *ctx, const char *s)
{
	return trace_put(ctx, "s:") ?: trace_put(ctx, s) ?: trace_put(ctx, " ");
}

static int trace_number(void *ctx, const char *text, size_t len,
			bool integer)
{
	char num[64];

	if (strsprintf(num, sizeof(num), "%s:%.*s ", integer ? "i" : "d",
		       (int)len, text) < 0)
		return -E2BIG;
	return trace_put(ctx, num);
}

static int trace_literal(void *ctx, int value)
{
	return trace_put(ctx, value > 0 ? "true " : value ? "null " : "false ");
}

static const struct json_visitor tracer = {
	.open = trace_open, .close = trace_close, .key = trace_key,
	.string = trace_string, .number = trace_number,
	.literal = trace_literal,
};

static int walk(const char *text, struct trace *t)
{
	t->len = 0;
	t->buf[0] = '\0';
	return json_walk(text, strlen(text), &tracer, t);
}

/* The walk reports a document in order, held to the parser's rules. */
static void walk_reports_every_token(void)
{
	char deep[128];
	struct trace t;
	int i;

	ASSERT_EQ(walk(" {\"a\":[1,\"x\\u00e9\",true,null,{\"b\":-2.5e3}],"
		       "\"c\":{},\"d\":false} ", &t), 0);
	EXPECT_STREQ(t.buf, "{k:a [i:1 s:x\xc3\xa9 true null {k:b d:-2.5e3 }]"
		     "k:c {}k:d false }");
	ASSERT_EQ(walk("\"top\"", &t), 0);
	EXPECT_STREQ(t.buf, "s:top ");
	ASSERT_EQ(walk("-0", &t), 0);
	EXPECT_STREQ(t.buf, "i:-0 ");

	EXPECT_EQ(walk("{\"a\":1,}", &t), -EINVAL);
	EXPECT_EQ(walk("{\"a\":\"\\u0000\"}", &t), -EINVAL);
	EXPECT_EQ(walk("[\"\xff\"]", &t), -EINVAL);
	EXPECT_EQ(walk("[1] 2", &t), -EINVAL);
	EXPECT_EQ(walk("", &t), -EINVAL);
	for (i = 0; i < 40; i++)
		deep[i] = '[';
	deep[i] = '\0';
	EXPECT_EQ(walk(deep, &t), -E2BIG);
	EXPECT_EQ(json_walk("[1]", 3, NULL, NULL), -EINVAL);
}

/*
 * ECMA-404, 2nd edition: what the grammar holds is taken, what it does
 * not is refused, and the restrictions json.h lists are refused too.
 */
static void walk_follows_ecma_404(void)
{
	static const char *const conforming[] = {
		"[]", "{}", "0", "-0", "1.5e+10", "1E-2", "-0.0e0", "true",
		"null", "\"\"", "{\"\":0}", " \t\n\r[1] ",
		"[\"\\u002F\\u002f\\/\"]", "\"\\uD834\\uDD1E\"",
		"[\"\\b\\f\\n\\r\\t\\\"\\\\\"]", "[\"\x7f\"]",
		"{\"a\":[{\"b\":null}],\"c\":\"\xf0\x9d\x84\x9e\"}",
	};
	static const char *const nonconforming[] = {
		"[01]", "[1.]", "[.5]", "[+1]", "[-]", "[1e]", "[1e+]", "[NaN]",
		"[Infinity]", "[\"\x01\"]", "[\"\\x41\"]", "[\"\\u12\"]",
		"[True]", "[1,]", "{\"a\":1,}", "{a:1}", "['a']", "[\"a\" \"b\"]",
		"\v[1]", "\f[1]", "\xef\xbb\xbf[1]", "[1]x", "[\"a]", "{\"a\"}",
		"{\"a\" 1}", "[1 2]", "",
	};
	static const char *const restricted[] = {
		"\"\\u0000\"", "\"\\uD800\"", "\"\\uDC00\"",
		"\"\\uD800\\u0041\"", "[\"\xff\"]", "[\"\xed\xa0\x80\"]",
	};
	struct trace t;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(conforming); i++)
		EXPECT_EQ(walk(conforming[i], &t), 0);
	for (i = 0; i < ARRAY_SIZE(nonconforming); i++)
		EXPECT_EQ(walk(nonconforming[i], &t), -EINVAL);
	for (i = 0; i < ARRAY_SIZE(restricted); i++)
		EXPECT_EQ(walk(restricted[i], &t), -EINVAL);
}

struct members {
	char	keys[64];
	char	value[16];
	int	values, members;
	struct json_field *slot;
};

static int member_value(void *ctx)
{
	struct members *m = ctx;

	m->values++;
	return 0;
}

static int member_key(void *ctx, const char *key)
{
	struct members *m = ctx;
	char entry[32];

	if (str_contains(m->keys, key))
		return -EEXIST;
	if (strsprintf(entry, sizeof(entry), "%s=%d ", key,
		       m->slot->seen ? m->values : -1) < 0 ||
	    strlen(m->keys) + strlen(entry) >= sizeof(m->keys))
		return -E2BIG;
	memcpy(m->keys + strlen(m->keys), entry, strlen(entry) + 1);
	m->values = 0;
	m->members++;
	return 0;
}

static int parse_members(const char *text, struct members *m)
{
	struct json_array values = { member_value, m };
	struct json_map map = { member_key, m };
	struct json_field value_sub[] = {
		{ "", JSON_T_STRING, m->value, sizeof(m->value), 0, NULL, 0 },
	};
	struct json_field member_sub[] = {
		{ "", JSON_T_ARRAY, &values, 0, 0, value_sub,
		  ARRAY_SIZE(value_sub) },
	};
	struct json_field f[] = {
		{ "map", JSON_T_MAP, &map, 0, 0, member_sub,
		  ARRAY_SIZE(member_sub) },
	};
	int ret;

	memset(m, 0, sizeof(*m));
	m->slot = &member_sub[0];
	ret = json_parse(text, strlen(text), f, ARRAY_SIZE(f));
	m->slot = NULL;
	return ret ? ret : f[0].seen ? 0 : -ENOENT;
}

/* A map takes keys no schema names, each value as sub[0] takes it. */
static void map_takes_any_key(void)
{
	struct members m;

	ASSERT_EQ(parse_members("{\"map\":{\"a\":[\"x\",\"y\"],\"b\":[],"
				"\"c\":null}}", &m), 0);
	EXPECT_STREQ(m.keys, "a=2 b=0 c=-1 ");
	EXPECT_EQ(m.members, 3);
	ASSERT_EQ(parse_members("{\"map\":{}}", &m), 0);
	EXPECT_EQ(m.members, 0);
	EXPECT_EQ(parse_members("{}", &m), -ENOENT);

	EXPECT_EQ(parse_members("{\"map\":{\"a\":[],\"a\":[]}}", &m), -EEXIST);
	EXPECT_EQ(parse_members("{\"map\":{\"a\":\"x\"}}", &m), -EINVAL);
	EXPECT_EQ(parse_members("{\"map\":{\"a\":[1]}}", &m), -EINVAL);
	EXPECT_EQ(parse_members("{\"map\":[]}", &m), -EINVAL);
	EXPECT_EQ(parse_members("{\"map\":{},\"map\":{}}", &m), -EINVAL);
	EXPECT_EQ(parse_members("{\"map\":{\"a\":[]}", &m), -EINVAL);
}

static int stop_at_number(void *ctx, const char *text, size_t len,
			  bool integer)
{
	return -ECANCELED;
}

static void walk_stops_where_a_callback_says(void)
{
	static const struct json_visitor stop = { .number = stop_at_number };

	EXPECT_EQ(json_walk("[\"a\",2,3]", 9, &stop, NULL), -ECANCELED);
	EXPECT_EQ(json_walk("[\"a\"]", 5, &stop, NULL), 0);
}

static void grow_to(size_t max, int err)
{
	struct json_emit e = { .max = max };

	json_obj_open(&e);
	json_obj_close(&e);
	EXPECT_EQ(e.err, err);
	EXPECT_TRUE(e.cap <= max);
	if (!err)
		EXPECT_STREQ(e.buf, "{}");
	xfree(e.buf, e.cap);
}

/* An emitter that may grow to max bytes holds max - 1 of text and a NUL. */
static void growth_keeps_room_for_the_nul(void)
{
	struct json_emit one = { .max = 1 };

	json_obj_open(&one);
	EXPECT_EQ(one.err, -E2BIG);
	EXPECT_EQ(one.len, 0);
	xfree(one.buf, one.cap);
	grow_to(1, -E2BIG);
	grow_to(2, -E2BIG);
	grow_to(3, 0);
}

/* A string field has room for nothing without a byte for its NUL. */
static void string_field_needs_room_for_the_nul(void)
{
	char guard[2] = { 'x', 'y' };
	struct json_field f[] = {
		{ "s", JSON_T_STRING, guard + 1, 0, 0, NULL, 0 },
	};

	EXPECT_EQ(json_parse("{\"s\":\"\"}", 8, f, ARRAY_SIZE(f)), -ENOSPC);
	EXPECT_EQ(guard[1], 'y');
	f[0].dst = guard;
	f[0].dst_cap = 1;
	EXPECT_EQ(json_parse("{\"s\":\"\"}", 8, f, ARRAY_SIZE(f)), 0);
	EXPECT_EQ(guard[0], '\0');
	EXPECT_EQ(guard[1], 'y');
}

static const struct unit_case cases[] = {
	UNIT_CASE(extracts_scalars_and_skips_nested_sets),
	UNIT_CASE(skips_unknown_keys_and_objects),
	UNIT_CASE(discarded_key_does_not_dispatch),
	UNIT_CASE(escaped_nul_is_refused),
	UNIT_CASE(malformed_documents_are_refused),
	UNIT_CASE(overlong_string_is_enospc),
	UNIT_CASE(deep_nesting_is_e2big),
	UNIT_CASE(garbage_fails_cleanly),
	UNIT_CASE(empty_object_parses),
	UNIT_CASE(string_array_dispatches_each_element),
	UNIT_CASE(object_array_uses_element_schema),
	UNIT_CASE(nested_array_then_trailing_scalar),
	UNIT_CASE(seen_flags_are_the_elements_own),
	UNIT_CASE(declared_key_takes_one_value),
	UNIT_CASE(growth_keeps_room_for_the_nul),
	UNIT_CASE(string_field_needs_room_for_the_nul),
	UNIT_CASE(malformed_arrays_are_refused),
	UNIT_CASE(object_array_takes_objects_only),
	UNIT_CASE(integer_takes_json_integers_only),
	UNIT_CASE(integer_holds_any_s64_and_no_more),
	UNIT_CASE(discarded_number_follows_the_grammar),
	UNIT_CASE(malformed_utf8_is_refused),
	UNIT_CASE(emitter_takes_well_formed_utf8_only),
	UNIT_CASE(emitter_takes_a_string_of_its_length),
	UNIT_CASE(emitter_writes_any_u64),
	UNIT_CASE(emitter_grows_up_to_its_max),
	UNIT_CASE(lossy_writes_replace_bad_bytes),
	UNIT_CASE(lossy_member_has_a_strict_key),
	UNIT_CASE(walk_reports_every_token),
	UNIT_CASE(walk_follows_ecma_404),
	UNIT_CASE(map_takes_any_key),
	UNIT_CASE(walk_stops_where_a_callback_says),
	{}
};

UNIT_SUITE(json, cases);
