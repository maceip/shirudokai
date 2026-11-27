// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * JSON emitter and schema parser; the parser dispatches declared keys
 * and parses and discards the rest.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "hex.h"
#include "json.h"
#include "malloc.h"

static bool grow(struct json_emit *e)
{
	size_t cap = e->cap ? size_mul(e->cap, 2) : 4096;
	char *buf;

	if (!e->max || e->cap >= e->max) {
		e->err = e->max ? -E2BIG : -ENOSPC;
		return false;
	}
	cap = min(cap, e->max);
	/* put() writes a byte and the NUL behind it. */
	if (cap <= e->len + 1) {
		e->err = -E2BIG;
		return false;
	}
	buf = xreallocarray(e->buf, e->cap, cap, 1);
	if (!buf) {
		e->err = -ENOMEM;
		return false;
	}
	e->buf = buf;
	e->cap = cap;
	return true;
}

static void put(struct json_emit *e, char c)
{
	if (e->err)
		return;
	if (e->len + 1 >= e->cap && !grow(e))
		return;
	e->buf[e->len++] = c;
	e->buf[e->len] = '\0';
}

static void put_raw(struct json_emit *e, const char *s)
{
	while (*s && !e->err)
		put(e, *s++);
}

/*
 * Malformed UTF-8 is -EILSEQ, so a stray byte can never produce
 * invalid JSON; lossy writes U+FFFD for it, and for a NUL, instead.
 */
static void put_string_n(struct json_emit *e, const char *s, size_t len,
			 bool lossy)
{
	const __u8 *p = (const __u8 *)s, *end = p + len;

	put(e, '"');
	while (p < end && !e->err) {
		__u8 c = *p;

		if (c == '"' || c == '\\') {
			put(e, '\\');
			put(e, (char)c);
			p++;
		} else if (c == '\n') {
			put_raw(e, "\\n");
			p++;
		} else if (c == '\r') {
			put_raw(e, "\\r");
			p++;
		} else if (c == '\t') {
			put_raw(e, "\\t");
			p++;
		} else if (c && c < 0x20) {
			char u[7];

			if (strsprintf(u, sizeof(u), "\\u%04x", c) < 0) {
				e->err = -E2BIG;
				break;
			}
			put_raw(e, u);
			p++;
		} else if (c && c < 0x80) {
			put(e, (char)c);
			p++;
		} else {
			size_t left = end - p;
			size_t n = c ? utf8_width((const char *)p,
						  min(left, 4U)) : 0;

			if (!n && !lossy) {
				e->err = -EILSEQ;
				return;
			}
			if (!n) {
				put_raw(e, "\\ufffd");
				p++;
			}
			while (n--)
				put(e, (char)*p++);
		}
	}
	put(e, '"');
}

static void put_string(struct json_emit *e, const char *s)
{
	put_string_n(e, s, strlen(s), false);
}

static void sep(struct json_emit *e)
{
	__u64 bit = 1ull << (e->depth % 64);
	__u32 word = e->depth / 64;

	if (e->err)
		return;
	if (e->nonempty[word] & bit)
		put(e, ',');
	else
		e->nonempty[word] |= bit;
}

static void enter(struct json_emit *e)
{
	if (e->err)
		return;
	if (e->depth + 1 >= JSON_EMIT_MAX_DEPTH) {
		e->err = -E2BIG;
		return;
	}
	e->depth++;
	e->nonempty[e->depth / 64] &= ~(1ull << (e->depth % 64));
}

static void leave(struct json_emit *e)
{
	if (e->depth)
		e->depth--;
}

static void json_value_begin(struct json_emit *e)
{
	if (e->value_pending)
		e->value_pending = false;
	else
		sep(e);
}

void json_obj_open(struct json_emit *e)
{
	sep(e);
	put(e, '{');
	enter(e);
}

void json_obj_open_key(struct json_emit *e, const char *key)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put(e, '{');
	enter(e);
}

void json_obj_value_open(struct json_emit *e)
{
	json_value_begin(e);
	put(e, '{');
	enter(e);
}

void json_obj_close(struct json_emit *e)
{
	put(e, '}');
	leave(e);
}

void json_arr_open(struct json_emit *e, const char *key)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put(e, '[');
	enter(e);
}

void json_arr_open_value(struct json_emit *e)
{
	json_value_begin(e);
	put(e, '[');
	enter(e);
}

void json_key(struct json_emit *e, const char *key)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	e->value_pending = true;
}

void json_arr_close(struct json_emit *e)
{
	put(e, ']');
	leave(e);
}

void json_kv_string(struct json_emit *e,
		    const char *key, const char *val)
{
	json_kv_string_n(e, key, val, strlen(val));
}

void json_kv_string_n(struct json_emit *e, const char *key,
		      const char *val, size_t len)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put_string_n(e, val, len, false);
}

void json_kv_int(struct json_emit *e,
		 const char *key, __s64 val)
{
	char num[24];

	if (strsprintf(num, sizeof(num), "%lld", (__s64)val) < 0) {
		e->err = -E2BIG;
		return;
	}
	sep(e);
	put_string(e, key);
	put(e, ':');
	put_raw(e, num);
}

void json_u64_value(struct json_emit *e, __u64 val)
{
	char num[24];
	int len = strsprintf(num, sizeof(num), "%llu", val);

	if (len < 0)
		e->err = -E2BIG;
	else
		json_raw_value(e, num, len);
}

void json_kv_u64(struct json_emit *e, const char *key, __u64 val)
{
	json_key(e, key);
	json_u64_value(e, val);
}

void json_kv_bool(struct json_emit *e, const char *key, int val)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put_raw(e, val ? "true" : "false");
}

void json_kv_null(struct json_emit *e, const char *key)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put_raw(e, "null");
}

void json_kv_raw(struct json_emit *e, const char *key,
		 const char *value, size_t value_len)
{
	size_t i;

	sep(e);
	put_string(e, key);
	put(e, ':');
	for (i = 0; i < value_len && !e->err; i++)
		put(e, value[i]);
}

void json_str(struct json_emit *e, const char *val)
{
	sep(e);
	put_string(e, val);
}

void json_str_value(struct json_emit *e, const char *val)
{
	json_value_begin(e);
	put_string(e, val);
}

void json_raw_value(struct json_emit *e, const char *value,
		    size_t value_len)
{
	size_t i;

	json_value_begin(e);
	for (i = 0; i < value_len && !e->err; i++)
		put(e, value[i]);
}

void json_raw(struct json_emit *e, const char *value,
	      size_t value_len)
{
	size_t i;

	sep(e);
	for (i = 0; i < value_len && !e->err; i++)
		put(e, value[i]);
}

void json_str_lossy(struct json_emit *e, const char *s, size_t n)
{
	json_value_begin(e);
	put_string_n(e, s, n, true);
}

void json_key_lossy(struct json_emit *e, const char *s, size_t n)
{
	sep(e);
	put_string_n(e, s, n, true);
	put(e, ':');
	e->value_pending = true;
}

void json_kv_string_lossy(struct json_emit *e, const char *key,
			  const char *val)
{
	json_key(e, key);
	json_str_lossy(e, val, strlen(val));
}

struct pctx {
	const char			*p;
	const char			*end;
	__u32				depth;
	struct json_field	*fields;
	size_t				n_fields;
	const struct json_visitor	*v;
	void				*v_ctx;
	char				*scratch;	/* walk: decoded text */
	size_t				scratch_cap;
};

/*
 * A walk reports what the parse discards, through the same grammar, so
 * that one parser checks every document shirudo reads.
 */
static int visit_open(struct pctx *c, bool array)
{
	return c->v && c->v->open ? c->v->open(c->v_ctx, array) : 0;
}

static int visit_close(struct pctx *c, bool array)
{
	return c->v && c->v->close ? c->v->close(c->v_ctx, array) : 0;
}

static int visit_literal(struct pctx *c, int value)
{
	return c->v && c->v->literal ? c->v->literal(c->v_ctx, value) : 0;
}

static void reset_seen(struct json_field *fields, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		fields[i].seen = 0;
		if (fields[i].type == JSON_T_OBJECT ||
		    fields[i].type == JSON_T_ARRAY ||
		    fields[i].type == JSON_T_MAP)
			reset_seen(fields[i].sub, fields[i].n_sub);
	}
}

static void skip_ws(struct pctx *c)
{
	while (c->p < c->end) {
		char ch = *c->p;

		if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
			c->p++;
		else
			break;
	}
}

static int hex4(const char *s)
{
	int v = 0, i;

	for (i = 0; i < 4; i++) {
		int n = hex_nibble(s[i]);

		if (n < 0)
			return -1;
		v = (v << 4) | n;
	}
	return v;
}

static int emit_byte(char *dst, size_t cap, size_t *len, __u8 b)
{
	size_t n = *len;

	if (n >= JSON_MAX_STRING_BYTES)
		return -E2BIG;
	if (dst) {
		if (n + 1 >= cap)	/* leave room for NUL */
			return -ENOSPC;
		dst[n] = (char)b;
	}
	*len = n + 1;
	return 0;
}

static int utf8_emit(char *dst, size_t cap, size_t *len, __u32 cp)
{
	int ret;

	if (cp < 0x80) {
		return emit_byte(dst, cap, len, cp);
	} else if (cp < 0x800) {
		ret = emit_byte(dst, cap, len, 0xC0 | (cp >> 6));
		if (!ret)
			ret = emit_byte(dst, cap, len, 0x80 | (cp & 0x3F));
		return ret;
	}
	ret = emit_byte(dst, cap, len, 0xE0 | (cp >> 12));
	if (!ret)
		ret = emit_byte(dst, cap, len, 0x80 | ((cp >> 6) & 0x3F));
	if (!ret)
		ret = emit_byte(dst, cap, len, 0x80 | (cp & 0x3F));
	return ret;
}

static int parse_string(struct pctx *c, char *dst, size_t cap)
{
	size_t len = 0;
	int ret;

	if (c->p >= c->end || *c->p != '"')
		return -EINVAL;
	c->p++;
	for (;;) {
		__u8 ch;

		if (c->p >= c->end)
			return -EINVAL;		/* unterminated */
		ch = (__u8)*c->p++;
		if (ch == '"')
			break;
		if (ch == '\\') {
			char e;

			if (c->p >= c->end)
				return -EINVAL;
			e = *c->p++;
			switch (e) {
			case '"':
				ret = emit_byte(dst, cap, &len, '"');
				break;
			case '\\':
				ret = emit_byte(dst, cap, &len, '\\');
				break;
			case '/':
				ret = emit_byte(dst, cap, &len, '/');
				break;
			case 'b':
				ret = emit_byte(dst, cap, &len, '\b');
				break;
			case 'f':
				ret = emit_byte(dst, cap, &len, '\f');
				break;
			case 'n':
				ret = emit_byte(dst, cap, &len, '\n');
				break;
			case 'r':
				ret = emit_byte(dst, cap, &len, '\r');
				break;
			case 't':
				ret = emit_byte(dst, cap, &len, '\t');
				break;
			case 'u': {
				int cp, lo;

				if (c->end - c->p < 4)
					return -EINVAL;
				cp = hex4(c->p);
				/* A NUL would end the string short of its value. */
				if (cp <= 0)
					return -EINVAL;
				c->p += 4;
				if (cp >= 0xD800 && cp <= 0xDBFF) {
					/* high surrogate: need \uDC00..DFFF */
					if (c->end - c->p < 6 ||
					    c->p[0] != '\\' || c->p[1] != 'u')
						return -EINVAL;
					lo = hex4(c->p + 2);
					if (lo < 0xDC00 || lo > 0xDFFF)
						return -EINVAL;
					c->p += 6;
					cp = 0x10000 +
					     ((cp - 0xD800) << 10) +
					     (lo - 0xDC00);
				} else if (cp >= 0xDC00 && cp <= 0xDFFF) {
					return -EINVAL;	/* lone low surrogate */
				}
				if (cp < 0x10000) {
					ret = utf8_emit(dst, cap, &len, cp);
				} else {
					ret = emit_byte(dst, cap, &len,
							0xF0 | (cp >> 18));
					if (!ret)
						ret = emit_byte(dst, cap, &len,
								0x80 | ((cp >> 12) & 0x3F));
					if (!ret)
						ret = emit_byte(dst, cap, &len,
								0x80 | ((cp >> 6) & 0x3F));
					if (!ret)
						ret = emit_byte(dst, cap, &len,
								0x80 | (cp & 0x3F));
				}
				break;
			}
			default:
				return -EINVAL;
			}
			if (ret)
				return ret;
		} else if (ch < 0x20) {
			return -EINVAL;		/* unescaped control char */
		} else {
			size_t n = utf8_width(c->p - 1,
					      (size_t)(c->end - c->p) + 1);

			if (!n)
				return -EINVAL;
			ret = emit_byte(dst, cap, &len, ch);
			while (!ret && --n)
				ret = emit_byte(dst, cap, &len, (__u8)*c->p++);
			if (ret)
				return ret;
		}
	}
	if (dst && !cap)
		return -ENOSPC;
	if (dst)
		dst[len] = '\0';
	return 0;
}

static int parse_value(struct pctx *c, struct json_field *f);

static int parse_object(struct pctx *c)
{
	char buf[256], *key = c->v ? c->scratch : buf;
	size_t key_cap = c->v ? c->scratch_cap : sizeof(buf);
	__u64 named = 0;
	int ret;

	if (++c->depth > JSON_MAX_DEPTH || c->n_fields > JSON_MAX_FIELDS)
		return -E2BIG;
	c->p++;				/* consume '{' */
	ret = visit_open(c, false);
	if (ret)
		return ret;
	skip_ws(c);
	if (c->p < c->end && *c->p == '}') {
		c->p++;
		c->depth--;
		return visit_close(c, false);
	}
	for (;;) {
		struct json_field *f = NULL;
		size_t i;

		skip_ws(c);
		ret = parse_string(c, key, key_cap);
		if (!ret && c->v && c->v->key)
			ret = c->v->key(c->v_ctx, key);
		if (ret)
			return ret;
		skip_ws(c);
		if (c->p >= c->end || *c->p != ':')
			return -EINVAL;
		c->p++;
		for (i = 0; i < c->n_fields; i++) {
			if (c->fields[i].key && strcmp(c->fields[i].key, key) == 0) {
				f = &c->fields[i];
				break;
			}
		}
		/* Readers that take the first or the last would differ. */
		if (f) {
			__u64 bit = 1ULL << (f - c->fields);

			if (named & bit)
				return -EINVAL;
			named |= bit;
		}
		ret = parse_value(c, f);
		if (ret)
			return ret;
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == ',') {
			c->p++;
			continue;
		}
		if (*c->p == '}') {
			c->p++;
			break;
		}
		return -EINVAL;
	}
	c->depth--;
	return visit_close(c, false);
}

static int parse_array(struct pctx *c)
{
	int ret;

	if (++c->depth > JSON_MAX_DEPTH)
		return -E2BIG;
	c->p++;				/* consume '[' */
	ret = visit_open(c, true);
	if (ret)
		return ret;
	skip_ws(c);
	if (c->p < c->end && *c->p == ']') {
		c->p++;
		c->depth--;
		return visit_close(c, true);
	}
	for (;;) {
		ret = parse_value(c, NULL);	/* elements never dispatched */
		if (ret)
			return ret;
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == ',') {
			c->p++;
			continue;
		}
		if (*c->p == ']') {
			c->p++;
			break;
		}
		return -EINVAL;
	}
	c->depth--;
	return visit_close(c, true);
}

static int parse_array_into(struct pctx *c, struct json_field *f)
{
	struct json_array *sink = f->dst;
	int ret;

	if (++c->depth > JSON_MAX_DEPTH)
		return -E2BIG;
	c->p++;				/* consume '[' */
	skip_ws(c);
	if (c->p < c->end && *c->p == ']') {
		c->p++;
		c->depth--;
		f->seen = 1;
		return 0;
	}
	for (;;) {
		reset_seen(f->sub, f->n_sub);
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (f->n_sub == 1 && (!f->sub[0].key || !f->sub[0].key[0])) {
			ret = parse_value(c, &f->sub[0]);
			if (ret)
				return ret;
			if (!f->sub[0].seen)
				return -EINVAL;
		} else if (*c->p == '{') {
			struct json_field *save_f = c->fields;
			size_t save_n = c->n_fields;

			c->fields = f->sub;
			c->n_fields = f->n_sub;
			ret = parse_object(c);
			c->fields = save_f;
			c->n_fields = save_n;
		} else if (!f->n_sub) {
			ret = parse_value(c, NULL);
		} else {
			return -EINVAL;	/* not an object, as sub[] asks */
		}
		if (ret)
			return ret;
		if (sink && sink->on_elem) {
			ret = sink->on_elem(sink->ctx);
			if (ret)
				return ret;
		}
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == ',') {
			c->p++;
			continue;
		}
		if (*c->p == ']') {
			c->p++;
			break;
		}
		return -EINVAL;
	}
	c->depth--;
	f->seen = 1;
	return 0;
}

static int parse_map(struct pctx *c, struct json_field *f)
{
	struct json_map *sink = f->dst;
	char key[256];
	int ret;

	if (++c->depth > JSON_MAX_DEPTH)
		return -E2BIG;
	c->p++;				/* consume '{' */
	skip_ws(c);
	if (c->p < c->end && *c->p == '}') {
		c->p++;
		c->depth--;
		f->seen = 1;
		return 0;
	}
	for (;;) {
		reset_seen(f->sub, f->n_sub);
		skip_ws(c);
		ret = parse_string(c, key, sizeof(key));
		if (ret)
			return ret;
		skip_ws(c);
		if (c->p >= c->end || *c->p != ':')
			return -EINVAL;
		c->p++;
		ret = parse_value(c, f->n_sub ? &f->sub[0] : NULL);
		if (!ret && sink && sink->on_member)
			ret = sink->on_member(sink->ctx, key);
		if (ret)
			return ret;
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == ',') {
			c->p++;
			continue;
		}
		if (*c->p == '}') {
			c->p++;
			break;
		}
		return -EINVAL;
	}
	c->depth--;
	f->seen = 1;
	return 0;
}

static int lit(struct pctx *c, const char *s)
{
	size_t n = strlen(s);

	if ((size_t)(c->end - c->p) < n || memcmp(c->p, s, n) != 0)
		return -EINVAL;
	c->p += n;
	return 0;
}

static int skip_digits(struct pctx *c)
{
	size_t n = digits(c->p, (size_t)(c->end - c->p));

	c->p += n;
	return n ? 0 : -EINVAL;
}

/*
 * A number as JSON spells one: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
 * An integer field takes the integer part alone, and only within __s64.
 */
static int parse_number(struct pctx *c, struct json_field *f)
{
	const char *start = c->p;
	const char *int_end;

	if (c->p < c->end && *c->p == '-')
		c->p++;
	if (c->p < c->end && *c->p == '0')
		c->p++;
	else if (skip_digits(c))
		return -EINVAL;
	int_end = c->p;
	if (c->p < c->end && *c->p == '.') {
		c->p++;
		if (skip_digits(c))
			return -EINVAL;
	}
	if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
		c->p++;
		if (c->p < c->end && (*c->p == '+' || *c->p == '-'))
			c->p++;
		if (skip_digits(c))
			return -EINVAL;
	}
	if (!f)
		return c->v && c->v->number ?
		       c->v->number(c->v_ctx, start, (size_t)(c->p - start),
				    c->p == int_end) : 0;
	if (f->type != JSON_T_INT || c->p != int_end)
		return -EINVAL;
	if (parse_s64(start, (size_t)(int_end - start), INT64_MIN, INT64_MAX,
		      f->dst))
		return -EINVAL;
	f->seen = 1;
	return 0;
}

static int parse_value(struct pctx *c, struct json_field *f)
{
	skip_ws(c);
	if (c->p >= c->end)
		return -EINVAL;
	switch (*c->p) {
	case '{': {
		struct json_field *save_f = c->fields;
		size_t save_n = c->n_fields;
		int ret;

		if (f) {
			if (f->type == JSON_T_MAP)
				return parse_map(c, f);
			if (f->type != JSON_T_OBJECT)
				return -EINVAL;
			c->fields = f->sub;
			c->n_fields = f->n_sub;
		} else {
			/*
			 * Discarded object: parse with an empty schema so its
			 * keys cannot collide with the enclosing schema and
			 * mis-dispatch (or type-mismatch) a value into it.
			 */
			c->fields = NULL;
			c->n_fields = 0;
		}
		ret = parse_object(c);
		c->fields = save_f;
		c->n_fields = save_n;
		if (ret)
			return ret;
		if (f)
			f->seen = 1;
		return 0;
	}
	case '[':
		if (f) {
			if (f->type != JSON_T_ARRAY)
				return -EINVAL;	/* declared scalar, got array */
			return parse_array_into(c, f);
		}
		return parse_array(c);
	case '"':
		if (f) {
			int ret;

			if (f->type != JSON_T_STRING)
				return -EINVAL;
			ret = parse_string(c, f->dst, f->dst_cap);
			if (ret)
				return ret;
			f->seen = 1;
			return 0;
		}
		if (c->v) {
			int ret = parse_string(c, c->scratch, c->scratch_cap);

			if (!ret && c->v->string)
				ret = c->v->string(c->v_ctx, c->scratch);
			return ret;
		}
		return parse_string(c, NULL, 0);
	case 't':
		if (lit(c, "true"))
			return -EINVAL;
		if (f) {
			if (f->type != JSON_T_BOOL)
				return -EINVAL;
			*(int *)f->dst = 1;
			f->seen = 1;
		}
		return f ? 0 : visit_literal(c, 1);
	case 'f':
		if (lit(c, "false"))
			return -EINVAL;
		if (f) {
			if (f->type != JSON_T_BOOL)
				return -EINVAL;
			*(int *)f->dst = 0;
			f->seen = 1;
		}
		return f ? 0 : visit_literal(c, 0);
	case 'n':
		if (lit(c, "null"))
			return -EINVAL;
		return f ? 0 : visit_literal(c, -1);	/* null never dispatched */
	default:
		return parse_number(c, f);
	}
}

int json_parse(const char *data, size_t len,
	       struct json_field *fields, size_t n_fields)
{
	struct pctx c = {
		.p = data, .end = data + len,
		.fields = fields, .n_fields = n_fields,
	};
	int ret;

	if (len > JSON_MAX_BYTES)
		return -E2BIG;
	reset_seen(fields, n_fields);

	skip_ws(&c);
	if (c.p >= c.end || *c.p != '{')
		return -EINVAL;
	ret = parse_object(&c);
	if (ret)
		return ret;
	skip_ws(&c);
	if (c.p != c.end)
		return -EINVAL;		/* trailing garbage */
	return 0;
}

int json_walk(const char *data, size_t len,
	      const struct json_visitor *v, void *ctx)
{
	struct pctx c = {
		.p = data, .end = data + len, .v = v, .v_ctx = ctx,
	};
	int ret;

	if (len > JSON_MAX_BYTES || !v)
		return len > JSON_MAX_BYTES ? -E2BIG : -EINVAL;
	/* A decoded string is never longer than its encoding. */
	c.scratch_cap = len + 1;
	c.scratch = xmalloc(c.scratch_cap);
	if (!c.scratch)
		return -ENOMEM;
	ret = parse_value(&c, NULL);
	if (!ret) {
		skip_ws(&c);
		if (c.p != c.end)
			ret = -EINVAL;
	}
	xfree(c.scratch, c.scratch_cap);
	return ret;
}
