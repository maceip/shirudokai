// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Reader of the pinned upatch maps, generic or through the upatch's
 * serializer.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "json.h"
#include "hex.h"
#include "malloc.h"
#include "paths.h"
#include "serializer.h"
#include "upatch.h"
#include "upatch_map_types.h"
#include "upatch_maps.h"
#include "upatch_pins.h"
#include "upatch_resolve.h"
#include "bpf/lib/serializer.h"

/*
 * Per-call recursion bound for the BTF value renderer. Real-world map
 * value structs are flat; nested-struct chains beyond ~4 hops would
 * either be an attacker-crafted BTF or a layout we should not be
 * pretty-printing in a "shirudo upatch get" view.
 */
#define BTF_MAX_DEPTH		6

static void resolve_map_location(struct map_view *v)
{
	struct btf *vbtf;

	if (!v)
		return;
	vbtf = btf__load_vmlinux_btf();
	if (libbpf_get_error(vbtf))
		vbtf = NULL;
	upatch_resolve_location(vbtf, v->upatch,
				v->location, sizeof(v->location));
	btf__free(vbtf);
}

#define SERIAL_MAX_BYTES \
	(SERIAL_MAX_CHUNKS * SERIAL_CHUNK_PAYLOAD)
#define SERIAL_MAX_TOTAL_BYTES \
	((__u64)SERIAL_MAX_PAGES * SERIAL_MAX_BYTES)

bool upatch_map_is_percpu(__u32 type)
{
	return type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static __u32 map_value_stride(__u32 type, __u32 value_size)
{
	if (!upatch_map_is_percpu(type))
		return value_size;
	return (value_size + 7U) & ~7U;
}

__u32 upatch_map_value_stride(const struct map_view *v)
{
	return v->value_stride ? v->value_stride : v->value_size;
}

static bool is_array_type(__u32 type)
{
	return type == BPF_MAP_TYPE_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_ARRAY;
}

static bool is_hash_type(__u32 type)
{
	return type == BPF_MAP_TYPE_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static const char *btf_type_name(struct btf *btf, __u32 type_id)
{
	const struct btf_type *t;
	const char *name;

	if (!btf || !type_id)
		return "";
	t = btf__type_by_id(btf, type_id);
	if (!t)
		return "";
	name = btf__name_by_offset(btf, t->name_off);
	if (name && name[0])
		return name;
	/*
	 * Anonymous types: walk one indirection to pick up a useful
	 * label (e.g. unnamed PTR -> named STRUCT). Bounded loop.
	 */
	{
		__u32 id = type_id;
		int hops;

		for (hops = 0; hops < 4; hops++) {
			t = btf__type_by_id(btf, id);
			if (!t)
				break;
			name = btf__name_by_offset(btf, t->name_off);
			if (name && name[0])
				return name;
			id = t->type;
			if (!id)
				break;
		}
	}
	return "";
}

static __u32 btf_unwrap(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;
	int hops;

	for (hops = 0; hops < BTF_MAX_DEPTH; hops++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return id;
		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			continue;
		default:
			return id;
		}
	}
	return id;
}

/*
 * Short kind tag for the "struct foo" / "union bar" / "enum baz"
 * prefix; for typedefs and primitives the BTF name carries enough
 * context on its own (no prefix needed).
 */
static const char *btf_kind_prefix(__u16 kind)
{
	switch (kind) {
	case BTF_KIND_STRUCT:
		return "struct ";
	case BTF_KIND_UNION:
		return "union ";
	case BTF_KIND_ENUM:
		return "enum ";
	case BTF_KIND_ENUM64:
		return "enum ";
	default:
		return "";
	}
}

static void btf_type_signature_into(const struct btf *btf, __u32 id,
				    char *buf, size_t cap, size_t *off,
				    int depth);

static void append_str(char *buf, size_t cap, size_t *off, const char *s)
{
	size_t n;

	if (*off >= cap || !s)
		return;
	n = strlen(s);
	if (n > cap - 1 - *off)
		n = cap - 1 - *off;
	memcpy(buf + *off, s, n);
	*off += n;
	buf[*off] = '\0';
}

static void append_indent(char *buf, size_t cap, size_t *off, int depth)
{
	int i;

	for (i = 0; i < depth && *off + 2 < cap; i++) {
		buf[(*off)++] = ' ';
		buf[(*off)++] = ' ';
	}
	if (*off < cap)
		buf[*off] = '\0';
}

static void btf_type_signature_into(const struct btf *btf, __u32 id,
				    char *buf, size_t cap, size_t *off,
				    int depth)
{
	const struct btf_type *t;
	const char *name;
	int i, vlen;
	__u16 kind;

	if (depth >= BTF_MAX_DEPTH || !btf || !id || *off >= cap)
		return;
	id = btf_unwrap(btf, id);
	t = btf__type_by_id(btf, id);
	if (!t) {
		append_str(buf, cap, off, "?");
		return;
	}
	kind = BTF_INFO_KIND(t->info);
	name = btf__name_by_offset(btf, t->name_off);

	if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
		const struct btf_member *m =
			(const struct btf_member *)(t + 1);

		append_str(buf, cap, off, btf_kind_prefix(kind));
		append_str(buf, cap, off, name && name[0] ? name : "<anon>");
		append_str(buf, cap, off, " {\n");
		vlen = BTF_INFO_VLEN(t->info);
		for (i = 0; i < vlen; i++) {
			const char *mname = btf__name_by_offset(btf,
								m[i].name_off);

			if (cap - *off < 8) {
				append_str(buf, cap, off, "  ...\n");
				break;
			}
			append_indent(buf, cap, off, depth + 1);
			/*
			 * Render the field type. For nested struct fields we
			 * print the short name (struct bar / int) instead of
			 * recursing, to keep the signature single-screen.
			 */
			{
				__u32 mid = btf_unwrap(btf, m[i].type);
				const struct btf_type *mt = btf__type_by_id(btf, mid);
				const char *mtype = mt ?
						    btf__name_by_offset(btf,
									mt->name_off) :
						    NULL;
				__u16 mkind = mt ? BTF_INFO_KIND(mt->info)
						    : 0;

				append_str(buf, cap, off, btf_kind_prefix(mkind));
				append_str(buf, cap, off,
					   mtype && mtype[0] ? mtype : "?");
			}
			append_str(buf, cap, off, " ");
			append_str(buf, cap, off,
				   mname && mname[0] ? mname : "<anon>");
			append_str(buf, cap, off, ";\n");
		}
		append_indent(buf, cap, off, depth);
		append_str(buf, cap, off, "}");
		return;
	}
	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);
		const struct btf_type *et = btf__type_by_id(btf,
							    btf_unwrap(btf, a->type));
		const char *en = et ? btf__name_by_offset(btf, et->name_off)
				    : "?";
		char nbuf[32];

		append_str(buf, cap, off, en && en[0] ? en : "?");
		append_str(buf, cap, off,
			   strsprintf(nbuf, sizeof(nbuf), "[%u]", a->nelems) < 0 ?
			   "[?]" : nbuf);
		return;
	}
	if (kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64) {
		append_str(buf, cap, off, "enum ");
		append_str(buf, cap, off, name && name[0] ? name : "<anon>");
		return;
	}
	append_str(buf, cap, off, name && name[0] ? name : "?");
}

static char *btf_format_value(const struct btf *btf, __u32 type_id,
			      const void *bytes, __u32 bytes_size,
			      int depth);

static int strbuf_append_take(char **out, size_t *cap, size_t *off,
			      char *piece)
{
	size_t n;

	if (!piece)
		return -1;
	n = strlen(piece);
	if (*off + n + 1 > *cap) {
		size_t nc = *cap ? *cap * 2 : 64;
		char *p;

		while (nc < *off + n + 1)
			nc *= 2;
		p = xmalloc(nc);
		if (!p) {
			xstrfree(piece);
			return -1;
		}
		memcpy(p, *out, *off);
		xfree(*out, *cap);
		*out = p;
		*cap = nc;
	}
	memcpy(*out + *off, piece, n);
	*off += n;
	(*out)[*off] = '\0';
	xstrfree(piece);
	return 0;
}

static char *btf_format_int(const struct btf_type *t, const void *bytes,
			    __u32 bytes_size)
{
	__u32 enc_word = *(const __u32 *)(t + 1);
	__u32 bits = BTF_INT_BITS(enc_word);
	__u32 encoding = BTF_INT_ENCODING(enc_word);
	bool is_signed = (encoding & BTF_INT_SIGNED) != 0;
	__u8 bytes_used = (__u8)DIV_ROUND_UP(bits, 8);

	if (bytes_used == 0 || bytes_used > bytes_size || bytes_used > 8)
		return xasprintf("?");
	if (is_signed) {
		__u64 v = 0;
		__u8 i;

		/* Shifting into the sign bit of an __s64 is undefined. */
		for (i = 0; i < bytes_used; i++)
			v |= (__u64)((const __u8 *)bytes)[i] << (8 * i);
		if (bits < 64 && (v & ((__u64)1 << (bits - 1))))
			v |= ~(((__u64)1 << bits) - 1);
		return xasprintf("%lld", (__s64)v);
	} else {
		__u64 v = 0;
		__u8 i;

		for (i = 0; i < bytes_used; i++)
			v |= (__u64)((const __u8 *)bytes)[i] << (8 * i);
		return xasprintf("%llu", v);
	}
}

/*
 * A struct member declared with a bit width: BTF gives its offset and
 * width in bits, and the value is no whole number of bytes.
 */
static char *btf_format_bitfield(const struct btf *btf, __u32 type_id,
				 const void *bytes, __u32 bytes_size,
				 __u32 bit_off, __u32 bit_size)
{
	__u32 shift = bit_off % 8, n = DIV_ROUND_UP(shift + bit_size, 8), i;
	const __u8 *b = (const __u8 *)bytes + bit_off / 8;
	const struct btf_type *t;
	bool is_signed = false;
	__u64 v = 0;

	if (!bit_size || shift + bit_size > 64 || bit_off / 8 + n > bytes_size)
		return xasprintf("?");
	for (i = 0; i < n; i++)
		v |= (__u64)b[i] << (8 * i);
	v >>= shift;
	t = btf__type_by_id(btf, btf_unwrap(btf, type_id));
	if (bit_size < 64)
		v &= ((__u64)1 << bit_size) - 1;
	if (t && BTF_INFO_KIND(t->info) == BTF_KIND_INT)
		is_signed = BTF_INT_ENCODING(*(const __u32 *)(t + 1)) &
			    BTF_INT_SIGNED;
	else if (t && (BTF_INFO_KIND(t->info) == BTF_KIND_ENUM ||
		       BTF_INFO_KIND(t->info) == BTF_KIND_ENUM64))
		is_signed = BTF_INFO_KFLAG(t->info);
	if (is_signed && bit_size < 64 && (v & ((__u64)1 << (bit_size - 1))))
		v |= ~(((__u64)1 << bit_size) - 1);
	return is_signed ? xasprintf("%lld", (__s64)v) :
			   xasprintf("%llu", v);
}

static char *btf_format_value(const struct btf *btf, __u32 type_id,
			      const void *bytes, __u32 bytes_size,
			      int depth)
{
	const struct btf_type *t;
	__u16 kind;

	if (depth >= BTF_MAX_DEPTH || !btf || !type_id || !bytes ||
	    !bytes_size)
		return NULL;
	type_id = btf_unwrap(btf, type_id);
	t = btf__type_by_id(btf, type_id);
	if (!t)
		return NULL;
	kind = BTF_INFO_KIND(t->info);

	if (kind == BTF_KIND_INT)
		return btf_format_int(t, bytes, bytes_size);

	if (kind == BTF_KIND_PTR) {
		__u64 v = 0;

		if (bytes_size >= 8)
			memcpy(&v, bytes, 8);
		else if (bytes_size >= 4)
			memcpy(&v, bytes, 4);
		return xasprintf("0x%llx", v);
	}

	if (kind == BTF_KIND_ENUM) {
		const struct btf_enum *e = (const struct btf_enum *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		__u32 v = 0, size = t->size, i;

		/* An enum is as wide as BTF says, one byte for a packed one. */
		if (!size || size > 4 || size > bytes_size)
			return xasprintf("?");
		for (i = 0; i < size; i++)
			v |= (__u32)((const __u8 *)bytes)[i] << (8 * i);
		if (BTF_INFO_KFLAG(t->info) && size < 4 &&
		    (v & (1u << (8 * size - 1))))
			v |= ~((1u << (8 * size)) - 1);
		for (i = 0; i < (__u32)vlen; i++) {
			if ((__u32)e[i].val == v) {
				const char *nm = btf__name_by_offset(btf,
								     e[i].name_off);
				return xasprintf("%s", nm && nm[0] ? nm : "?");
			}
		}
		return BTF_INFO_KFLAG(t->info) ?
		       xasprintf("%d", (__s32)v) :
		       xasprintf("%u", v);
	}

	if (kind == BTF_KIND_ENUM64) {
		const struct btf_enum64 *e =
			(const struct btf_enum64 *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		__u64 v = 0;
		int i;

		if (bytes_size >= 8)
			memcpy(&v, bytes, 8);
		for (i = 0; i < vlen; i++) {
			__u64 ev = ((__u64)e[i].val_hi32 << 32) |
				      e[i].val_lo32;

			if (ev == v) {
				const char *nm = btf__name_by_offset(btf,
								     e[i].name_off);
				return xasprintf("%s", nm && nm[0] ? nm : "?");
			}
		}
		return xasprintf("0x%llx", v);
	}

	if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
		const struct btf_member *m =
			(const struct btf_member *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		size_t cap = 64, off = 0;
		char *out = xmalloc(cap);
		bool emitted = false;
		int i;

		if (!out)
			return NULL;
		out[0] = '\0';
		if (strbuf_append_take(&out, &cap, &off,
				       xasprintf("{ ")) != 0) {
			xfree(out, cap);
			return NULL;
		}
		for (i = 0; i < vlen; i++) {
			__u32 bit_off = BTF_INFO_KFLAG(t->info) ?
					   BTF_MEMBER_BIT_OFFSET(m[i].offset) :
					   m[i].offset;
			__u32 byte_off = bit_off / 8, bit_size = 0;
			const struct btf_type *ft;
			__u32 fsize = 0, end;
			const char *fname;
			char *fval;

			if (byte_off >= bytes_size)
				continue;
			if (BTF_INFO_KFLAG(t->info))
				bit_size = BTF_MEMBER_BITFIELD_SIZE(m[i].offset);
			ft = btf__type_by_id(btf, btf_unwrap(btf, m[i].type));
			fname = btf__name_by_offset(btf, m[i].name_off);
			if (ft) {
				__s64 sz = btf__resolve_size(btf, m[i].type);

				if (sz > 0 && (__u64)sz <= bytes_size)
					fsize = (__u32)sz;
			}
			if (!fsize || check_add_overflow(byte_off, fsize, &end) ||
			    end > bytes_size)
				fsize = bytes_size - byte_off;
			if (bit_size)
				fval = btf_format_bitfield(btf, m[i].type,
							   bytes, bytes_size,
							   bit_off, bit_size);
			else
				fval = btf_format_value(btf, m[i].type,
							(const char *)bytes +
							byte_off, fsize,
							depth + 1);
			if (!fval)
				fval = xasprintf("?");
			strbuf_append_take(&out, &cap, &off,
					   xasprintf("%s%s=%s",
						     emitted ? ", " : "",
						     fname && fname[0] ?
						     fname : "?",
						     fval ? fval : "?"));
			emitted = true;
			xstrfree(fval);
		}
		strbuf_append_take(&out, &cap, &off, xasprintf(" }"));
		return out;
	}

	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);
		__s64 esz = btf__resolve_size(btf, a->type);
		size_t cap = 64, off = 0, total;
		__u32 i, n = a->nelems;
		char *out;

		if (esz <= 0 || check_mul_overflow(esz, n, &total) ||
		    total > bytes_size)
			return NULL;
		out = xmalloc(cap);
		if (!out)
			return NULL;
		out[0] = '\0';
		strbuf_append_take(&out, &cap, &off, xasprintf("[ "));
		for (i = 0; i < n && i < 16; i++) {
			char *ev = btf_format_value(btf, a->type,
						    (const char *)bytes + i * (size_t)esz,
						    (__u32)esz, depth + 1);

			strbuf_append_take(&out, &cap, &off,
					   xasprintf("%s%s",
						     i ? ", " : "",
						     ev ? ev : "?"));
			xstrfree(ev);
		}
		if (n > 16)
			strbuf_append_take(&out, &cap, &off,
					   xasprintf(", ... (%u more)",
						     n - 16));
		strbuf_append_take(&out, &cap, &off, xasprintf(" ]"));
		return out;
	}

	return NULL;
}

/*
 * A lookup of a per-CPU value copies one for every possible CPU, a
 * figure the kernel keeps to itself: sysconf counts the present ones,
 * and the sysfs file libbpf would read is root's to replace in a mount
 * namespace of its own, so either undersizes the buffer the kernel
 * fills. The shortest mask sched_getaffinity accepts is the kernel's
 * own cpumask, nr_cpu_ids bits rounded up, and bounds what a lookup
 * writes.
 */
int upatch_nproc_possible(void)
{
	static int cached;
	__u8 mask[1024];
	size_t len;

	if (cached)
		return cached;
	for (len = 8; len <= sizeof(mask); len *= 2) {
		long n = syscall(__NR_sched_getaffinity, 0, len, mask);

		if (n > 0) {
			cached = (int)(n * 8);
			return cached;
		}
		if (errno != EINVAL)
			return -errno;
	}
	return -E2BIG;
}

bool upatch_map_name_valid(const char *name)
{
	size_t i;

	if (!name || !name[0])
		return false;
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return false;
	for (i = 0; name[i]; i++) {
		char c = name[i];
		bool ok = (c >= 'A' && c <= 'Z') ||
			  (c >= 'a' && c <= 'z') ||
			  (c >= '0' && c <= '9') ||
			  c == '_' || c == '.';

		if (!ok || i >= MAP_NAME_MAX)
			return false;
	}
	return true;
}

static char *format_value(const void *value, __u32 value_size,
			  const char *btf_type)
{
	if (btf_type && btf_type[0]) {
		if (value_size == 8 &&
		    (strcmp(btf_type, "__u64") == 0 ||
		     strcmp(btf_type, "u64") == 0 ||
		     strcmp(btf_type, "long long unsigned int") == 0)) {
			__u64 v;

			memcpy(&v, value, 8);
			return xasprintf("%llu", v);
		}
		if (value_size == 8 &&
		    (strcmp(btf_type, "__s64") == 0 ||
		     strcmp(btf_type, "s64") == 0 ||
		     strcmp(btf_type, "long long int") == 0)) {
			__s64 v;

			memcpy(&v, value, 8);
			return xasprintf("%lld", v);
		}
		if (value_size == 4 &&
		    (strcmp(btf_type, "__u32") == 0 ||
		     strcmp(btf_type, "u32") == 0 ||
		     strcmp(btf_type, "unsigned int") == 0)) {
			__u32 v;

			memcpy(&v, value, 4);
			return xasprintf("%u", v);
		}
		if (value_size == 4 &&
		    (strcmp(btf_type, "__s32") == 0 ||
		     strcmp(btf_type, "s32") == 0 ||
		     strcmp(btf_type, "int") == 0)) {
			__s32 v;

			memcpy(&v, value, 4);
			return xasprintf("%d", v);
		}
	}
	if (value_size == 8) {
		__u64 v;

		memcpy(&v, value, 8);
		return xasprintf("%llu", v);
	}
	if (value_size == 4) {
		__u32 v;

		memcpy(&v, value, 4);
		return xasprintf("%u", v);
	}
	/* Hex fallback (cap at 32 bytes shown for readability). */
	{
		const __u8 *p = value;
		__u32 cap = min(value_size, 32U);
		size_t buf_sz = (size_t)cap * 2 + 8;
		char *out = xmalloc(buf_sz);
		size_t off = 0;

		if (!out)
			return NULL;
		out[off++] = '0';
		out[off++] = 'x';
		hex_encode(p, cap, out + off);
		off += (size_t)cap * 2;
		if (value_size > cap) {
			memcpy(out + off, "...", 3);
			off += 3;
		}
		out[off] = '\0';
		return out;
	}
}

char *upatch_map_format_percpu_sum(const struct map_view *v,
				   const void *values_per_cpu,
				   const char *btf_type)
{
	if (v->value_size == 1 || v->value_size == 2 ||
	    v->value_size == 4 || v->value_size == 8) {
		__u32 bits = 8 * v->value_size, i;
		const struct btf_type *t = NULL;
		bool is_signed = false;
		__u64 sum = 0;

		if (v->btf && v->value_type_id) {
			__u32 id = btf_unwrap(v->btf, v->value_type_id);

			t = btf__type_by_id(v->btf, id);
		}
		if (t && BTF_INFO_KIND(t->info) == BTF_KIND_INT) {
			__u32 enc = *(const __u32 *)(t + 1);

			is_signed = BTF_INT_ENCODING(enc) & BTF_INT_SIGNED;
		}
		for (i = 0; i < v->n_cpus; i++) {
			__u64 one = 0;

			memcpy(&one, (const char *)values_per_cpu +
			       (size_t)i * upatch_map_value_stride(v),
			       v->value_size);
			/* A negative per-CPU count must not add as 2^n - 1. */
			if (is_signed && bits < 64 &&
			    (one & ((__u64)1 << (bits - 1))))
				one |= ~(((__u64)1 << bits) - 1);
			sum += one;
		}
		return is_signed ? xasprintf("%lld", (__s64)sum) :
				   xasprintf("%llu", sum);
	}
	return xstrdup("(unsupported width)");
}

static int open_map_pin(const char *upatch, const char *map_name,
			int *fd_out, struct bpf_map_info *info_out)
{
	char path[PATH_MAX];
	__u32 info_len = sizeof(*info_out);
	int fd, ret;

	if (!upatch_name_valid(upatch) || !upatch_map_name_valid(map_name))
		return -EINVAL;
	if (upatch_pin_path(path, sizeof(path), upatch, "maps", map_name, NULL))
		return -ENAMETOOLONG;
	/* libbpf returns the error it failed with. */
	fd = bpf_obj_get(path);
	if (fd < 0)
		return fd;
	memset(info_out, 0, sizeof(*info_out));
	ret = bpf_map_get_info_by_fd(fd, info_out, &info_len);
	if (ret) {
		close(fd);
		return ret;
	}
	*fd_out = fd;
	return 0;
}

static struct btf *try_load_btf(__u32 btf_id)
{
	if (!btf_id)
		return NULL;
	return btf__load_from_kernel_by_id(btf_id);
}

static int open_serializer_pin(const char *upatch, const char *map_name)
{
	char path[PATH_MAX];
	int fd;

	if (!upatch_name_valid(upatch) || !upatch_map_name_valid(map_name))
		return -EINVAL;
	if (upatch_pin_path(path, sizeof(path), upatch, "serializers",
			    map_name, NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;
	return fd;
}

int prog_test_run(int prog_fd, void *ctx, __u32 ctx_sz,
		  __u32 *retval)
{
	union bpf_attr attr = {};
	long ret;

	attr.test.prog_fd = prog_fd;
	attr.test.ctx_in = ptr_to_u64(ctx);
	attr.test.ctx_size_in = ctx_sz;
	ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	if (ret < 0)
		return -errno;
	*retval = attr.test.retval;
	return 0;
}

static int validate_serial_map(const struct bpf_map_info *info)
{
	if (info->type != BPF_MAP_TYPE_ARRAY)
		return -EINVAL;
	if (info->key_size != sizeof(__u32))
		return -EINVAL;
	if (info->value_size != sizeof(struct serial_chunk))
		return -EINVAL;
	if (info->max_entries == 0 ||
	    info->max_entries > SERIAL_MAX_CHUNKS)
		return -E2BIG;
	return 0;
}

static int clear_serial_map(int fd, const struct bpf_map_info *info)
{
	void *zero;
	__u32 i;

	zero = xcalloc(1, info->value_size);
	if (!zero)
		return -ENOMEM;
	for (i = 0; i < info->max_entries; i++) {
		if (bpf_map_update_elem(fd, &i, zero, BPF_ANY) != 0) {
			int e = -errno;

			xfree(zero, info->value_size);
			return e;
		}
	}
	xfree(zero, info->value_size);
	return 0;
}

static int append_serial_page(struct map_view *out,
			      struct serial_page *page)
{
	void *p;

	p = xreallocarray(out->serial_pages, out->n_serial_pages,
			  out->n_serial_pages + 1, sizeof(*out->serial_pages));
	if (!p)
		return -ENOMEM;
	out->serial_pages = p;
	out->serial_pages[out->n_serial_pages++] = *page;
	memset(page, 0, sizeof(*page));
	return 0;
}

static int read_serial_page(int serial_fd,
			    const struct bpf_map_info *serial_info,
			    __u32 want_page_index, __u64 want_cursor,
			    __u64 invocation_id,
			    struct serial_page *page)
{
	struct serial_chunk *chunk;
	__u32 key, total_chunks, bytes_total, copied = 0;
	__u32 page_index, flags;
	__u64 cursor, next_cursor;
	__u8 *data = NULL;
	int ret;

	chunk = xmalloc(sizeof(*chunk));
	if (!chunk)
		return -ENOMEM;
	key = 0;
	if (bpf_map_lookup_elem(serial_fd, &key, chunk) != 0) {
		ret = -errno;
		goto out_chunk;
	}
	if (chunk->magic != SERIAL_MAGIC ||
	    chunk->version != SERIAL_VERSION ||
	    chunk->invocation_id != invocation_id) {
		ret = -EBADMSG;
		goto out_chunk;
	}
	if (chunk->status != 0) {
		ret = chunk->status < 0 ? chunk->status : -EIO;
		goto out_chunk;
	}
	total_chunks = chunk->total_chunks;
	bytes_total = chunk->bytes_total;
	page_index = chunk->page_index;
	cursor = chunk->cursor;
	next_cursor = chunk->next_cursor;
	flags = chunk->flags;
	if (total_chunks == 0 || total_chunks > serial_info->max_entries ||
	    total_chunks > SERIAL_MAX_CHUNKS ||
	    bytes_total > SERIAL_MAX_BYTES ||
	    bytes_total > total_chunks * SERIAL_CHUNK_PAYLOAD) {
		ret = -EBADMSG;
		goto out_chunk;
	}
	if (page_index != want_page_index || cursor != want_cursor ||
	    next_cursor < cursor) {
		ret = -EBADMSG;
		goto out_chunk;
	}
	data = bytes_total ? xmalloc(bytes_total) : NULL;
	if (bytes_total && !data) {
		ret = -ENOMEM;
		goto out_chunk;
	}
	for (key = 0; key < total_chunks; key++) {
		if (key != 0 &&
		    bpf_map_lookup_elem(serial_fd, &key, chunk) != 0) {
			ret = -errno;
			goto out_data;
		}
		ret = serial_chunk_validate(chunk, key, total_chunks,
					    page_index, cursor,
					    next_cursor, invocation_id);
		if (ret)
			goto out_data;
		if (chunk->status != 0) {
			ret = chunk->status < 0 ? chunk->status : -EIO;
			goto out_data;
		}
		if (chunk->bytes_total != bytes_total ||
		    copied + chunk->bytes_in_chunk > bytes_total) {
			ret = -EBADMSG;
			goto out_data;
		}
		if (chunk->bytes_in_chunk)
			memcpy(data + copied, chunk->data,
			       chunk->bytes_in_chunk);
		copied += chunk->bytes_in_chunk;
	}
	if (copied != bytes_total) {
		ret = -EBADMSG;
		goto out_data;
	}

	memset(page, 0, sizeof(*page));
	page->page_index = page_index;
	page->cursor = cursor;
	page->next_cursor = next_cursor;
	page->flags = flags;
	page->chunks = total_chunks;
	page->bytes = bytes_total;
	page->done = (page->flags & SERIAL_F_DONE) != 0;
	page->data = data;
	xfree(chunk, sizeof(*chunk));
	return 0;

out_data:
	xfree(data, bytes_total);
out_chunk:
	xfree(chunk, sizeof(*chunk));
	return ret;
}

static int try_read_serialized(const char *upatch, const char *map,
			       __u32 flags, struct map_view *out)
{
	struct bpf_map_info serial_info = {};
	__u64 cursor = 0, bytes_total = 0, invocation_id;
	__u32 page_index;
	int prog_fd = -1, serial_fd = -1, lock_fd = -1, ret;

	if (strcmp(map, SERIAL_MAP_NAME) == 0)
		return 0;
	prog_fd = open_serializer_pin(upatch, map);
	if (prog_fd < 0) {
		if (prog_fd == -ENOENT)
			return 0;
		return prog_fd;
	}
	ret = open_map_pin(upatch, SERIAL_MAP_NAME,
			   &serial_fd, &serial_info);
	if (ret)
		goto out;
	ret = validate_serial_map(&serial_info);
	if (ret)
		goto out;
	/*
	 * Clearing, running and reading are one transaction. Key the lock by
	 * the kernel map ID so every process sharing this exact output map
	 * contends, while unrelated upatches remain independent.
	 */
	lock_fd = serializer_lock_acquire(serial_info.id);
	if (lock_fd < 0) {
		ret = lock_fd;
		lock_fd = -1;
		goto out;
	}
	ret = serializer_new_invocation_id(&invocation_id);
	if (ret)
		goto out;

	for (page_index = 0; page_index < SERIAL_MAX_PAGES;
	     page_index++) {
		struct serialize_ctx ctx = {};
		struct serial_page page = {};
		__u32 retval = 0;

		ret = clear_serial_map(serial_fd, &serial_info);
		if (ret)
			goto out;

		ctx.magic = SERIAL_MAGIC;
		ctx.version = SERIAL_VERSION;
		ctx.flags = (flags & MAP_READ_PEEK) ?
			    SERIAL_CTX_F_PEEK : 0;
		ctx.max_chunks = serial_info.max_entries;
		ctx.chunk_payload_size = SERIAL_CHUNK_PAYLOAD;
		ctx.page_index = page_index;
		ctx.cursor = cursor;
		ctx.invocation_id = invocation_id;

		ret = prog_test_run(prog_fd, &ctx, sizeof(ctx), &retval);
		if (ret)
			goto out;
		if ((__s32)retval < 0) {
			ret = (__s32)retval;
			goto out;
		}
		if (ctx.magic != SERIAL_MAGIC ||
		    ctx.version != SERIAL_VERSION ||
		    ctx.page_index != page_index ||
		    ctx.cursor != cursor ||
		    ctx.invocation_id != invocation_id) {
			ret = -EBADMSG;
			goto out;
		}

		ret = read_serial_page(serial_fd, &serial_info, page_index,
				       cursor, invocation_id, &page);
		if (ret)
			goto out;
		if (bytes_total + page.bytes > SERIAL_MAX_TOTAL_BYTES) {
			xfree(page.data, page.bytes);
			ret = -E2BIG;
			goto out;
		}
		bytes_total += page.bytes;
		ret = append_serial_page(out, &page);
		if (ret) {
			xfree(page.data, page.bytes);
			goto out;
		}

		page = out->serial_pages[out->n_serial_pages - 1];
		if (page.done)
			break;
		if (page.next_cursor == cursor) {
			ret = -EBADMSG;
			goto out;
		}
		cursor = page.next_cursor;
	}
	if (out->n_serial_pages == 0 ||
	    !out->serial_pages[out->n_serial_pages - 1].done) {
		ret = -E2BIG;
		goto out;
	}

	out->serialized = true;
	out->serial_bytes_total = bytes_total;
	close(lock_fd);
	close(serial_fd);
	close(prog_fd);
	return 1;

out:
	if (ret < 0 && out->serial_pages) {
		__u32 i;

		for (i = 0; i < out->n_serial_pages; i++)
			xfree(out->serial_pages[i].data,
			      out->serial_pages[i].bytes);
		xfree(out->serial_pages,
		      out->n_serial_pages * sizeof(*out->serial_pages));
		out->serial_pages = NULL;
		out->n_serial_pages = 0;
		out->serial_bytes_total = 0;
	}
	if (serial_fd >= 0)
		close(serial_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	close(prog_fd);
	return ret;
}

static int read_entries(int fd, struct map_view *v,
			__u32 cap)
{
	size_t value_count = upatch_map_is_percpu(v->type) ?
		v->n_cpus : 1;
	size_t value_alloc;
	__u32 i;
	int err;

	if (check_mul_overflow(upatch_map_value_stride(v), value_count,
			       &value_alloc))
		return -EOVERFLOW;

	v->entries = NULL;
	v->n_entries = 0;
	v->truncated = false;
	v->n_truncated_at = cap;

	if (is_array_type(v->type)) {
		__u32 take = v->max_entries;

		if (cap && take > cap) {
			take = cap;
			v->truncated = (v->max_entries > cap);
		}
		if (take == 0)
			return 0;
		v->entries = xcalloc(take, sizeof(*v->entries));
		v->entries_cap = take;
		if (!v->entries)
			return -ENOMEM;
		for (i = 0; i < take; i++) {
			void *key = xmalloc(v->key_size);
			void *value = xmalloc(value_alloc);

			if (!key || !value) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				return -ENOMEM;
			}
			memcpy(key, &i, min(v->key_size, sizeof(i)));
			if (v->key_size > sizeof(i))
				memset((char *)key + sizeof(i), 0,
				       v->key_size - sizeof(i));
			err = bpf_map_lookup_elem(fd, key, value);
			if (err) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				continue;	/* hole; rare for ARRAY */
			}
			v->entries[v->n_entries].key = key;
			v->entries[v->n_entries].value = value;
			v->n_entries++;
		}
		return 0;
	}
	if (is_hash_type(v->type)) {
		void *prev_key = NULL;
		void *next_key;
		v->entries_cap = 32;
		v->entries = xcalloc(v->entries_cap, sizeof(*v->entries));
		if (!v->entries)
			return -ENOMEM;
		next_key = xmalloc(v->key_size);
		if (!next_key)
			return -ENOMEM;
		while (bpf_map_get_next_key(fd, prev_key, next_key) == 0) {
			void *key = xmalloc(v->key_size);
			void *value = xmalloc(value_alloc);

			if (!key || !value) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				break;
			}
			memcpy(key, next_key, v->key_size);
			if (bpf_map_lookup_elem(fd, key, value) != 0) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				prev_key = next_key;
				continue;
			}
			if (v->n_entries == v->entries_cap) {
				void *p = xreallocarray(v->entries,
							v->entries_cap,
							v->entries_cap * 2,
							sizeof(*v->entries));
				if (!p) {
					xfree(key, v->key_size);
					xfree(value, value_alloc);
					break;
				}
				v->entries = p;
				memset((char *)v->entries +
				       v->entries_cap * sizeof(*v->entries),
				       0, v->entries_cap * sizeof(*v->entries));
				v->entries_cap *= 2;
			}
			v->entries[v->n_entries].key = key;
			v->entries[v->n_entries].value = value;
			v->n_entries++;
			if (cap && v->n_entries >= cap) {
				v->truncated = true;
				break;
			}
			prev_key = next_key;
		}
		xfree(next_key, v->key_size);
		return 0;
	}
	return -EOPNOTSUPP;
}

void map_view_free(struct map_view *v)
{
	size_t value_alloc;
	__u32 i;

	if (!v)
		return;
	if (v->entries) {
		value_alloc = (size_t)upatch_map_value_stride(v) *
			      (upatch_map_is_percpu(v->type) ?
			       v->n_cpus : 1);
		for (i = 0; i < v->n_entries; i++) {
			xfree(v->entries[i].key, v->key_size);
			xfree(v->entries[i].value, value_alloc);
		}
		xfree(v->entries, v->entries_cap * sizeof(*v->entries));
		v->entries = NULL;
		v->entries_cap = 0;
		v->n_entries = 0;
	}
	if (v->btf) {
		btf__free(v->btf);
		v->btf = NULL;
	}
	if (v->serial_pages) {
		for (i = 0; i < v->n_serial_pages; i++)
			xfree(v->serial_pages[i].data,
			      v->serial_pages[i].bytes);
		xfree(v->serial_pages,
		      v->n_serial_pages * sizeof(*v->serial_pages));
		v->serial_pages = NULL;
		v->n_serial_pages = 0;
		v->serial_bytes_total = 0;
	}
}

int upatch_maps_read(const char *upatch, const char *map,
		     __u32 max_entries_cap, __u32 flags,
		     struct map_view *out)
{
	struct bpf_map_info info = {};
	char upatch_dir[PATH_MAX];
	struct stat upatch_st;
	int fd = -1;
	int ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!upatch_name_valid(upatch) || !upatch_map_name_valid(map))
		return -EINVAL;
	if (strscpy(out->upatch, upatch, sizeof(out->upatch)) < 0 ||
	    strscpy(out->name, map, sizeof(out->name)) < 0)
		return -ENAMETOOLONG;

	ret = open_map_pin(upatch, map, &fd, &info);
	if (ret)
		return ret;
	out->type = info.type;
	out->type_name = map_type_name(info.type);
	out->key_size = info.key_size;
	out->value_size = info.value_size;
	out->value_stride = map_value_stride(info.type, info.value_size);
	out->max_entries = info.max_entries;
	out->n_cpus = 1;
	if (upatch_map_is_percpu(info.type)) {
		int n = upatch_nproc_possible();

		if (n < 0) {
			close(fd);
			return n;
		}
		out->n_cpus = (__u32)n;
	}
	resolve_map_location(out);
	if (!upatch_pin_path(upatch_dir, sizeof(upatch_dir), upatch, NULL) &&
	    stat(upatch_dir, &upatch_st) == 0)
		out->lifetime_start_ns =
			(__u64)upatch_st.st_ctim.tv_sec * 1000000000ULL +
			(__u64)upatch_st.st_ctim.tv_nsec;
	out->has_payload = !upatch_pin_payload(upatch, out->payload);

	ret = try_read_serialized(upatch, map, flags, out);
	if (ret < 0) {
		close(fd);
		return ret;
	}
	if (ret > 0) {
		close(fd);
		return 0;
	}

	if (map_skip_reason(info.type)) {
		out->skipped = true;
		out->skipped_reason = map_skip_reason(info.type);
		close(fd);
		return 0;
	}

	out->btf = try_load_btf(info.btf_id);
	if (out->btf) {
		size_t off;

		out->key_type_id = info.btf_key_type_id;
		out->value_type_id = info.btf_value_type_id;
		if (strscpy(out->btf_key_type,
			    btf_type_name(out->btf, info.btf_key_type_id),
			    sizeof(out->btf_key_type)) < 0)
			strscpy_literal(out->btf_key_type, "?");
		if (strscpy(out->btf_value_type,
			    btf_type_name(out->btf, info.btf_value_type_id),
			    sizeof(out->btf_value_type)) < 0)
			strscpy_literal(out->btf_value_type, "?");
		off = 0;
		out->key_type_def[0] = '\0';
		btf_type_signature_into(out->btf, info.btf_key_type_id,
					out->key_type_def,
					sizeof(out->key_type_def), &off, 0);
		off = 0;
		out->value_type_def[0] = '\0';
		btf_type_signature_into(out->btf, info.btf_value_type_id,
					out->value_type_def,
					sizeof(out->value_type_def), &off, 0);
	}

	ret = read_entries(fd, out, max_entries_cap);

	close(fd);
	return ret;
}

static void summary_append(struct map_summary **list, size_t *n,
			   size_t *cap, const struct map_summary *one)
{
	if (*n == *cap) {
		size_t nc = *cap ? *cap * 2 : 8;
		void *p = xreallocarray(*list, *cap, nc, sizeof(**list));

		if (!p)
			return;
		*list = p;
		*cap = nc;
	}
	(*list)[(*n)++] = *one;
}

static void scan_upatch_maps(const char *upatch,
			     struct map_summary **list, size_t *n,
			     size_t *cap)
{
	char dir[PATH_MAX];
	struct dirent *e;
	DIR *d;

	if (upatch_pin_path(dir, sizeof(dir), upatch, "maps", NULL))
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((e = readdir(d))) {
		struct bpf_map_info info = {};
		struct map_summary one = {};
		int fd, ret;

		if (e->d_name[0] == '.')
			continue;
		if (strcmp(e->d_name, SERIAL_MAP_NAME) == 0)
			continue;
		ret = open_map_pin(upatch, e->d_name, &fd, &info);
		if (ret)
			continue;
		close(fd);
		if (strscpy(one.upatch, upatch, sizeof(one.upatch)) < 0 ||
		    strscpy(one.name, e->d_name, sizeof(one.name)) < 0)
			continue;
		one.type = info.type;
		one.type_name = map_type_name(info.type);
		one.max_entries = info.max_entries;
		one.n_cpus = 1;
		if (upatch_map_is_percpu(info.type)) {
			int cpus = upatch_nproc_possible();

			if (cpus < 0)
				continue;
			one.n_cpus = (__u32)cpus;
		}
		summary_append(list, n, cap, &one);
	}
	closedir(d);
}

int upatch_maps_list_one(const char *upatch,
			 struct map_summary **out,
			 size_t *n_out)
{
	struct map_summary *list = NULL;
	size_t n = 0, cap = 0;

	scan_upatch_maps(upatch, &list, &n, &cap);
	*out = list;
	*n_out = n;
	return 0;
}

int upatch_maps_list_all(struct map_summary **out,
			 size_t *n_out)
{
	struct map_summary *list = NULL;
	size_t n = 0, cap = 0;
	struct dirent *e;
	DIR *d;

	d = opendir(BPFFS_UPATCHES_DIR);
	if (!d) {
		*out = NULL;
		*n_out = 0;
		return 0;
	}
	while ((e = readdir(d))) {
		char raw_name[UPATCH_NAME_MAX + 1];

		if (e->d_name[0] == '.')
			continue;
		if (upatch_name_from_bpffs(raw_name, sizeof(raw_name),
					   e->d_name))
			continue;
		scan_upatch_maps(raw_name, &list, &n, &cap);
	}
	closedir(d);
	*out = list;
	*n_out = n;
	return 0;
}

void map_summary_free(struct map_summary *list, size_t n)
{
	xfree(list, n * sizeof(*list));
}

void upatch_maps_print_summary(const struct map_summary *list,
			       size_t n)
{
	size_t i;

	printf("Pinned maps (%zu):\n", n);
	if (n == 0) {
		printf("  none\n");
		return;
	}
	printf("  %-22s %-16s %-18s %s\n", "UPATCH", "MAP", "TYPE",
	       "ENTRIES");
	for (i = 0; i < n; i++) {
		const struct map_summary *m = &list[i];

		printf("  %-22s %-16s %-18s max=%u%s\n",
		       m->upatch, m->name, m->type_name, m->max_entries,
		       m->n_cpus > 1 ? "  (per-cpu)" : "");
	}
}

char *upatch_map_format_cell(const struct map_view *v,
			     __u32 type_id, const void *bytes,
			     __u32 bytes_size,
			     const char *btf_name)
{
	char *s = NULL;

	if (v->btf && type_id)
		s = btf_format_value(v->btf, type_id, bytes, bytes_size, 0);
	if (!s)
		s = format_value(bytes, bytes_size, btf_name);
	return s;
}

static void print_type_def(const char *label, const char *def, __u32 size)
{
	const char *p = def;

	printf("%-22s ", label);
	while (*p) {
		const char *nl = strchr(p, '\n');

		if (nl) {
			printf("%.*s\n%-22s ", (int)(nl - p), p, "");
			p = nl + 1;
		} else {
			printf("%s", p);
			break;
		}
	}
	printf(" (%u B)\n", size);
}

static void print_serialized_hex(const __u8 *data, __u32 len)
{
	__u32 i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("  %08x: ", i);
		printf("%02x", data[i]);
		if (i % 16 == 15 || i + 1 == len)
			printf("\n");
		else if (i % 2 == 1)
			printf(" ");
	}
}

void upatch_maps_print_detail(const struct map_view *v)
{
	__u32 i;

	printf("%-22s %s\n", "Name:", v->upatch);
	printf("%-22s %s\n", "Map:", v->name);
	if (upatch_map_is_percpu(v->type))
		printf("%-22s %s (%u CPUs)\n", "Type:",
		       v->type_name, v->n_cpus);
	else
		printf("%-22s %s\n", "Type:", v->type_name);
	printf("%-22s %u\n", "Max entries:", v->max_entries);
	if (v->skipped) {
		printf("%-22s skipped: %s\n", "Status:",
		       v->skipped_reason ? v->skipped_reason : "(no reason)");
		return;
	}
	if (v->serialized) {
		__u32 p;

		printf("%-22s serialized\n", "Status:");
		printf("%-22s %u\n", "Serialized pages:", v->n_serial_pages);
		printf("%-22s %llu\n", "Serialized bytes:",
		       v->serial_bytes_total);
		for (p = 0; p < v->n_serial_pages; p++) {
			const struct serial_page *page =
				&v->serial_pages[p];

			printf("\nPage %u:\n", page->page_index);
			printf("  %-22s %llu\n", "Cursor:",
			       page->cursor);
			printf("  %-22s %llu\n", "Next cursor:",
			       page->next_cursor);
			printf("  %-22s %s\n", "Done:",
			       page->done ? "true" : "false");
			printf("  %-22s 0x%x\n", "Flags:", page->flags);
			printf("  %-22s %u\n", "Chunks:", page->chunks);
			printf("  %-22s %u\n", "Bytes:", page->bytes);
			if (page->bytes) {
				printf("\n  Data (hex):\n");
				print_serialized_hex(page->data, page->bytes);
			}
		}
		return;
	}
	printf("%-22s %u of %u%s\n", "Entries:", v->n_entries,
	       v->max_entries,
	       v->truncated ? "  (truncated; use --show-full)" : "");
	if (v->key_type_def[0])
		print_type_def("Key type:", v->key_type_def, v->key_size);
	else if (v->btf_key_type[0])
		printf("%-22s %s (%u B)\n", "Key type:",
		       v->btf_key_type, v->key_size);
	else
		printf("%-22s %u B  (no BTF)\n", "Key size:", v->key_size);
	if (v->value_type_def[0])
		print_type_def("Value type:", v->value_type_def, v->value_size);
	else if (v->btf_value_type[0])
		printf("%-22s %s (%u B per CPU)\n", "Value type:",
		       v->btf_value_type, v->value_size);
	else
		printf("%-22s %u B  (no BTF)\n", "Value size:", v->value_size);

	if (v->n_entries == 0)
		return;
	printf("\nContents:\n");
	for (i = 0; i < v->n_entries; i++) {
		const struct map_entry *en = &v->entries[i];
		char *key_s;

		key_s = upatch_map_format_cell(v, v->key_type_id,
					       en->key, v->key_size,
					       v->btf_key_type);
		if (upatch_map_is_percpu(v->type)) {
			char *sum_s;
			int j;

			sum_s = upatch_map_format_percpu_sum(v, en->value,
							     v->btf_value_type);
			printf("  key=%s: sum=%s\n", key_s ? key_s : "?",
			       sum_s ? sum_s : "?");
			for (j = 0; j < (int)v->n_cpus; j++) {
				const char *p = (const char *)en->value +
						(size_t)j * upatch_map_value_stride(v);
				char *one;

				one = upatch_map_format_cell(v, v->value_type_id,
							     p, v->value_size,
							     v->btf_value_type);
				if (j % 4 == 0)
					printf("    ");
				printf("cpu%d=%-7s  ", j, one ? one : "?");
				if ((j + 1) % 4 == 0)
					printf("\n");
				xstrfree(one);
			}
			if (v->n_cpus % 4 != 0)
				printf("\n");
			xstrfree(sum_s);
		} else {
			char *val_s;

			val_s = upatch_map_format_cell(v, v->value_type_id,
						       en->value, v->value_size,
						       v->btf_value_type);
			printf("  key = %s\n     -> %s\n", key_s ? key_s : "?",
			       val_s ? val_s : "?");
			xstrfree(val_s);
		}
		xstrfree(key_s);
	}
}

void upatch_maps_emit_json_fields(struct json_emit *e,
				  const struct map_view *v)
{
	__u32 i, j;

	if (!v)
		return;
	json_kv_string(e, "name", v->name);
	json_kv_string(e, "type", v->type_name);
	json_kv_int(e, "max_entries", v->max_entries);
	json_kv_int(e, "n_entries", v->n_entries);
	if (upatch_map_is_percpu(v->type))
		json_kv_int(e, "n_cpus", v->n_cpus);
	if (v->serialized) {
		__u32 p;

		json_kv_bool(e, "serialized", true);
		json_kv_int(e, "serialized_pages",
			    v->n_serial_pages);
		json_kv_int(e, "serialized_bytes",
			    v->serial_bytes_total);
		json_arr_open(e, "pages");
		for (p = 0; p < v->n_serial_pages; p++) {
			const struct serial_page *page =
				&v->serial_pages[p];
			char *hex = hex_alloc(page->data,
					      page->bytes);

			json_obj_open(e);
			json_kv_int(e, "page_index",
				    page->page_index);
			json_kv_int(e, "cursor", page->cursor);
			json_kv_int(e, "next_cursor",
				    page->next_cursor);
			json_kv_bool(e, "done", page->done);
			json_kv_int(e, "flags", page->flags);
			json_kv_int(e, "chunks", page->chunks);
			json_kv_int(e, "bytes", page->bytes);
			json_kv_string(e, "data_hex",
				       hex ? hex : "");
			xfree(hex, size_add(size_mul(page->bytes, 2), 1));
			json_obj_close(e);
		}
		json_arr_close(e);
		return;
	}
	json_kv_bool(e, "serialized", false);
	if (v->skipped) {
		json_kv_string(e, "skipped",
			       v->skipped_reason ?
			       v->skipped_reason : "");
		return;
	}
	json_kv_bool(e, "truncated", v->truncated);
	if (v->truncated)
		json_kv_int(e, "n_truncated_at", v->n_truncated_at);
	if (v->btf_key_type[0] || v->btf_value_type[0]) {
		json_obj_open_key(e, "btf");
		json_kv_string(e, "key_type",
			       v->btf_key_type[0] ? v->btf_key_type
							  : "");
		json_kv_string(e, "value_type",
			       v->btf_value_type[0] ?
			       v->btf_value_type : "");
		if (v->key_type_def[0])
			json_kv_string(e, "key_type_def",
				       v->key_type_def);
		if (v->value_type_def[0])
			json_kv_string(e, "value_type_def",
				       v->value_type_def);
		json_obj_close(e);
	}
	json_arr_open(e, "entries");
	for (i = 0; i < v->n_entries; i++) {
		const struct map_entry *en = &v->entries[i];
		char *key_s;

		key_s = upatch_map_format_cell(v, v->key_type_id,
					       en->key, v->key_size,
					       v->btf_key_type);
		json_obj_open(e);
		json_kv_string(e, "key", key_s ? key_s : "");
		if (upatch_map_is_percpu(v->type)) {
			char *sum_s;

			sum_s = upatch_map_format_percpu_sum(v, en->value,
							     v->btf_value_type);
			json_arr_open(e, "values_per_cpu");
			for (j = 0; j < v->n_cpus; j++) {
				const char *p = (const char *)en->value +
						(size_t)j * upatch_map_value_stride(v);
				char *one;

				one = upatch_map_format_cell(v, v->value_type_id,
							     p, v->value_size,
							     v->btf_value_type);
				json_str(e, one ? one : "");
				xstrfree(one);
			}
			json_arr_close(e);
			json_kv_string(e, "sum",
				       sum_s ? sum_s : "");
			xstrfree(sum_s);
		} else {
			char *val_s;

			val_s = upatch_map_format_cell(v, v->value_type_id,
						       en->value, v->value_size,
						       v->btf_value_type);
			json_kv_string(e, "value",
				       val_s ? val_s : "");
			xstrfree(val_s);
		}
		json_obj_close(e);
		xstrfree(key_s);
	}
	json_arr_close(e);
}

void upatch_maps_emit_json_object(struct json_emit *e,
				  const struct map_view *v)
{
	if (!v)
		return;
	json_obj_open(e);
	upatch_maps_emit_json_fields(e, v);
	json_obj_close(e);
}

static bool btf_is_char_elem(const struct btf *btf, __u32 type_id)
{
	const struct btf_type *t;
	const char *name;
	__u32 enc;

	type_id = btf_unwrap(btf, type_id);
	t = btf__type_by_id(btf, type_id);
	if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_INT || t->size != 1)
		return false;
	enc = *(const __u32 *)(t + 1);
	if (BTF_INT_BITS(enc) != 8)
		return false;
	if (BTF_INT_ENCODING(enc) & BTF_INT_CHAR)
		return true;
	name = btf__name_by_offset(btf, t->name_off);
	return name && strcmp(name, "char") == 0;
}

static void btf_emit_json_int(struct json_emit *e, const struct btf_type *t,
			      const void *bytes, __u32 bytes_size)
{
	__u32 enc_word = *(const __u32 *)(t + 1);
	__u32 bits = BTF_INT_BITS(enc_word);
	__u32 encoding = BTF_INT_ENCODING(enc_word);
	bool is_signed = (encoding & BTF_INT_SIGNED) != 0;
	__u8 bytes_used = (__u8)DIV_ROUND_UP(bits, 8);
	__u64 v = 0;
	__u8 i;

	if (bytes_used == 0 || bytes_used > bytes_size || bytes_used > 8) {
		json_raw_value(e, "null", 4);
		return;
	}
	for (i = 0; i < bytes_used; i++)
		v |= (__u64)((const __u8 *)bytes)[i] << (8 * i);
	if (encoding & BTF_INT_BOOL) {
		json_raw_value(e, v ? "true" : "false", v ? 4 : 5);
		return;
	}
	if (is_signed) {
		char sbuf[32];
		int n;

		if (bits < 64 && (v & ((__u64)1 << (bits - 1))))
			v |= ~(((__u64)1 << bits) - 1);
		n = strsprintf(sbuf, sizeof(sbuf), "%lld", (__s64)v);
		if (n < 0)
			json_raw_value(e, "0", 1);
		else
			json_raw_value(e, sbuf, (size_t)n);
		return;
	}
	json_u64_value(e, v);
}

static void btf_emit_json_bitfield(struct json_emit *e, const struct btf *btf,
				   __u32 type_id, const void *bytes,
				   __u32 bytes_size, __u32 bit_off,
				   __u32 bit_size)
{
	__u32 shift = bit_off % 8, n = DIV_ROUND_UP(shift + bit_size, 8), i;
	const __u8 *b = (const __u8 *)bytes + bit_off / 8;
	const struct btf_type *t;
	bool is_signed = false;
	__u64 v = 0;

	if (!bit_size || shift + bit_size > 64 || bit_off / 8 + n > bytes_size) {
		json_raw_value(e, "null", 4);
		return;
	}
	for (i = 0; i < n; i++)
		v |= (__u64)b[i] << (8 * i);
	v >>= shift;
	if (bit_size < 64)
		v &= ((__u64)1 << bit_size) - 1;
	t = btf__type_by_id(btf, btf_unwrap(btf, type_id));
	if (t && BTF_INFO_KIND(t->info) == BTF_KIND_INT)
		is_signed = BTF_INT_ENCODING(*(const __u32 *)(t + 1)) &
			    BTF_INT_SIGNED;
	else if (t && (BTF_INFO_KIND(t->info) == BTF_KIND_ENUM ||
		       BTF_INFO_KIND(t->info) == BTF_KIND_ENUM64))
		is_signed = BTF_INFO_KFLAG(t->info);
	if (is_signed) {
		char sbuf[32];
		int len;

		if (bit_size < 64 && (v & ((__u64)1 << (bit_size - 1))))
			v |= ~(((__u64)1 << bit_size) - 1);
		len = strsprintf(sbuf, sizeof(sbuf), "%lld", (__s64)v);
		if (len < 0)
			json_raw_value(e, "0", 1);
		else
			json_raw_value(e, sbuf, (size_t)len);
		return;
	}
	json_u64_value(e, v);
}

static void btf_emit_json_value(struct json_emit *e, const struct btf *btf,
				__u32 type_id, const void *bytes,
				__u32 bytes_size, int depth)
{
	const struct btf_type *t;
	__u16 kind;

	if (depth >= BTF_MAX_DEPTH || !btf || !type_id || !bytes || !bytes_size) {
		json_raw_value(e, "null", 4);
		return;
	}
	type_id = btf_unwrap(btf, type_id);
	t = btf__type_by_id(btf, type_id);
	if (!t) {
		json_raw_value(e, "null", 4);
		return;
	}
	kind = BTF_INFO_KIND(t->info);

	if (kind == BTF_KIND_INT) {
		btf_emit_json_int(e, t, bytes, bytes_size);
		return;
	}
	if (kind == BTF_KIND_PTR) {
		char pbuf[24];
		__u64 v = 0;

		if (bytes_size >= 8)
			memcpy(&v, bytes, 8);
		else if (bytes_size >= 4)
			memcpy(&v, bytes, 4);
		if (strsprintf(pbuf, sizeof(pbuf), "0x%llx", v) < 0)
			json_str_value(e, "0x0");
		else
			json_str_value(e, pbuf);
		return;
	}
	if (kind == BTF_KIND_ENUM) {
		const struct btf_enum *en = (const struct btf_enum *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		__u32 v = 0, size = t->size, i;

		if (!size || size > 4 || size > bytes_size) {
			json_raw_value(e, "null", 4);
			return;
		}
		for (i = 0; i < size; i++)
			v |= (__u32)((const __u8 *)bytes)[i] << (8 * i);
		if (BTF_INFO_KFLAG(t->info) && size < 4 &&
		    (v & (1u << (8 * size - 1))))
			v |= ~((1u << (8 * size)) - 1);
		for (i = 0; i < (__u32)vlen; i++) {
			if ((__u32)en[i].val == v) {
				const char *nm = btf__name_by_offset(btf,
								     en[i].name_off);

				if (nm && nm[0]) {
					json_str_value(e, nm);
					return;
				}
			}
		}
		if (BTF_INFO_KFLAG(t->info)) {
			char sbuf[32];
			int n = strsprintf(sbuf, sizeof(sbuf), "%d", (__s32)v);

			json_raw_value(e, n < 0 ? "0" : sbuf,
				       n < 0 ? 1 : (size_t)n);
		} else {
			json_u64_value(e, v);
		}
		return;
	}
	if (kind == BTF_KIND_ENUM64) {
		const struct btf_enum64 *en = (const struct btf_enum64 *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		__u64 v = 0;
		int i;

		if (bytes_size < 8) {
			json_raw_value(e, "null", 4);
			return;
		}
		memcpy(&v, bytes, 8);
		for (i = 0; i < vlen; i++) {
			__u64 ev = ((__u64)en[i].val_hi32 << 32) | en[i].val_lo32;

			if (ev == v) {
				const char *nm = btf__name_by_offset(btf,
								     en[i].name_off);

				if (nm && nm[0]) {
					json_str_value(e, nm);
					return;
				}
			}
		}
		json_u64_value(e, v);
		return;
	}
	if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
		const struct btf_member *m = (const struct btf_member *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info), i;

		json_obj_value_open(e);
		for (i = 0; i < vlen; i++) {
			__u32 bit_off = BTF_INFO_KFLAG(t->info) ?
					BTF_MEMBER_BIT_OFFSET(m[i].offset) :
					m[i].offset;
			__u32 byte_off = bit_off / 8, bit_size = 0;
			const char *fname = btf__name_by_offset(btf, m[i].name_off);
			__u32 fsize = 0, end;
			char anon[24];
			__s64 sz;

			if (byte_off >= bytes_size)
				continue;
			if (BTF_INFO_KFLAG(t->info))
				bit_size = BTF_MEMBER_BITFIELD_SIZE(m[i].offset);
			if (!fname || !fname[0]) {
				if (strsprintf(anon, sizeof(anon), "_%d", i) < 0)
					strscpy_literal(anon, "_");
				fname = anon;
			}
			json_key(e, fname);
			if (bit_size) {
				btf_emit_json_bitfield(e, btf, m[i].type,
						       bytes, bytes_size,
						       bit_off, bit_size);
				continue;
			}
			sz = btf__resolve_size(btf, m[i].type);
			if (sz > 0 && (__u64)sz <= bytes_size)
				fsize = (__u32)sz;
			if (!fsize || check_add_overflow(byte_off, fsize, &end) ||
			    end > bytes_size)
				fsize = bytes_size - byte_off;
			btf_emit_json_value(e, btf, m[i].type,
					    (const char *)bytes + byte_off,
					    fsize, depth + 1);
		}
		json_obj_close(e);
		return;
	}
	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);
		__s64 esz = btf__resolve_size(btf, a->type);
		__u32 i, n = a->nelems;
		size_t total;

		if (esz <= 0 || check_mul_overflow((size_t)esz, n, &total) ||
		    total > bytes_size) {
			json_raw_value(e, "null", 4);
			return;
		}
		if (btf_is_char_elem(btf, a->type)) {
			const char *s = bytes;
			size_t slen = strnlen(s, n);

			json_str_lossy(e, s, slen);
			return;
		}
		json_arr_open_value(e);
		for (i = 0; i < n; i++)
			btf_emit_json_value(e, btf, a->type,
					    (const char *)bytes +
					    (size_t)i * (size_t)esz,
					    (__u32)esz, depth + 1);
		json_arr_close(e);
		return;
	}
	json_raw_value(e, "null", 4);
}

__u32 ringbuf_resolve_btf_value_type(const struct btf *btf, const char *map,
				     __u32 info_value_type_id)
{
	__u32 id, cnt;

	if (info_value_type_id)
		return info_value_type_id;
	if (!btf || !map || !map[0])
		return 0;
	cnt = btf__type_cnt(btf);
	for (id = 1; id < cnt; id++) {
		const struct btf_member *m;
		const struct btf_type *t, *st;
		const char *vname;
		int i, vlen;

		t = btf__type_by_id(btf, id);
		if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_VAR)
			continue;
		vname = btf__name_by_offset(btf, t->name_off);
		if (!vname || strcmp(vname, map) != 0)
			continue;
		st = btf__type_by_id(btf, btf_unwrap(btf, t->type));
		if (!st || BTF_INFO_KIND(st->info) != BTF_KIND_STRUCT)
			continue;
		m = (const struct btf_member *)(st + 1);
		vlen = BTF_INFO_VLEN(st->info);
		for (i = 0; i < vlen; i++) {
			const char *mname = btf__name_by_offset(btf,
								m[i].name_off);
			const struct btf_type *pt;

			if (!mname || strcmp(mname, "value") != 0)
				continue;
			pt = btf__type_by_id(btf, btf_unwrap(btf, m[i].type));
			if (pt && BTF_INFO_KIND(pt->info) == BTF_KIND_PTR)
				return pt->type;
		}
	}
	return 0;
}

static char *format_ringbuf_hex(const void *data, __u32 size)
{
	__u32 cap = min(size, 256U);
	size_t buf_sz = (size_t)cap * 2 + 8;
	char *out = xmalloc(buf_sz);
	size_t off = 0;

	if (!out)
		return NULL;
	out[off++] = '0';
	out[off++] = 'x';
	if (cap) {
		hex_encode(data, cap, out + off);
		off += (size_t)cap * 2;
	}
	if (size > cap) {
		memcpy(out + off, "...", 3);
		off += 3;
	}
	out[off] = '\0';
	return out;
}

int ringbuf_format_record(const struct ringbuf_record_spec *spec,
			  const void *data, __u32 size, bool json,
			  char **out)
{
	__s64 resolved_sz = 0;
	bool typed = false;

	if (!spec || !out || (!data && size > 0))
		return -EINVAL;
	*out = NULL;
	if (size > RINGBUF_MAX_SAMPLE_BYTES)
		return -E2BIG;
	if (spec->btf && spec->value_type_id) {
		resolved_sz = btf__resolve_size(spec->btf, spec->value_type_id);
		if (resolved_sz > 0 && (__u64)resolved_sz <= size)
			typed = true;
	}
	if (json) {
		struct json_emit e = { .max = JSON_MAX_BYTES };
		char *copy;

		json_obj_open(&e);
		json_kv_string(&e, "upatch", spec->upatch ? spec->upatch : "");
		json_kv_string(&e, "map", spec->map ? spec->map : "");
		json_kv_u64(&e, "size", size);
		if (typed) {
			const struct btf_type *vt;
			const char *tname;
			char tlabel[MAP_TYPENAME_MAX + 16];
			__u32 uid = btf_unwrap(spec->btf, spec->value_type_id);

			vt = btf__type_by_id(spec->btf, uid);
			tname = btf_type_name((struct btf *)spec->btf,
					      spec->value_type_id);
			if (vt && tname && tname[0] &&
			    strsprintf(tlabel, sizeof(tlabel), "%s%s",
				       btf_kind_prefix(BTF_INFO_KIND(vt->info)),
				       tname) >= 0)
				json_kv_string(&e, "btf_type", tlabel);
			json_key(&e, "value");
			btf_emit_json_value(&e, spec->btf, spec->value_type_id,
					    data, (__u32)resolved_sz, 0);
		} else {
			char *hex = size ? hex_alloc(data, size) : NULL;

			if (size && !hex) {
				xfree(e.buf, e.cap);
				return -ENOMEM;
			}
			json_kv_string(&e, "data_hex", hex ? hex : "");
			xfree(hex, size_add(size_mul(size, 2), 1));
		}
		json_obj_close(&e);
		if (e.err) {
			int err = e.err;

			xfree(e.buf, e.cap);
			return err;
		}
		copy = xstrdup(e.buf ? e.buf : "{}");
		xfree(e.buf, e.cap);
		if (!copy)
			return -ENOMEM;
		*out = copy;
		return 0;
	}
	{
		char *val = NULL, *line;

		if (typed)
			val = btf_format_value(spec->btf, spec->value_type_id,
					       data, (__u32)resolved_sz, 0);
		if (!val)
			val = format_ringbuf_hex(data, size);
		if (!val)
			return -ENOMEM;
		line = xasprintf("%s (%u B): %s",
				 spec->map && spec->map[0] ? spec->map : "?",
				 size, val);
		xstrfree(val);
		if (!line)
			return -ENOMEM;
		*out = line;
		return 0;
	}
}

void ringbuf_batch_free(struct ringbuf_batch *batch)
{
	size_t i;

	if (!batch)
		return;
	for (i = 0; i < batch->n_records; i++)
		xstrfree(batch->lines[i]);
	xfree(batch->lines, size_mul(batch->cap, sizeof(*batch->lines)));
	memset(batch, 0, sizeof(*batch));
}

int ringbuf_consume_record(const struct ringbuf_record_spec *spec,
			   const void *data, __u32 size,
			   struct ringbuf_batch *batch)
{
	char *line = NULL;
	int err;

	if (!spec || !batch)
		return -EINVAL;
	if (!batch->max_records || batch->n_records >= batch->max_records) {
		batch->truncated = true;
		return 0;
	}
	err = ringbuf_format_record(spec, data, size, batch->json, &line);
	if (err) {
		batch->err = err;
		return err;
	}
	if (batch->n_records == batch->cap) {
		size_t nc = batch->cap ? size_mul(batch->cap, 2) : 16;
		char **grown;

		grown = xreallocarray(batch->lines, batch->cap, nc,
				      sizeof(*batch->lines));
		if (!grown) {
			xstrfree(line);
			batch->err = -ENOMEM;
			return -ENOMEM;
		}
		batch->lines = grown;
		batch->cap = nc;
	}
	batch->lines[batch->n_records++] = line;
	return 0;
}

struct ringbuf_slot {
	char				name[MAP_NAME_MAX + 1];
	int				fd;
	struct btf			*btf;
	struct ringbuf_record_spec	spec;
	struct ringbuf_batch		*batch;
};

static int ringbuf_sample_cb(void *ctx, void *data, size_t size)
{
	struct ringbuf_slot *slot = ctx;

	if (size > RINGBUF_MAX_SAMPLE_BYTES) {
		slot->batch->err = -E2BIG;
		return -E2BIG;
	}
	return ringbuf_consume_record(&slot->spec, data, (__u32)size,
				      slot->batch);
}

static struct btf *try_load_upatch_btf(const char *upatch)
{
	struct bpf_prog_info pinfo = {};
	struct bpf_link_info linfo = {};
	struct upatch_pins pins = {};
	__u32 linfo_len = sizeof(linfo), pinfo_len = sizeof(pinfo);
	char dir[PATH_MAX], pin[PATH_MAX + 32];
	int lfd = -1, pfd = -1;
	struct btf *btf = NULL;

	if (upatch_pins_read(upatch, &pins) != 0)
		return NULL;
	if (pins.has_link) {
		if (upatch_pin_path(pin, sizeof(pin), upatch, "link", NULL))
			return NULL;
		lfd = bpf_obj_get(pin);
	} else if (pins.nr_links) {
		if (upatch_pin_path(dir, sizeof(dir), upatch, NULL) ||
		    upatch_link_pin(pin, sizeof(pin), dir, pins.first_link))
			return NULL;
		lfd = bpf_obj_get(pin);
	} else if (pins.nr_xdp_progs) {
		__u32 id = 0;

		pfd = upatch_xdp_prog_open(upatch, pins.first_xdp_prog, &id);
	} else if (pins.nr_tcx_progs) {
		__u32 id = 0;

		pfd = upatch_tcx_prog_open(upatch, pins.first_tcx_prog, &id);
	}
	if (lfd >= 0) {
		if (bpf_link_get_info_by_fd(lfd, &linfo, &linfo_len) == 0 &&
		    linfo.prog_id)
			pfd = bpf_prog_get_fd_by_id(linfo.prog_id);
		close(lfd);
	}
	if (pfd >= 0) {
		if (bpf_prog_get_info_by_fd(pfd, &pinfo, &pinfo_len) == 0)
			btf = try_load_btf(pinfo.btf_id);
		close(pfd);
	}
	return btf;
}

static int ringbuf_not_dot(const struct dirent *e)
{
	return e->d_name[0] != '.' && strcmp(e->d_name, SERIAL_MAP_NAME) != 0;
}

static void ringbuf_slots_free(struct ringbuf_slot *slots, size_t n, size_t cap)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (slots[i].fd >= 0)
			close(slots[i].fd);
		btf__free(slots[i].btf);
	}
	xfree(slots, size_mul(cap, sizeof(*slots)));
}

static int ringbuf_slot_add(struct ringbuf_slot **slots, size_t *n, size_t *cap,
			    const char *upatch, const char *map_name, int fd,
			    const struct bpf_map_info *info,
			    struct ringbuf_batch *batch)
{
	struct ringbuf_slot *s;

	if (*n == *cap) {
		size_t nc = *cap ? size_mul(*cap, 2) : 4;
		struct ringbuf_slot *grown;

		grown = xreallocarray(*slots, *cap, nc, sizeof(**slots));
		if (!grown)
			return -ENOMEM;
		*slots = grown;
		*cap = nc;
	}
	s = &(*slots)[*n];
	memset(s, 0, sizeof(*s));
	s->fd = -1;
	if (strscpy(s->name, map_name, sizeof(s->name)) < 0)
		return -ENAMETOOLONG;
	s->fd = fd;
	s->btf = try_load_btf(info->btf_id);
	if (!s->btf)
		s->btf = try_load_upatch_btf(upatch);
	s->batch = batch;
	s->spec.upatch = upatch;
	s->spec.map = s->name;
	s->spec.btf = s->btf;
	s->spec.value_type_id = ringbuf_resolve_btf_value_type(s->btf, s->name,
							       info->btf_value_type_id);
	(*n)++;
	return 0;
}

static void ringbuf_rebind_specs(struct ringbuf_slot *slots, size_t n,
				 const char *upatch, struct ringbuf_batch *batch)
{
	size_t i;

	for (i = 0; i < n; i++) {
		slots[i].batch = batch;
		slots[i].spec.upatch = upatch;
		slots[i].spec.map = slots[i].name;
		slots[i].spec.btf = slots[i].btf;
	}
}

int upatch_ringbuf_read(const char *upatch, const char *map,
			__u32 max_records, __u32 timeout_ms, bool json,
			struct ringbuf_batch *out)
{
	struct ringbuf_slot *slots = NULL;
	struct ring_buffer *rb = NULL;
	size_t n_slots = 0, cap_slots = 0, i;
	int ret = 0, consumed, epfd;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!upatch_name_valid(upatch))
		return -EINVAL;
	if (!max_records || max_records > RINGBUF_MAX_RECORDS_LIMIT ||
	    timeout_ms > RINGBUF_MAX_TIMEOUT_MS)
		return -EINVAL;
	if (map && !upatch_map_name_valid(map))
		return -EINVAL;
	out->max_records = max_records;
	out->json = json;

	if (map) {
		struct bpf_map_info info = {};
		int fd = -1;

		ret = open_map_pin(upatch, map, &fd, &info);
		if (ret)
			return ret;
		if (info.type != BPF_MAP_TYPE_RINGBUF) {
			close(fd);
			return -EINVAL;
		}
		ret = ringbuf_slot_add(&slots, &n_slots, &cap_slots, upatch,
				       map, fd, &info, out);
		if (ret) {
			close(fd);
			goto out;
		}
	} else {
		struct dirent **ents = NULL;
		char dir[PATH_MAX];
		int nd, k;

		if (upatch_pin_path(dir, sizeof(dir), upatch, "maps", NULL))
			return -ENAMETOOLONG;
		nd = scandir(dir, &ents, ringbuf_not_dot, alphasort);
		if (nd < 0)
			return -errno;
		for (k = 0; k < nd; k++) {
			struct bpf_map_info info = {};
			int fd = -1;

			if (!ret &&
			    open_map_pin(upatch, ents[k]->d_name, &fd, &info) == 0) {
				if (info.type == BPF_MAP_TYPE_RINGBUF) {
					ret = ringbuf_slot_add(&slots, &n_slots,
							       &cap_slots, upatch,
							       ents[k]->d_name,
							       fd, &info, out);
					if (ret)
						close(fd);
				} else {
					close(fd);
				}
			}
			libc_free(ents[k]);
		}
		libc_free(ents);
		if (ret)
			goto out;
		if (n_slots == 0)
			return -ENODATA;
	}

	ringbuf_rebind_specs(slots, n_slots, upatch, out);
	rb = ring_buffer__new(slots[0].fd, ringbuf_sample_cb, &slots[0], NULL);
	if (!rb) {
		ret = -errno;
		goto out;
	}
	for (i = 1; i < n_slots; i++) {
		ret = ring_buffer__add(rb, slots[i].fd, ringbuf_sample_cb,
				       &slots[i]);
		if (ret)
			goto out;
	}

	consumed = ring_buffer__consume_n(rb, max_records);
	if (consumed < 0) {
		ret = out->err ? out->err : consumed;
		goto out;
	}
	epfd = ring_buffer__epoll_fd(rb);
	if (consumed == 0 && timeout_ms > 0 && epfd >= 0) {
		struct pollfd pfd = {
			.fd	= epfd,
			.events	= POLLIN,
		};
		int pr = poll(&pfd, 1, (int)timeout_ms);

		if (pr < 0 && errno != EINTR) {
			ret = -errno;
			goto out;
		}
		if (pr > 0 && (pfd.revents & POLLIN)) {
			consumed = ring_buffer__consume_n(rb, max_records);
			if (consumed < 0) {
				ret = out->err ? out->err : consumed;
				goto out;
			}
		}
	}
	if (out->n_records == max_records && epfd >= 0) {
		struct pollfd pfd = {
			.fd	= epfd,
			.events	= POLLIN,
		};

		if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN))
			out->truncated = true;
	}

out:
	ring_buffer__free(rb);
	ringbuf_slots_free(slots, n_slots, cap_slots);
	if (ret)
		ringbuf_batch_free(out);
	return ret;
}

static bool shield_btf_uint_width(const struct btf *btf, __u32 type_id,
				  __u32 *width_out)
{
	const struct btf_type *t;
	__u32 enc;

	if (!btf || !type_id)
		return false;
	t = btf__type_by_id(btf, btf_unwrap(btf, type_id));
	if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_INT)
		return false;
	if (t->size != 1 && t->size != 2 && t->size != 4 && t->size != 8)
		return false;
	enc = *(const __u32 *)(t + 1);
	if ((BTF_INT_ENCODING(enc) & BTF_INT_SIGNED) ||
	    BTF_INT_OFFSET(enc) != 0 || BTF_INT_BITS(enc) != t->size * 8)
		return false;
	*width_out = t->size;
	return true;
}

static __u64 shield_sum_percpu_field(const struct map_view *v,
				     const void *values_per_cpu,
				     __u32 byte_off, __u32 width)
{
	__u32 stride = upatch_map_value_stride(v), cpu, b;
	__u64 sum = 0;

	for (cpu = 0; cpu < v->n_cpus; cpu++) {
		const __u8 *p = (const __u8 *)values_per_cpu +
				(size_t)cpu * stride + byte_off;
		__u64 one = 0;

		for (b = 0; b < width; b++)
			one |= (__u64)p[b] << (8 * b);
		sum += one;
	}
	return sum;
}

static int shield_summary_from_struct(const struct map_view *v,
				      const struct btf_type *st,
				      struct shield_hits_summary *out)
{
	const struct btf_member *m = (const struct btf_member *)(st + 1);
	__u32 hits_off = 0, hits_w = 0, act_off = 0, act_w = 0, i;
	int idx, vlen = BTF_INFO_VLEN(st->info);

	for (idx = 0; idx < vlen; idx++) {
		__u32 bit_off = BTF_INFO_KFLAG(st->info) ?
				BTF_MEMBER_BIT_OFFSET(m[idx].offset) :
				m[idx].offset;
		__u32 bit_sz = BTF_INFO_KFLAG(st->info) ?
			       BTF_MEMBER_BITFIELD_SIZE(m[idx].offset) : 0;
		const char *fname = btf__name_by_offset(v->btf, m[idx].name_off);
		__u32 byte_off = bit_off / 8, w = 0, end;

		if (!fname)
			continue;
		if (strcmp(fname, "hits") != 0 &&
		    strcmp(fname, "activity") != 0)
			continue;
		if (bit_sz || bit_off % 8 != 0 ||
		    !shield_btf_uint_width(v->btf, m[idx].type, &w) ||
		    check_add_overflow(byte_off, w, &end) ||
		    end > v->value_size)
			return -EOPNOTSUPP;
		if (strcmp(fname, "hits") == 0) {
			out->has_hits = true;
			hits_off = byte_off;
			hits_w = w;
		} else {
			out->has_activity = true;
			act_off = byte_off;
			act_w = w;
		}
	}
	if (!out->has_hits && !out->has_activity)
		return -EOPNOTSUPP;
	for (i = 0; i < v->n_entries; i++) {
		if (!v->entries || !v->entries[i].value)
			return -EINVAL;
		if (out->has_hits)
			out->hits += shield_sum_percpu_field(v,
							     v->entries[i].value,
							     hits_off, hits_w);
		if (out->has_activity)
			out->activity += shield_sum_percpu_field(v,
								 v->entries[i].value,
								 act_off, act_w);
	}
	return 0;
}

int upatch_shield_hits_summary(const struct map_view *v,
			       struct shield_hits_summary *out)
{
	bool is_hits, is_activity, is_stats;
	__u32 stride, i;

	if (!v || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	is_hits = strcmp(v->name, "hits") == 0;
	is_activity = strcmp(v->name, "activity") == 0;
	is_stats = strcmp(v->name, "shield_stats") == 0;
	if (!is_hits && !is_activity && !is_stats)
		return -ENOENT;
	if (v->skipped || v->serialized || v->truncated ||
	    !upatch_map_is_percpu(v->type) || !v->n_cpus)
		return -EOPNOTSUPP;
	stride = upatch_map_value_stride(v);
	if (stride < v->value_size)
		return -EINVAL;

	if (is_stats && v->btf && v->value_type_id) {
		const struct btf_type *t;

		t = btf__type_by_id(v->btf, btf_unwrap(v->btf, v->value_type_id));
		if (t && BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT)
			return shield_summary_from_struct(v, t, out);
	}

	if (v->value_size != 1 && v->value_size != 2 &&
	    v->value_size != 4 && v->value_size != 8)
		return -EOPNOTSUPP;
	if (v->btf && v->value_type_id) {
		__u32 w = 0;

		if (!shield_btf_uint_width(v->btf, v->value_type_id, &w) ||
		    w != v->value_size)
			return -EOPNOTSUPP;
	}

	if (is_hits || is_activity) {
		__u64 total = 0;

		for (i = 0; i < v->n_entries; i++) {
			if (!v->entries || !v->entries[i].value)
				return -EINVAL;
			total += shield_sum_percpu_field(v, v->entries[i].value,
							 0, v->value_size);
		}
		if (is_hits) {
			out->has_hits = true;
			out->hits = total;
		} else {
			out->has_activity = true;
			out->activity = total;
		}
		return 0;
	}

	if (!v->max_entries || v->max_entries > 2 || v->n_entries > 2)
		return -EOPNOTSUPP;
	out->has_hits = true;
	if (v->max_entries == 2)
		out->has_activity = true;
	for (i = 0; i < v->n_entries; i++) {
		__u32 slot = i;
		__u64 val;

		if (!v->entries || !v->entries[i].value)
			return -EINVAL;
		if (v->entries[i].key && v->key_size == sizeof(__u32))
			memcpy(&slot, v->entries[i].key, sizeof(slot));
		val = shield_sum_percpu_field(v, v->entries[i].value, 0,
					      v->value_size);
		if (slot == 0) {
			out->has_hits = true;
			out->hits += val;
		} else if (slot == 1) {
			out->has_activity = true;
			out->activity += val;
		} else {
			return -EOPNOTSUPP;
		}
	}
	return 0;
}
