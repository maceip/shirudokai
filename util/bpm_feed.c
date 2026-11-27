// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Curated signed CVE shield feed: schema parser, canonical emitter and
 * ML-DSA-87 detached CMS signature verification.
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_feed.h"
#include "bpm_package.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "keys.h"
#include "malloc.h"
#include "paths.h"
#include "upatch.h"

#define BPM_FEED_SIG_MAX	(1024u * 1024u)
#define BPM_FEED_CERT_MAX	(256u * 1024u)

static bool feed_text_ok(const char *s)
{
	for (; *s; s++)
		if ((__u8)*s < 0x20 || (__u8)*s == 0x7f)
			return false;
	return true;
}

static bool feed_texts_ok(const char (*v)[TREE_STRING_MAX], int n)
{
	for (int i = 0; i < n; i++)
		if (!v[i][0] || !feed_text_ok(v[i]))
			return false;
	return true;
}

static bool feed_kv_texts_ok(const struct tree_selector_kv *kv, int n)
{
	for (int i = 0; i < n; i++)
		if (!kv[i].key[0] || !feed_text_ok(kv[i].key) ||
		    kv[i].n_values <= 0 ||
		    !feed_texts_ok(kv[i].values, kv[i].n_values))
			return false;
	return true;
}

static bool feed_id_ok(const char *s)
{
	size_t n;

	if (!s || !s[0] || s[0] == '.' || s[0] == '-' || s[0] == '/')
		return false;
	n = strlen(s);
	if (n >= TREE_STRING_MAX || s[n - 1] == '/')
		return false;
	for (size_t i = 0; i < n; i++) {
		__u8 c = (__u8)s[i];

		if (!isalnum(c) && c != '.' && c != '_' && c != ':' &&
		    c != '-' && c != '/')
			return false;
		if (c == '/' && i + 1 < n && s[i + 1] == '/')
			return false;
	}
	return !str_contains(s, "..");
}

static bool feed_leap_year(__u64 year)
{
	return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static __s64 days_from_civil(__s64 y, unsigned m, unsigned d)
{
	__s64 era, yoe, doy, doe;

	y -= m <= 2;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = y - era * 400;
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + doe - 719468;
}

static bool feed_timestamp_parse(const char *s, __s64 *unix_sec)
{
	static const __u8 mdays[12] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	};
	__u64 year, mon, day, hour, min, sec, max_day;
	__s64 days;

	if (!s || strlen(s) != 20)
		return false;
	if (s[4] != '-' || s[7] != '-' || s[10] != 'T' ||
	    s[13] != ':' || s[16] != ':' || s[19] != 'Z')
		return false;
	if (parse_u64(s, 4, 9999, &year) ||
	    parse_u64(s + 5, 2, 12, &mon) || mon < 1 ||
	    parse_u64(s + 8, 2, 31, &day) || day < 1 ||
	    parse_u64(s + 11, 2, 23, &hour) ||
	    parse_u64(s + 14, 2, 59, &min) ||
	    parse_u64(s + 17, 2, 60, &sec))
		return false;
	max_day = mdays[mon - 1];
	if (mon == 2 && feed_leap_year(year))
		max_day = 29;
	if (day > max_day)
		return false;
	if (sec == 60)
		sec = 59;
	days = days_from_civil((__s64)year, (unsigned)mon, (unsigned)day);
	if (unix_sec)
		*unix_sec = days * 86400 + (__s64)hour * 3600 +
			    (__s64)min * 60 + (__s64)sec;
	return true;
}

static bool feed_timestamp_ok(const char *s)
{
	return feed_timestamp_parse(s, NULL);
}

bool bpm_feed_cve_ok(const char *cve)
{
	const char *rest = str_after_prefix(cve ? cve : "", "CVE-");
	size_t n;

	if (!rest || digits(rest, 4) != 4 || rest[4] != '-')
		return false;
	rest += 5;
	n = strlen(rest);
	return n >= 4 && n <= 19 && digits(rest, n) == n;
}

static bool feed_digest_ok(const char *s)
{
	__u8 raw[CRYPTO_SHA256_LEN];

	if (sha256_digest_decode(s, raw))
		return false;
	for (const char *p = s + 7; *p; p++)
		if (isupper((__u8)*p))
			return false;
	return true;
}

static bool feed_oci_ref_ok(const char *ref)
{
	const char *rest = str_after_prefix(ref ? ref : "", "oci://");
	const char *slash, *sep;
	size_t host_len, repo_len;

	if (!rest || strlen(ref) >= BPM_MAX_ENDPOINT || !feed_text_ok(ref) ||
	    str_contains(rest, "..") || str_contains(rest, "//"))
		return false;
	slash = strchr(rest, '/');
	if (!slash || slash == rest)
		return false;
	host_len = (size_t)(slash - rest);
	for (size_t i = 0; i < host_len; i++) {
		__u8 c = (__u8)rest[i];

		if (!isalnum(c) && c != '.' && c != '-' && c != ':' &&
		    c != '[' && c != ']')
			return false;
	}
	sep = strchr(slash + 1, '@');
	if (!sep)
		sep = strchr(slash + 1, ':');
	if (!sep || sep == slash + 1 || sep[-1] == '/')
		return false;
	repo_len = (size_t)(sep - (slash + 1));
	for (size_t i = 0; i < repo_len; i++) {
		__u8 c = (__u8)slash[1 + i];

		if (!isalnum(c) && c != '.' && c != '_' && c != '-' && c != '/')
			return false;
	}
	if (*sep == '@')
		return feed_digest_ok(sep + 1);
	return bpm_version_ok(sep + 1);
}

static enum bpm_feed_role feed_role_parse(const char *s)
{
	if (!strcmp(s, "mitigation"))
		return BPM_FEED_ROLE_MITIGATION;
	if (!strcmp(s, "detector"))
		return BPM_FEED_ROLE_DETECTOR;
	return BPM_FEED_ROLE_NONE;
}

const char *bpm_feed_role_str(enum bpm_feed_role role)
{
	switch (role) {
	case BPM_FEED_ROLE_MITIGATION:
		return "mitigation";
	case BPM_FEED_ROLE_DETECTOR:
		return "detector";
	default:
		return "";
	}
}

bool bpm_feed_entry_has_cve(const struct bpm_feed_entry *entry,
			    const char *cve)
{
	if (!entry || !cve)
		return false;
	for (int i = 0; i < entry->n_cves; i++)
		if (!strcmp(entry->cves[i], cve))
			return true;
	return false;
}

struct feed_kver {
	__u64	major;
	__u64	minor;
	__u64	patch;
	bool	has_patch;
};

static bool feed_kver_parse_prefix(const char *s, const char **endp,
				   struct feed_kver *v, bool allow_suffix)
{
	size_t n;

	if (!s || !isdigit((__u8)*s))
		return false;
	n = digits(s, 8);
	if (!n || parse_u64(s, n, 99999, &v->major) || s[n] != '.')
		return false;
	s += n + 1;
	n = digits(s, 8);
	if (!n || parse_u64(s, n, 99999, &v->minor))
		return false;
	s += n;
	v->patch = 0;
	v->has_patch = false;
	if (*s == '.') {
		s++;
		n = digits(s, 8);
		if (!n || parse_u64(s, n, 99999, &v->patch))
			return false;
		s += n;
		v->has_patch = true;
	}
	if (!allow_suffix && *s && *s != ',')
		return false;
	if (allow_suffix && *s && *s != '-' && *s != '+' && *s != '.')
		return false;
	if (endp)
		*endp = s;
	return true;
}

static int feed_kver_cmp(const struct feed_kver *a, const struct feed_kver *b)
{
	if (a->major != b->major)
		return a->major < b->major ? -1 : 1;
	if (a->minor != b->minor)
		return a->minor < b->minor ? -1 : 1;
	if (a->patch != b->patch)
		return a->patch < b->patch ? -1 : 1;
	return 0;
}

static bool feed_fixed_in_ok(const char *s)
{
	struct feed_kver v;
	const char *end;

	if (!s || !*s)
		return true;
	return feed_kver_parse_prefix(s, &end, &v, false) && !*end;
}

static bool feed_affected_eval(const char *expr, const struct feed_kver *rel)
{
	const char *p = expr;
	int terms = 0;

	while (*p) {
		enum { OP_EQ, OP_LT, OP_LE, OP_GT, OP_GE } op = OP_EQ;
		struct feed_kver bound;
		const char *end;
		int cmp;

		if (terms >= 2)
			return false;
		if (p[0] == '>' && p[1] == '=') {
			op = OP_GE;
			p += 2;
		} else if (p[0] == '<' && p[1] == '=') {
			op = OP_LE;
			p += 2;
		} else if (p[0] == '>') {
			op = OP_GT;
			p += 1;
		} else if (p[0] == '<') {
			op = OP_LT;
			p += 1;
		} else if (p[0] == '=') {
			op = OP_EQ;
			p += 1;
		}
		if (!feed_kver_parse_prefix(p, &end, &bound, false))
			return false;
		if (rel) {
			cmp = feed_kver_cmp(rel, &bound);
			if (op == OP_EQ && !bound.has_patch) {
				if (rel->major != bound.major ||
				    rel->minor != bound.minor)
					return false;
			} else if ((op == OP_EQ && cmp != 0) ||
				   (op == OP_LT && cmp >= 0) ||
				   (op == OP_LE && cmp > 0) ||
				   (op == OP_GT && cmp <= 0) ||
				   (op == OP_GE && cmp < 0)) {
				return false;
			}
		}
		terms++;
		if (!*end)
			return true;
		if (*end != ',' || !end[1])
			return false;
		p = end + 1;
	}
	return terms > 0;
}

static bool feed_affected_ok(const char *s)
{
	if (!s || !*s)
		return true;
	return feed_affected_eval(s, NULL);
}

bool bpm_feed_entry_matches_release(const struct bpm_feed_entry *entry,
				    const char *release)
{
	struct feed_kver rel, fixed;

	if (!entry)
		return false;
	if (!entry->affected[0] && !entry->fixed_in[0])
		return true;
	if (!release || !feed_kver_parse_prefix(release, NULL, &rel, true))
		return false;
	if (entry->fixed_in[0]) {
		if (!feed_kver_parse_prefix(entry->fixed_in, NULL, &fixed,
					    false))
			return false;
		if (feed_kver_cmp(&rel, &fixed) >= 0)
			return false;
	}
	if (entry->affected[0] && !feed_affected_eval(entry->affected, &rel))
		return false;
	return true;
}

int bpm_feed_check_freshness(const struct bpm_feed *feed, __s64 now_sec)
{
	__s64 gen_sec = 0, exp_sec = 0;

	if (!feed || !feed_timestamp_parse(feed->generated_at, &gen_sec))
		return -EINVAL;
	if (gen_sec > now_sec + BPM_FEED_CLOCK_SKEW_SEC)
		return -EINVAL;
	if (feed->expires[0]) {
		if (!feed_timestamp_parse(feed->expires, &exp_sec))
			return -EINVAL;
		if (exp_sec < gen_sec)
			return -EINVAL;
		if (now_sec > exp_sec)
			return -EKEYEXPIRED;
	}
	return 0;
}

void bpm_feed_free(struct bpm_feed *feed)
{
	if (!feed)
		return;
	for (int i = 0; i < feed->entries_capacity; i++)
		tree_selector_free(&feed->entries[i].selector);
	xfree(feed->entries,
	      (size_t)feed->entries_capacity * sizeof(*feed->entries));
	*feed = (struct bpm_feed){};
}

static int feed_entries_reserve(struct bpm_feed *feed)
{
	int old_cap = feed->entries_capacity;
	int new_cap = old_cap ? old_cap * 2 : 16;
	struct bpm_feed_entry *grown;

	if (feed->n_entries >= BPM_FEED_MAX_ENTRIES)
		return -E2BIG;
	if (feed->n_entries < old_cap)
		return 0;
	if (new_cap > BPM_FEED_MAX_ENTRIES)
		new_cap = BPM_FEED_MAX_ENTRIES;
	grown = xreallocarray(feed->entries, (size_t)old_cap, (size_t)new_cap,
			      sizeof(*grown));
	if (!grown)
		return -ENOMEM;
	feed->entries = grown;
	feed->entries_capacity = new_cap;
	return 0;
}

struct feed_reader {
	struct bpm_feed		*feed;
	struct bpm_feed_entry	entry;
	char			role_str[32];
	struct json_field	*sel_lists;
	struct json_field	*entry_fields;
	char			value[TREE_STRING_MAX];
	char			cve[BPM_FEED_CVE_MAX];
	char			pair[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int			n_pair;
};

struct feed_list {
	struct feed_reader	*r;
	char			(*values)[TREE_STRING_MAX];
	int			*n;
};

struct feed_map {
	struct feed_reader	*r;
	struct tree_selector_kv	**kvs;
	int			*n;
	int			max;
};

static int feed_list_value(void *ctx)
{
	struct feed_list *l = ctx;

	if (*l->n >= TREE_MAX_SELECTOR_VALUES ||
	    strscpy(l->values[*l->n], l->r->value, sizeof(l->values[0])) < 0)
		return -E2BIG;
	(*l->n)++;
	return 0;
}

static int feed_cve_value(void *ctx)
{
	struct feed_reader *r = ctx;
	struct bpm_feed_entry *e = &r->entry;

	if (e->n_cves >= BPM_FEED_MAX_CVES)
		return -E2BIG;
	if (!bpm_feed_cve_ok(r->cve))
		return -EINVAL;
	for (int i = 0; i < e->n_cves; i++)
		if (!strcmp(e->cves[i], r->cve))
			return -EINVAL;
	if (strscpy(e->cves[e->n_cves], r->cve, sizeof(e->cves[0])) < 0)
		return -E2BIG;
	e->n_cves++;
	return 0;
}

static int feed_map_pair(void *ctx, const char *key)
{
	struct feed_map *m = ctx;
	struct feed_reader *r = m->r;
	struct tree_selector_kv *kv;
	int ret;

	if (!r->n_pair)
		return -EINVAL;
	for (int i = 0; i < *m->n; i++)
		if (!strcmp((*m->kvs)[i].key, key))
			return -EINVAL;
	ret = tree_selector_kv_add(m->kvs, m->n, m->max, &kv);
	if (ret)
		return ret;
	if (strscpy(kv->key, key, sizeof(kv->key)) < 0)
		return -E2BIG;
	memcpy(kv->values, r->pair, sizeof(kv->values));
	kv->n_values = r->n_pair;
	r->n_pair = 0;
	return 0;
}

static bool feed_selector_text_ok(const struct tree_selector *s)
{
	return feed_texts_ok(s->kernel_release_prefix,
			     s->n_kernel_release_prefix) &&
	       feed_texts_ok(s->kernel_build_id, s->n_kernel_build_id) &&
	       feed_texts_ok(s->architecture, s->n_architecture) &&
	       feed_kv_texts_ok(s->kconfig, s->n_kconfig) &&
	       feed_kv_texts_ok(s->labels, s->n_labels);
}

static bool feed_entry_valid(const struct bpm_feed_entry *e)
{
	if (!upatch_name_valid(e->id) || e->n_cves <= 0 ||
	    e->n_cves > BPM_FEED_MAX_CVES ||
	    !bpm_package_name_ok(e->package) ||
	    !bpm_semver_valid(e->version) ||
	    !feed_oci_ref_ok(e->reference) ||
	    !feed_digest_ok(e->manifest_digest) ||
	    e->role == BPM_FEED_ROLE_NONE ||
	    !feed_selector_text_ok(&e->selector) ||
	    !feed_text_ok(e->description) ||
	    !feed_affected_ok(e->affected) ||
	    !feed_fixed_in_ok(e->fixed_in))
		return false;
	for (int i = 0; i < e->n_cves; i++) {
		if (!bpm_feed_cve_ok(e->cves[i]))
			return false;
		for (int j = i + 1; j < e->n_cves; j++)
			if (!strcmp(e->cves[i], e->cves[j]))
				return false;
	}
	return true;
}

static int feed_cves_cmp(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b);
}

static int feed_take_entry(void *ctx)
{
	struct feed_reader *r = ctx;
	struct bpm_feed_entry *e = &r->entry;
	const struct tree_selector *s = &e->selector;
	const int counts[] = {
		s->n_kernel_release_prefix,
		s->n_kernel_build_id,
		s->n_architecture,
	};
	int ret;

	/* id, cves, package, version, reference, manifest_digest, role */
	for (int i = 0; i < 7; i++)
		if (!r->entry_fields[i].seen)
			return -EINVAL;
	if ((r->entry_fields[9].seen && !e->affected[0]) ||
	    (r->entry_fields[10].seen && !e->fixed_in[0]))
		return -EINVAL;
	for (size_t i = 0; i < ARRAY_SIZE(counts); i++)
		if (r->sel_lists[i].seen && !counts[i])
			return -EINVAL;
	e->role = feed_role_parse(r->role_str);
	if (!feed_entry_valid(e))
		return -EINVAL;
	for (int i = 0; i < r->feed->n_entries; i++)
		if (!strcmp(r->feed->entries[i].id, e->id))
			return -EINVAL;
	qsort(e->cves, (size_t)e->n_cves, sizeof(e->cves[0]), feed_cves_cmp);
	ret = feed_entries_reserve(r->feed);
	if (ret)
		return ret;
	r->feed->entries[r->feed->n_entries++] = *e;
	memzero_explicit(e, sizeof(*e));
	memzero_explicit(r->role_str, sizeof(r->role_str));
	memzero_explicit(r->value, sizeof(r->value));
	memzero_explicit(r->cve, sizeof(r->cve));
	return 0;
}

int bpm_feed_parse(const char *body, size_t len, struct bpm_feed *out)
{
	struct feed_reader *r;
	__s64 schema = 0;
	int ret;

	if (!body || !out || len > JSON_MAX_BYTES)
		return -EINVAL;
	*out = (struct bpm_feed){};
	r = xcalloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;
	r->feed = out;
	{
		struct bpm_feed_entry *e = &r->entry;
		struct feed_list release = {
			r, e->selector.kernel_release_prefix,
			&e->selector.n_kernel_release_prefix,
		};
		struct feed_list build_id = {
			r, e->selector.kernel_build_id,
			&e->selector.n_kernel_build_id,
		};
		struct feed_list arch = {
			r, e->selector.architecture,
			&e->selector.n_architecture,
		};
		struct feed_list pair = { r, r->pair, &r->n_pair };
		struct feed_map kconfig = {
			r, &e->selector.kconfig, &e->selector.n_kconfig,
			TREE_MAX_KCONFIG,
		};
		struct feed_map labels = {
			r, &e->selector.labels, &e->selector.n_labels,
			TREE_MAX_LABELS,
		};
		struct json_array release_sink = { feed_list_value, &release };
		struct json_array build_id_sink = { feed_list_value, &build_id };
		struct json_array arch_sink = { feed_list_value, &arch };
		struct json_array pair_sink = { feed_list_value, &pair };
		struct json_array cve_sink = { feed_cve_value, r };
		struct json_map kconfig_map = { feed_map_pair, &kconfig };
		struct json_map labels_map = { feed_map_pair, &labels };
		struct json_array entries_sink = { feed_take_entry, r };
		struct json_field str_val[] = {
			{ "", JSON_T_STRING, r->value, sizeof(r->value), 0,
			  NULL, 0 },
		};
		struct json_field cve_val[] = {
			{ "", JSON_T_STRING, r->cve, sizeof(r->cve), 0,
			  NULL, 0 },
		};
		struct json_field pair_val[] = {
			{ "", JSON_T_ARRAY, &pair_sink, 0, 0, str_val,
			  ARRAY_SIZE(str_val) },
		};
		struct json_field selector[] = {
			{ "kernel_release_prefix", JSON_T_ARRAY, &release_sink,
			  0, 0, str_val, ARRAY_SIZE(str_val) },
			{ "kernel_build_id", JSON_T_ARRAY, &build_id_sink, 0, 0,
			  str_val, ARRAY_SIZE(str_val) },
			{ "architecture", JSON_T_ARRAY, &arch_sink, 0, 0,
			  str_val, ARRAY_SIZE(str_val) },
			{ "kconfig", JSON_T_MAP, &kconfig_map, 0, 0, pair_val,
			  ARRAY_SIZE(pair_val) },
			{ "kernel_config", JSON_T_MAP, &kconfig_map, 0, 0,
			  pair_val, ARRAY_SIZE(pair_val) },
			{ "labels", JSON_T_MAP, &labels_map, 0, 0, pair_val,
			  ARRAY_SIZE(pair_val) },
		};
		struct json_field entry[] = {
			{ "id", JSON_T_STRING, e->id, sizeof(e->id), 0, NULL,
			  0 },
			{ "cves", JSON_T_ARRAY, &cve_sink, 0, 0, cve_val,
			  ARRAY_SIZE(cve_val) },
			{ "package", JSON_T_STRING, e->package,
			  sizeof(e->package), 0, NULL, 0 },
			{ "version", JSON_T_STRING, e->version,
			  sizeof(e->version), 0, NULL, 0 },
			{ "reference", JSON_T_STRING, e->reference,
			  sizeof(e->reference), 0, NULL, 0 },
			{ "manifest_digest", JSON_T_STRING, e->manifest_digest,
			  sizeof(e->manifest_digest), 0, NULL, 0 },
			{ "role", JSON_T_STRING, r->role_str,
			  sizeof(r->role_str), 0, NULL, 0 },
			{ "selector", JSON_T_OBJECT, NULL, 0, 0, selector,
			  ARRAY_SIZE(selector) },
			{ "description", JSON_T_STRING, e->description,
			  sizeof(e->description), 0, NULL, 0 },
			{ "affected", JSON_T_STRING, e->affected,
			  sizeof(e->affected), 0, NULL, 0 },
			{ "fixed_in", JSON_T_STRING, e->fixed_in,
			  sizeof(e->fixed_in), 0, NULL, 0 },
		};
		struct json_field root[] = {
			{ "schema", JSON_T_INT, &schema, 0, 0, NULL, 0 },
			{ "feed_id", JSON_T_STRING, out->feed_id,
			  sizeof(out->feed_id), 0, NULL, 0 },
			{ "generated_at", JSON_T_STRING, out->generated_at,
			  sizeof(out->generated_at), 0, NULL, 0 },
			{ "entries", JSON_T_ARRAY, &entries_sink, 0, 0, entry,
			  ARRAY_SIZE(entry) },
			{ "expires", JSON_T_STRING, out->expires,
			  sizeof(out->expires), 0, NULL, 0 },
		};

		r->sel_lists = selector;
		r->entry_fields = entry;
		ret = json_parse(body, len, root, ARRAY_SIZE(root));
		if (!ret && (!root[0].seen || !root[1].seen || !root[2].seen ||
			     !root[3].seen))
			ret = -EINVAL;
		if (!ret && root[4].seen && !out->expires[0])
			ret = -EINVAL;
	}
	if (ret && ret != -E2BIG && ret != -ENOMEM)
		ret = -EINVAL;
	if (!ret && (schema != 1 || !feed_id_ok(out->feed_id) ||
		     !feed_timestamp_ok(out->generated_at)))
		ret = -EINVAL;
	if (!ret && out->expires[0]) {
		__s64 gen_sec = 0, exp_sec = 0;

		if (!feed_timestamp_parse(out->generated_at, &gen_sec) ||
		    !feed_timestamp_parse(out->expires, &exp_sec) ||
		    exp_sec < gen_sec)
			ret = -EINVAL;
	}
	out->schema = (int)schema;
	tree_selector_free(&r->entry.selector);
	xfree(r, sizeof(*r));
	if (ret)
		bpm_feed_free(out);
	return ret;
}

static int feed_kv_cmp(const void *left, const void *right)
{
	const struct tree_selector_kv *a =
		*(const struct tree_selector_kv * const *)left;
	const struct tree_selector_kv *b =
		*(const struct tree_selector_kv * const *)right;

	return strcmp(a->key, b->key);
}

static int feed_str_ptr_cmp(const void *left, const void *right)
{
	const char *a = *(const char * const *)left;
	const char *b = *(const char * const *)right;

	return strcmp(a, b);
}

static int feed_emit_selector(struct json_emit *e,
			      const struct tree_selector *s)
{
	const struct tree_selector_kv *kconfig[TREE_MAX_KCONFIG];
	const struct tree_selector_kv *labels[TREE_MAX_LABELS];

	if (s->n_kconfig > (int)ARRAY_SIZE(kconfig) ||
	    s->n_labels > (int)ARRAY_SIZE(labels))
		return -E2BIG;
	for (int i = 0; i < s->n_kconfig; i++)
		kconfig[i] = &s->kconfig[i];
	for (int i = 0; i < s->n_labels; i++)
		labels[i] = &s->labels[i];
	qsort(kconfig, (size_t)s->n_kconfig, sizeof(kconfig[0]), feed_kv_cmp);
	qsort(labels, (size_t)s->n_labels, sizeof(labels[0]), feed_kv_cmp);

	json_obj_open_key(e, "selector");
	if (s->n_architecture) {
		json_arr_open(e, "architecture");
		for (int i = 0; i < s->n_architecture; i++)
			json_str(e, s->architecture[i]);
		json_arr_close(e);
	}
	if (s->n_kconfig) {
		json_obj_open_key(e, "kconfig");
		for (int i = 0; i < s->n_kconfig; i++) {
			json_arr_open(e, kconfig[i]->key);
			for (int j = 0; j < kconfig[i]->n_values; j++)
				json_str(e, kconfig[i]->values[j]);
			json_arr_close(e);
		}
		json_obj_close(e);
	}
	if (s->n_kernel_build_id) {
		json_arr_open(e, "kernel_build_id");
		for (int i = 0; i < s->n_kernel_build_id; i++)
			json_str(e, s->kernel_build_id[i]);
		json_arr_close(e);
	}
	if (s->n_kernel_release_prefix) {
		json_arr_open(e, "kernel_release_prefix");
		for (int i = 0; i < s->n_kernel_release_prefix; i++)
			json_str(e, s->kernel_release_prefix[i]);
		json_arr_close(e);
	}
	if (s->n_labels) {
		json_obj_open_key(e, "labels");
		for (int i = 0; i < s->n_labels; i++) {
			json_arr_open(e, labels[i]->key);
			for (int j = 0; j < labels[i]->n_values; j++)
				json_str(e, labels[i]->values[j]);
			json_arr_close(e);
		}
		json_obj_close(e);
	}
	json_obj_close(e);
	return 0;
}

static int feed_emit_entry(struct json_emit *e,
			   const struct bpm_feed_entry *ent)
{
	const char *cves[BPM_FEED_MAX_CVES];
	int ret;

	if (!feed_entry_valid(ent))
		return -EINVAL;
	for (int i = 0; i < ent->n_cves; i++)
		cves[i] = ent->cves[i];
	qsort(cves, (size_t)ent->n_cves, sizeof(cves[0]), feed_str_ptr_cmp);

	json_obj_open(e);
	json_kv_string(e, "id", ent->id);
	json_arr_open(e, "cves");
	for (int i = 0; i < ent->n_cves; i++)
		json_str(e, cves[i]);
	json_arr_close(e);
	json_kv_string(e, "package", ent->package);
	json_kv_string(e, "version", ent->version);
	json_kv_string(e, "reference", ent->reference);
	json_kv_string(e, "manifest_digest", ent->manifest_digest);
	json_kv_string(e, "role", bpm_feed_role_str(ent->role));
	ret = feed_emit_selector(e, &ent->selector);
	if (ret)
		return ret;
	json_kv_string(e, "description", ent->description);
	if (ent->affected[0])
		json_kv_string(e, "affected", ent->affected);
	if (ent->fixed_in[0])
		json_kv_string(e, "fixed_in", ent->fixed_in);
	json_obj_close(e);
	return e->err;
}

int bpm_feed_emit(const struct bpm_feed *feed, char **out, size_t *out_len)
{
	struct json_emit e;
	char *body;
	size_t cap;
	int ret = 0;

	if (!feed || !out || !out_len || feed->schema != 1 ||
	    !feed_id_ok(feed->feed_id) ||
	    !feed_timestamp_ok(feed->generated_at) ||
	    (feed->expires[0] && !feed_timestamp_ok(feed->expires)) ||
	    feed->n_entries < 0 || feed->n_entries > BPM_FEED_MAX_ENTRIES)
		return -EINVAL;
	for (int i = 0; i < feed->n_entries; i++) {
		for (int j = i + 1; j < feed->n_entries; j++)
			if (!strcmp(feed->entries[i].id, feed->entries[j].id))
				return -EINVAL;
	}
	cap = 1024 + (size_t)feed->n_entries * 1024;
	if (cap > JSON_MAX_BYTES)
		cap = JSON_MAX_BYTES;
	body = xmalloc(cap);
	if (!body)
		return -ENOMEM;
	e = (struct json_emit){
		.buf = body, .cap = cap, .max = JSON_MAX_BYTES + 1,
	};
	json_obj_open(&e);
	json_kv_int(&e, "schema", feed->schema);
	json_kv_string(&e, "feed_id", feed->feed_id);
	json_kv_string(&e, "generated_at", feed->generated_at);
	if (feed->expires[0])
		json_kv_string(&e, "expires", feed->expires);
	json_arr_open(&e, "entries");
	for (int i = 0; !ret && i < feed->n_entries; i++)
		ret = feed_emit_entry(&e, &feed->entries[i]);
	json_arr_close(&e);
	json_obj_close(&e);
	if (!ret)
		ret = e.err;
	if (!ret && e.len > JSON_MAX_BYTES)
		ret = -E2BIG;
	if (ret) {
		xfree(e.buf, e.cap);
		return ret;
	}
	*out = e.buf;
	*out_len = e.len;
	return 0;
}

int bpm_feed_verify_memory(const __u8 *feed_bytes, size_t feed_len,
			   const __u8 *sig_bytes, size_t sig_len,
			   const struct cert *cert, struct bpm_feed *out)
{
	char alg[32] = {};
	int signed_by;
	int ret;

	if (!feed_bytes || !sig_bytes || !cert || !out)
		return -EINVAL;
	if (cert_key_algorithm(cert, alg, sizeof(alg)) ||
	    strcmp(alg, "ML-DSA-87"))
		return -EKEYREJECTED;
	if (cert_valid_at(cert, (__s64)time(NULL)))
		return -EKEYREJECTED;
	if (cms_check_signers(sig_bytes, sig_len))
		return -EKEYREJECTED;
	signed_by = cms_signed_by(sig_bytes, sig_len, cert);
	if (signed_by != 1)
		return signed_by < 0 ? signed_by : -EKEYREJECTED;
	ret = verify_detached(feed_bytes, feed_len, sig_bytes, sig_len, cert);
	if (ret)
		return -EKEYREJECTED;
	ret = bpm_feed_parse((const char *)feed_bytes, feed_len, out);
	if (ret)
		return ret;
	ret = bpm_feed_check_freshness(out, (__s64)time(NULL));
	if (ret)
		bpm_feed_free(out);
	return ret;
}

int bpm_feed_verify_trusted(const __u8 *feed_bytes, size_t feed_len,
			    const __u8 *sig_bytes, size_t sig_len,
			    const struct trusted_set *trusted,
			    struct bpm_feed *out)
{
	int ret = -EKEYREJECTED;

	if (!feed_bytes || !sig_bytes || !trusted || !out)
		return -EINVAL;
	if (!trusted->n)
		return -ENOKEY;
	if (cms_check_signers(sig_bytes, sig_len))
		return -EKEYREJECTED;
	for (size_t i = 0; i < trusted->n; i++) {
		struct cert cert = {};
		int r;

		r = keys_cert_read(&trusted->certs[i], &cert);
		if (r)
			continue;
		r = cms_signed_by(sig_bytes, sig_len, &cert);
		if (r == 1) {
			ret = bpm_feed_verify_memory(feed_bytes, feed_len,
						     sig_bytes, sig_len,
						     &cert, out);
			cert_free(&cert);
			return ret;
		}
		cert_free(&cert);
	}
	return ret;
}

int bpm_feed_verify_files(const char *feed_path, const char *sig_path,
			  const char *cert_path, struct bpm_feed *out)
{
	size_t feed_len = 0, sig_len = 0, cert_len = 0;
	__u8 *feed_bytes = NULL, *sig_bytes = NULL, *cert_bytes = NULL;
	struct cert cert = {};
	int ret;

	if (!feed_path || !sig_path || !cert_path || !out)
		return -EINVAL;
	ret = read_file(feed_path, JSON_MAX_BYTES, &feed_bytes, &feed_len);
	if (ret)
		return ret;
	ret = read_file(sig_path, BPM_FEED_SIG_MAX, &sig_bytes, &sig_len);
	if (ret)
		goto out_feed;
	ret = read_file(cert_path, BPM_FEED_CERT_MAX, &cert_bytes, &cert_len);
	if (ret)
		goto out_sig;
	ret = cert_read_memory(cert_bytes, cert_len, &cert);
	if (!ret)
		ret = bpm_feed_verify_memory(feed_bytes, feed_len, sig_bytes,
					     sig_len, &cert, out);
	cert_free(&cert);
	xfree(cert_bytes, cert_len + 1);
out_sig:
	xfree(sig_bytes, sig_len + 1);
out_feed:
	xfree(feed_bytes, feed_len + 1);
	return ret;
}

int bpm_feed_verify_files_trusted(const char *feed_path, const char *sig_path,
				  const char *keys_dir, struct bpm_feed *out)
{
	size_t feed_len = 0, sig_len = 0;
	__u8 *feed_bytes = NULL, *sig_bytes = NULL;
	struct trusted_set *trusted;
	int ret;

	if (!feed_path || !sig_path || !out)
		return -EINVAL;
	trusted = xcalloc(1, sizeof(*trusted));
	if (!trusted)
		return -ENOMEM;
	if (!keys_dir) {
		const char *env = getenv(KEYS_DIR_ENV);

		keys_dir = (env && env[0]) ? env : KEYS_DIR;
	}
	ret = keys_load(keys_dir, KEYS_REVOKED_DIR, true, trusted);
	if (!ret && (!trusted->n || trusted->n_unvouched))
		ret = -EKEYREJECTED;
	if (ret)
		goto out_trusted;
	ret = read_file(feed_path, JSON_MAX_BYTES, &feed_bytes, &feed_len);
	if (ret)
		goto out_trusted;
	ret = read_file(sig_path, BPM_FEED_SIG_MAX, &sig_bytes, &sig_len);
	if (ret)
		goto out_feed;
	ret = bpm_feed_verify_trusted(feed_bytes, feed_len, sig_bytes, sig_len,
				      trusted, out);
	xfree(sig_bytes, sig_len + 1);
out_feed:
	xfree(feed_bytes, feed_len + 1);
out_trusted:
	xfree(trusted, sizeof(*trusted));
	return ret;
}
