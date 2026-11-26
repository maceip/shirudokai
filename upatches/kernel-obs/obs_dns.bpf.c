// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * obs_dns.bpf.c -- map answered addresses to the names that resolved them.
 *
 * Egress UDP queries are keyed by network namespace, flow and transaction
 * id and remembered with the querying identity; the matching ingress
 * response consumes the entry and records every matching A or AAAA answer
 * under the identity and address.
 */

#include "obs_dns_parse.h"

BUILD_BUG_ON_MSG(sizeof(struct dns_request_key) != 48,
		 "dns request key ABI must remain verifier-friendly");
BUILD_BUG_ON_MSG(sizeof(struct dns_request) != 296,
		 "dns request value layout must remain 8-byte aligned");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DNS_REQ_MAP_ENTRIES);
	__type(key, struct dns_request_key);
	__type(value, struct dns_request);
} obs_i_dns_req SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_scratch);
} obs_i_dns_tmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DNS_DBG_MAX);
	__type(key, __u32);
	__type(value, __u64);
} obs_i_dns_dbg SEC(".maps");

#define OBS_T		dns
#define OBS_T_MAP	dns
#define OBS_T_KEY	struct dns_key
#define OBS_T_VAL	struct dns_val
#define OBS_T_CAPACITY	1024
#define OBS_T_BUCKETS	512
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x41534e44u	/* "DNSA" little-endian */
#define OBS_T_RECORD	1168
#define OBS_T_EMIT	dns_emit_record
#include "obs_table.h"

static __always_inline void dns_debug_inc(__u32 key)
{
	__u64 *value;

	if (key >= DNS_DBG_MAX)
		return;
	value = bpf_map_lookup_elem(&obs_i_dns_dbg, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline void dns_req_live_inc(void)
{
	__u32 key = DNS_DBG_REQ_LIVE, tries;
	__u64 *live;

	live = bpf_map_lookup_elem(&obs_i_dns_dbg, &key);
	if (!live)
		return;
#pragma clang loop unroll(disable)
	for (tries = 0; tries < 8; tries++) {
		__u64 cur = READ_ONCE(*live);

		if (cur >= DNS_REQ_MAP_ENTRIES) {
			dns_debug_inc(DNS_DBG_REQ_LRU_EVICT);
			return;
		}
		if (__sync_val_compare_and_swap(live, cur, cur + 1) == cur)
			return;
	}
}

static __always_inline void dns_req_delete(const struct dns_request_key *req_key)
{
	__u32 key = DNS_DBG_REQ_LIVE, tries;
	__u64 *live;

	if (bpf_map_delete_elem(&obs_i_dns_req, req_key) != 0)
		return;
	live = bpf_map_lookup_elem(&obs_i_dns_dbg, &key);
	if (!live)
		return;
#pragma clang loop unroll(disable)
	for (tries = 0; tries < 8; tries++) {
		__u64 cur = READ_ONCE(*live);

		if (cur == 0)
			return;
		if (__sync_val_compare_and_swap(live, cur, cur - 1) == cur)
			return;
	}
}

__attribute__((noinline)) void
obs_dns_emit_name(struct serial_chunk *chunk, __u32 base,
		  const struct dns_name __arena *stat)
{
	int i;

	if (!chunk || !stat ||
	    base > SERIAL_CHUNK_PAYLOAD - sizeof(struct dns_name))
		return;
	barrier_var(base);
	*(__u64 *)&chunk->data[base] = stat->seen;
	*(__u64 *)&chunk->data[base + 8] = stat->last_ns;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_NAME_BYTES; i++)
		chunk->data[base + 16 + i] = stat->name[i];
}

static int dns_emit_record(struct serial_chunk *chunk, __u32 off,
			   const struct dns_entry __arena *e)
{
	int i;

	*(__u32 *)&chunk->data[off + 8] = e->key.ident.exe.dev;
	*(__u32 *)&chunk->data[off + 12] = 0;
	*(__u64 *)&chunk->data[off + 16] = e->key.ident.exe.ino;
	*(__u64 *)&chunk->data[off + 24] = e->key.ident.cgroup;
	chunk->data[off + 32] = e->key.family;
	chunk->data[off + 33] = 0;
	*(__u16 *)&chunk->data[off + 34] = 0;
	*(__u32 *)&chunk->data[off + 36] = 0;
	*(__u32 *)&chunk->data[off + 40] = e->key.addr[0];
	*(__u32 *)&chunk->data[off + 44] = e->key.addr[1];
	*(__u32 *)&chunk->data[off + 48] = e->key.addr[2];
	*(__u32 *)&chunk->data[off + 52] = e->key.addr[3];
	*(__u64 *)&chunk->data[off + 56] = e->val.count;
	*(__u64 *)&chunk->data[off + 64] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 72] = e->val.last_ns;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAMES_PER_IP; i++)
		obs_dns_emit_name(chunk, off + 80 + i * sizeof(struct dns_name),
				  &e->val.names[i]);
	return 0;
}

__attribute__((noinline)) bool
obs_dns_name_equal_arena(const char __arena *a, const struct dns_request *req)
{
	int i;

	if (!a || !req)
		return false;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_NAME_BYTES; i++) {
		__u8 ca = (__u8)a[i];
		__u8 cb = (__u8)req->name[i];

		if (dns_ascii_lower(ca) != dns_ascii_lower(cb))
			return false;
		if (ca == '\0')
			return true;
	}
	return true;
}

__attribute__((noinline)) void
obs_dns_name_copy_to_arena(char __arena *dst, const struct dns_request *req)
{
	int i;

	if (!dst || !req)
		return;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_CHARS; i++)
		dst[i] = req->name[i];
	dst[DNS_MAX_NAME_CHARS] = 0;
}

static __always_inline void dns_name_set(struct dns_name __arena *stat,
					 const struct dns_request *req,
					 __u64 now)
{
	stat->seen = 1;
	stat->last_ns = now;
	obs_dns_name_copy_to_arena(stat->name, req);
}

/* Up to four names per address; the oldest gives way to a new one. */
static __always_inline void dns_names_touch(struct dns_entry __arena *e,
					    const struct dns_request *req,
					    __u64 now)
{
	struct dns_name __arena *stat, *oldest_stat = 0, *empty_stat = 0;
	__u64 oldest = ~0ULL;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAMES_PER_IP; i++) {
		stat = &e->val.names[i];
		if (stat->seen && obs_dns_name_equal_arena(stat->name, req)) {
			__sync_fetch_and_add(&stat->seen, 1);
			stat->last_ns = now;
			return;
		}
		if (!stat->seen && !empty_stat)
			empty_stat = stat;
		if (stat->last_ns < oldest) {
			oldest = stat->last_ns;
			oldest_stat = stat;
		}
	}
	stat = empty_stat ? empty_stat : oldest_stat;
	if (stat)
		dns_name_set(stat, req, now);
}

static __always_inline void dns_table_touch(const struct dns_request *req,
					    const struct dns_key *ip,
					    __u64 now)
{
	struct dns_entry __arena *e;
	struct dns_key key = *ip;
	int status;

	if (!req->name[0])
		return;
	dns_debug_inc(DNS_DBG_TOUCH_CALLED);
	key.ident.exe = req->exe;
	key.ident.cgroup = req->cgroup;
	e = dns_touch(&key, &status);
	switch (status) {
	case OBS_TOUCH_HIT:
		dns_debug_inc(DNS_DBG_TOUCH_HIT);
		break;
	case OBS_TOUCH_CREATED:
		dns_debug_inc(DNS_DBG_ALLOC_ATTEMPT);
		dns_debug_inc(DNS_DBG_ALLOC_OK);
		dns_debug_inc(DNS_DBG_CAS_OK);
		break;
	case OBS_TOUCH_NO_STATE:
		dns_debug_inc(DNS_DBG_TOUCH_INIT_FAIL);
		return;
	case OBS_TOUCH_OVERFLOW:
		dns_debug_inc(DNS_DBG_ALLOC_ATTEMPT);
		dns_debug_inc(DNS_DBG_ALLOC_BAD_IDX);
		return;
	default:
		dns_debug_inc(DNS_DBG_ALLOC_ATTEMPT);
		dns_debug_inc(DNS_DBG_ALLOC_OK);
		dns_debug_inc(DNS_DBG_CAS_FAIL);
		return;
	}
	if (!e) {
		dns_debug_inc(DNS_DBG_ALLOC_ENTRY_MISS);
		return;
	}
	if (status == OBS_TOUCH_CREATED)
		e->val.first_ns = now;
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	dns_names_touch(e, req, now);
}

static __always_inline const __u8 *dns_skb_data(struct __sk_buff *skb)
{
	return (const __u8 *)(long)skb->data;
}

static __always_inline const __u8 *dns_skb_data_end(struct __sk_buff *skb)
{
	return (const __u8 *)(long)skb->data_end;
}

__attribute__((noinline)) int
obs_dns_parse_name_label(struct __sk_buff *skb, __u32 off, __u32 start,
			 __u32 dns_end)
{
	struct dns_scratch *scratch;
	__u32 zero = 0;

	scratch = bpf_map_lookup_elem(&obs_i_dns_tmp, &zero);
	if (!scratch)
		return -EINVAL;
	return dns_parse_label_into(dns_skb_data(skb), dns_skb_data_end(skb),
				    off, start, dns_end, scratch->req.name);
}

static __always_inline int dns_parse_name(struct __sk_buff *skb, __u32 off,
					  __u32 dns_end,
					  struct dns_request *req,
					  __u32 *next_off)
{
	__u32 start = off, pos = off;
	int consumed, replaced = 0, i;

	if (!req || !next_off)
		return -EINVAL;
	/*
	 * The request is stored whole, and its name goes on to the arena and
	 * the export: the bytes a longer name of an earlier query left behind
	 * the terminator would go with it.
	 */
	__builtin_memset(req->name, 0, sizeof(req->name));
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_STEPS; i++) {
		consumed = obs_dns_parse_name_label(skb, pos, start, dns_end);
		if (consumed < 0)
			return consumed;
		if (consumed == 0) {
			*next_off = pos + 1;
			return replaced;
		}
		replaced |= consumed & DNS_NAME_REPLACED;
		consumed &= ~DNS_NAME_REPLACED;
		if ((__u32)consumed > dns_end - pos)
			return -EINVAL;
		pos += (__u32)consumed;
		if (pos - start >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
	}
	return -EINVAL;
}

__attribute__((noinline)) int
obs_dns_skip_name(struct __sk_buff *skb, __u32 dns_off, __u32 dns_end,
		  __u32 off)
{
	__u32 next_off = 0;
	int err;

	err = dns_skip_name_bounded(dns_skb_data(skb), dns_skb_data_end(skb),
				    dns_off, dns_end, off, &next_off);
	if (err < 0)
		return err;
	return (int)next_off;
}

__attribute__((noinline)) int
obs_dns_match_label(struct __sk_buff *skb, __u32 cur, __u32 len,
		    const struct dns_request *req, __u32 name_pos)
{
	if (!req)
		return -EINVAL;
	return dns_match_label_chars(dns_skb_data(skb), dns_skb_data_end(skb),
				     cur, len, req->name, name_pos);
}

static __always_inline int dns_match_qname(struct __sk_buff *skb,
					   __u32 dns_off, __u32 dns_end,
					   __u32 off,
					   const struct dns_request *req,
					   __u32 *next_off)
{
	const __u8 *data = dns_skb_data(skb);
	const __u8 *data_end = dns_skb_data_end(skb);
	__u32 cur = off, after_first = 0, wire_bytes = 0, jumps = 0;
	__u32 name_pos = 0;
	bool jumped = false;
	int step;

	barrier_var(dns_off);
	barrier_var(dns_end);
	if (!req || !next_off || dns_end > DNS_MAX_PACKET_BYTES ||
	    dns_off > DNS_MAX_PACKET_BYTES - sizeof(struct dns_hdr) ||
	    dns_off + sizeof(struct dns_hdr) > dns_end)
		return -EINVAL;

#pragma clang loop unroll(disable)
	for (step = 0; step < DNS_MAX_NAME_STEPS; step++) {
		__u32 label_len, ptr_rel, target;
		const __u8 *src;
		int next_pos;
		__u8 len;

		barrier_var(cur);
		if (cur < dns_off + sizeof(struct dns_hdr) || cur >= dns_end)
			return -EINVAL;
		if (wire_bytes >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
		src = data + cur;
		if (src + 1 > data_end)
			return -EINVAL;
		len = *src;

		if ((len & DNS_COMPRESSED_MASK) == DNS_COMPRESSED_MASK) {
			if (cur > dns_end - 2 || src + 2 > data_end)
				return -EINVAL;
			if (jumps >= DNS_MAX_JUMPS)
				return -EINVAL;
			ptr_rel = (((__u32)(len & 0x3f)) << 8) | (__u32)src[1];
			if (ptr_rel < sizeof(struct dns_hdr))
				return -EINVAL;
			target = dns_off + ptr_rel;
			if (target >= cur || target >= dns_end)
				return -EINVAL;
			if (!jumped) {
				after_first = cur + 2;
				jumped = true;
			}
			jumps++;
			cur = target;
			continue;
		}
		if (len & DNS_COMPRESSED_MASK)
			return -EINVAL;
		if (len == 0) {
			if (wire_bytes + 1 > DNS_MAX_WIRE_NAME_BYTES)
				return -EINVAL;
			barrier_var(name_pos);
			if (name_pos == 0 || name_pos > DNS_MAX_NAME_CHARS)
				return -EBADMSG;
			if (req->name[name_pos] != '\0')
				return -EBADMSG;
			*next_off = jumped ? after_first : cur + 1;
			return 0;
		}
		if (len > DNS_MAX_LABEL_BYTES)
			return -EINVAL;

		label_len = (__u32)len;
		if (wire_bytes + 1 + label_len >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
		if (label_len > dns_end - cur - 1)
			return -EINVAL;
		next_pos = obs_dns_match_label(skb, cur, label_len, req,
					       name_pos);
		if (next_pos < 0)
			return next_pos;
		name_pos = (__u32)next_pos;
		wire_bytes += 1 + label_len;
		cur += 1 + label_len;
	}
	return -EINVAL;
}

/* The querying identity: the socket's owner, else the sending task. */
static __always_inline bool dns_query_ident(struct __sk_buff *skb,
					    struct obs_ident *ident)
{
	struct obs_sock_meta *meta = 0;
	struct bpf_sock *sk = skb->sk;

	if (sk)
		meta = bpf_sk_storage_get(&obs_i_sock, sk, 0, 0);
	if (meta) {
		ident->exe = meta->exe;
		ident->cgroup = meta->cgroup;
		return true;
	}
	return obs_ident_checked(ident, obs_now());
}

static __always_inline void dns_store_pending_query(struct dns_request_key *req_key,
						    struct dns_request *req,
						    __u64 now_ns)
{
	struct dns_request *existing;
	long err;

	err = bpf_map_update_elem(&obs_i_dns_req, req_key, req, BPF_NOEXIST);
	if (err == 0) {
		dns_req_live_inc();
		dns_debug_inc(DNS_DBG_QUERY_STORED);
		return;
	}
	if (err == -EEXIST) {
		existing = bpf_map_lookup_elem(&obs_i_dns_req, req_key);
		if (existing && dns_is_req_stale(existing, now_ns)) {
			dns_debug_inc(DNS_DBG_RESP_STALE);
			dns_req_delete(req_key);
			err = bpf_map_update_elem(&obs_i_dns_req, req_key, req,
						  BPF_NOEXIST);
			if (err == 0) {
				dns_req_live_inc();
				dns_debug_inc(DNS_DBG_QUERY_STORED);
				return;
			}
		}
	}
	dns_debug_inc(DNS_DBG_REQ_TABLE_FULL);
}

/*
 * The scratch is per CPU and unguarded: kernel-obs is written for a kernel
 * without preemptible RCU, where no egress run starts on a CPU before
 * another one there ends.
 */
static __always_inline void dns_parse_query_payload(struct __sk_buff *skb,
						    __u32 dns_off,
						    __u32 dns_end,
						    struct dns_request_key *req_key)
{
	const __u8 *data = dns_skb_data(skb), *data_end = dns_skb_data_end(skb);
	__u16 id, flags, qdcount, qtype, qclass, arcount;
	struct dns_scratch *scratch;
	struct obs_ident ident = {};
	__u64 now_ns = bpf_ktime_get_ns();
	__u32 zero = 0, next = 0;
	int parsed;

	dns_debug_inc(DNS_DBG_QUERY_PACKET);
	if (!dns_query_ident(skb, &ident)) {
		dns_debug_inc(DNS_DBG_QUERY_NO_UID);
		return;
	}
	if (!dns_read_u16_bounded(data, data_end, dns_off, dns_end, &id) ||
	    !dns_read_u16_bounded(data, data_end, dns_off + 2, dns_end, &flags) ||
	    !dns_read_u16_bounded(data, data_end, dns_off + 4, dns_end, &qdcount) ||
	    !dns_read_u16_bounded(data, data_end, dns_off + 10, dns_end, &arcount)) {
		dns_debug_inc(DNS_DBG_QUERY_HDR_FAIL);
		return;
	}
	if (flags & DNS_FLAG_QR) {
		dns_debug_inc(DNS_DBG_QUERY_IS_RESPONSE);
		return;
	}
	if (flags & DNS_OPCODE_MASK) {
		dns_debug_inc(DNS_DBG_QUERY_BAD_OPCODE);
		return;
	}
	if (qdcount != 1) {
		dns_debug_inc(DNS_DBG_QUERY_QDCOUNT_BAD);
		return;
	}
	scratch = bpf_map_lookup_elem(&obs_i_dns_tmp, &zero);
	if (!scratch) {
		dns_debug_inc(DNS_DBG_QUERY_SCRATCH_MISS);
		return;
	}
	parsed = dns_parse_name(skb, dns_off + sizeof(struct dns_hdr),
				dns_end, &scratch->req, &next);
	if (parsed < 0) {
		dns_debug_inc(DNS_DBG_QUERY_NAME_FAIL);
		return;
	}
	if (parsed & DNS_NAME_REPLACED)
		dns_debug_inc(DNS_DBG_QUERY_NAME_REPLACED);
	if (!scratch->req.name[0]) {
		dns_debug_inc(DNS_DBG_QUERY_EMPTY_NAME);
		return;
	}
	if (!dns_read_u16_bounded(data, data_end, next, dns_end, &qtype) ||
	    !dns_read_u16_bounded(data, data_end, next + 2, dns_end, &qclass)) {
		dns_debug_inc(DNS_DBG_QUERY_QTYPE_READ_FAIL);
		return;
	}
	if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
		dns_debug_inc(DNS_DBG_QUERY_QTYPE_UNSUPPORTED);
		return;
	}
	if (qclass != DNS_CLASS_IN) {
		dns_debug_inc(DNS_DBG_QUERY_QCLASS_UNSUPPORTED);
		return;
	}
	scratch->req.exe = ident.exe;
	scratch->req.cgroup = ident.cgroup;
	scratch->req.sent_ns = now_ns;
	scratch->req.qtype = qtype;
	scratch->req.qclass = qclass;
	scratch->req._pad = 0;
	req_key->id = id;
	dns_store_pending_query(req_key, &scratch->req, now_ns);
}

__attribute__((noinline)) int
obs_dns_parse_answer(struct __sk_buff *skb, const struct dns_request *req,
		     __u32 dns_off, __u32 dns_end, __u32 off, __u64 now)
{
	const __u8 *data, *data_end;
	struct dns_key key = {};
	__u16 rtype, rclass, rdlen;
	__u32 next, rdata_off;
	int skip_rc, addr_rc;

	if (!req)
		return -EINVAL;
	dns_debug_inc(DNS_DBG_RESP_ANSWER_SEEN);
	skip_rc = obs_dns_skip_name(skb, dns_off, dns_end, off);
	if (skip_rc < 0) {
		dns_debug_inc(DNS_DBG_RESP_ANSWER_SKIP_FAIL);
		return -EINVAL;
	}
	next = (__u32)skip_rc;
	data = dns_skb_data(skb);
	data_end = dns_skb_data_end(skb);
	if (!dns_read_u16_bounded(data, data_end, next, dns_end, &rtype) ||
	    !dns_read_u16_bounded(data, data_end, next + 2, dns_end, &rclass) ||
	    !dns_read_u16_bounded(data, data_end, next + 8, dns_end, &rdlen)) {
		dns_debug_inc(DNS_DBG_RESP_RR_READ_FAIL);
		return -EINVAL;
	}
	rdata_off = next + 10;
	barrier_var(rtype);
	barrier_var(rclass);
	barrier_var(rdlen);
	barrier_var(rdata_off);
	barrier_var(dns_end);
	if (dns_end > DNS_MAX_PACKET_BYTES ||
	    rdata_off > dns_end ||
	    rdlen > dns_end - rdata_off) {
		dns_debug_inc(DNS_DBG_RESP_RDATA_BOUNDS_FAIL);
		return -EINVAL;
	}
	addr_rc = dns_extract_answer_addr(data, data_end, rdata_off, dns_end,
					  req->qtype, rtype, rclass, rdlen,
					  &key);
	if (addr_rc < 0) {
		dns_debug_inc(DNS_DBG_RESP_RDATA_BOUNDS_FAIL);
		return -EINVAL;
	}
	if (addr_rc == 0) {
		dns_debug_inc(DNS_DBG_RESP_ADDR_UNSUPPORTED);
	} else {
		dns_debug_inc(DNS_DBG_RESP_ADDR_PARSED);
		dns_debug_inc(DNS_DBG_RESP_TOUCH);
		dns_table_touch(req, &key, now);
	}
	return (int)(rdata_off + rdlen);
}

static __always_inline void dns_parse_response_payload(struct __sk_buff *skb,
						       __u32 dns_off,
						       __u32 dns_end,
						       struct dns_request_key *req_key)
{
	const __u8 *data = dns_skb_data(skb), *data_end = dns_skb_data_end(skb);
	__u16 id, flags, qdcount, ancount, arcount, qtype, qclass;
	__u64 now = obs_now(), now_ns = bpf_ktime_get_ns();
	struct dns_request *req;
	__u32 off, next = 0;
	bool bad_flags = false;
	int qrc, answer_off, i;

	dns_debug_inc(DNS_DBG_RESP_PACKET);
	if (!dns_read_u16_bounded(data, data_end, dns_off, dns_end, &id) ||
	    !dns_read_u16_bounded(data, data_end, dns_off + 2, dns_end, &flags) ||
	    !dns_read_u16_bounded(data, data_end, dns_off + 4, dns_end, &qdcount) ||
	    !dns_read_u16_bounded(data, data_end, dns_off + 6, dns_end, &ancount) ||
	    !dns_read_u16_bounded(data, data_end, dns_off + 10, dns_end, &arcount)) {
		dns_debug_inc(DNS_DBG_RESP_HDR_FAIL);
		return;
	}
	if ((flags & DNS_FLAG_QR) == 0) {
		dns_debug_inc(DNS_DBG_RESP_NOT_RESPONSE);
		return;
	}
	if (flags & DNS_OPCODE_MASK) {
		dns_debug_inc(DNS_DBG_RESP_BAD_OPCODE);
		bad_flags = true;
	}
	if (flags & DNS_FLAG_TC) {
		dns_debug_inc(DNS_DBG_RESP_TRUNCATED);
		bad_flags = true;
	}
	if (flags & DNS_RCODE_MASK) {
		dns_debug_inc(DNS_DBG_RESP_BAD_RCODE);
		bad_flags = true;
	}
	if (qdcount != 1) {
		dns_debug_inc(DNS_DBG_RESP_QDCOUNT_BAD);
		return;
	}

	req_key->id = id;
	req = bpf_map_lookup_elem(&obs_i_dns_req, req_key);
	if (!req) {
		if (!bad_flags && ancount == 0)
			dns_debug_inc(DNS_DBG_RESP_NO_ANSWER);
		else if (!bad_flags)
			dns_debug_inc(DNS_DBG_RESP_REQ_MISS);
		return;
	}
	if (dns_is_req_stale(req, now_ns)) {
		dns_debug_inc(DNS_DBG_RESP_STALE);
		dns_req_delete(req_key);
		dns_debug_inc(DNS_DBG_RESP_DELETE);
		return;
	}

	qrc = dns_match_qname(skb, dns_off, dns_end,
			      dns_off + sizeof(struct dns_hdr), req, &next);
	if (qrc < 0) {
		if (qrc == -EBADMSG)
			dns_debug_inc(DNS_DBG_RESP_QNAME_MISMATCH);
		else
			dns_debug_inc(DNS_DBG_RESP_QNAME_SKIP_FAIL);
		return;
	}
	data = dns_skb_data(skb);
	data_end = dns_skb_data_end(skb);
	if (!dns_read_u16_bounded(data, data_end, next, dns_end, &qtype) ||
	    !dns_read_u16_bounded(data, data_end, next + 2, dns_end, &qclass)) {
		dns_debug_inc(DNS_DBG_RESP_QTYPE_READ_FAIL);
		return;
	}
	if (qtype != req->qtype) {
		dns_debug_inc(DNS_DBG_RESP_QTYPE_MISMATCH);
		return;
	}
	if (qclass != DNS_CLASS_IN || qclass != req->qclass) {
		dns_debug_inc(DNS_DBG_RESP_QCLASS_MISMATCH);
		return;
	}

	/*
	 * A correlated response carrying TC=1, non-zero OPCODE, or non-zero
	 * RCODE (e.g. NXDOMAIN or truncated UDP fallback to TCP) retires the
	 * pending query without recording partial or untrusted answers.
	 */
	if (bad_flags) {
		dns_req_delete(req_key);
		dns_debug_inc(DNS_DBG_RESP_DELETE);
		return;
	}
	if (ancount == 0) {
		dns_debug_inc(DNS_DBG_RESP_NO_ANSWER);
		dns_req_delete(req_key);
		dns_debug_inc(DNS_DBG_RESP_DELETE);
		return;
	}

	off = next + 4;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_ANSWERS; i++) {
		if (i >= ancount)
			break;
		answer_off = obs_dns_parse_answer(skb, req, dns_off, dns_end,
						  off, now);
		if (answer_off < 0)
			break;
		off = (__u32)answer_off;
	}
	if (i == DNS_MAX_ANSWERS && ancount > DNS_MAX_ANSWERS)
		dns_debug_inc(DNS_DBG_RESP_ANSWER_CAP);

	dns_req_delete(req_key);
	dns_debug_inc(DNS_DBG_RESP_DELETE);
}

/*
 * Called for every packet the cgroup hooks see, parsed or not, so the
 * debug counters account for the ones the header parser rejected.
 */
static __always_inline void dns_parse_packet(struct __sk_buff *skb,
					     const struct obs_pkt *pkt,
					     bool parsed, bool send)
{
	struct dns_request_key req_key = {};
	struct dns_pkt_meta meta = {};
	const __u32 *client, *resolver;
	enum dns_pkt_verdict verdict;

	switch (pkt->ethertype) {
	case ETH_P_IP:
		dns_debug_inc(DNS_DBG_PACKET_IPV4);
		break;
	case ETH_P_IPV6:
		if (!obs_ipv6_enabled())
			return;
		dns_debug_inc(DNS_DBG_PACKET_IPV6);
		break;
	default:
		return;
	}

	verdict = dns_validate_packet(dns_skb_data(skb), dns_skb_data_end(skb),
				      skb->len, pkt->ethertype, send, &meta);
	switch (verdict) {
	case DNS_PKT_OK:
		break;
	case DNS_PKT_FRAGMENT:
		dns_debug_inc(DNS_DBG_PACKET_FRAGMENT);
		return;
	case DNS_PKT_IPV6_EXT:
		dns_debug_inc(DNS_DBG_PACKET_IPV6_EXT);
		return;
	case DNS_PKT_NOT_UDP:
		dns_debug_inc(DNS_DBG_PACKET_NOT_UDP);
		return;
	case DNS_PKT_PORT_SKIP:
		dns_debug_inc(DNS_DBG_PACKET_PORT_SKIP);
		return;
	case DNS_PKT_OVER_BUDGET:
		dns_debug_inc(DNS_DBG_PACKET_OVER_BUDGET);
		return;
	case DNS_PKT_LEN_BAD:
	default:
		dns_debug_inc(DNS_DBG_PACKET_LEN_BAD);
		return;
	}

	if (send) {
		client = meta.saddr;
		resolver = meta.daddr;
		req_key.client_port = meta.sport;
		req_key.resolver_port = meta.dport;
	} else {
		client = meta.daddr;
		resolver = meta.saddr;
		req_key.client_port = meta.dport;
		req_key.resolver_port = meta.sport;
	}
	req_key.family = meta.family;
	req_key.client_addr[0] = client[0];
	req_key.client_addr[1] = client[1];
	req_key.client_addr[2] = client[2];
	req_key.client_addr[3] = client[3];
	req_key.resolver_addr[0] = resolver[0];
	req_key.resolver_addr[1] = resolver[1];
	req_key.resolver_addr[2] = resolver[2];
	req_key.resolver_addr[3] = resolver[3];
	req_key.netns_cookie = bpf_get_netns_cookie(skb);

	if (send)
		dns_parse_query_payload(skb, meta.dns_off, meta.dns_end,
					&req_key);
	else
		dns_parse_response_payload(skb, meta.dns_off, meta.dns_end,
					   &req_key);
}
