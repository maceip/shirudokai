// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Host unit tests for the shared DNS wire parser in
 * upatches/kernel-obs/obs_dns_parse.h under ASan/UBSan.
 */

#include <errno.h>
#include <string.h>

#include "malloc.h"
#include "unit.h"
#include "../upatches/kernel-obs/obs_dns_parse.h"

struct sim_dns_slot {
	bool			used;
	__u64			order;
	struct dns_request_key	key;
	struct dns_request	req;
};

struct sim_dns_state {
	struct sim_dns_slot	slots[16];
	__u32			capacity;
	__u64			clock_seq;
	__u64			dbg[DNS_DBG_MAX];
	__u32			recorded;
	struct dns_key		last_ip;
	char			last_name[DNS_NAME_BYTES];
};

static void put_be16_at(__u8 *p, __u16 v)
{
	p[0] = (__u8)(v >> 8);
	p[1] = (__u8)v;
}

static size_t build_ipv4_udp(__u8 *buf, const __u8 *dns, size_t dns_len,
			     __u16 sport, __u16 dport, __u16 frag_off,
			     __u8 proto, int override_udp_len,
			     int override_tot_len)
{
	size_t udp_len = 8 + dns_len;
	size_t tot_len = 20 + udp_len;

	memset(buf, 0, 28);
	buf[0] = 0x45;
	put_be16_at(buf + 2, (__u16)(override_tot_len >= 0 ?
				     (size_t)override_tot_len : tot_len));
	put_be16_at(buf + 6, frag_off);
	buf[8] = 64;
	buf[9] = proto;
	if (sport == 53) {
		buf[12] = 198;
		buf[13] = 51;
		buf[14] = 100;
		buf[15] = 53;
		buf[16] = 192;
		buf[17] = 0;
		buf[18] = 2;
		buf[19] = 10;
	} else {
		buf[12] = 192;
		buf[13] = 0;
		buf[14] = 2;
		buf[15] = 10;
		buf[16] = 198;
		buf[17] = 51;
		buf[18] = 100;
		buf[19] = 53;
	}

	put_be16_at(buf + 20, sport);
	put_be16_at(buf + 22, dport);
	put_be16_at(buf + 24, (__u16)(override_udp_len >= 0 ?
				      (size_t)override_udp_len : udp_len));
	if (dns_len)
		memcpy(buf + 28, dns, dns_len);
	return tot_len;
}

static size_t build_ipv6_udp(__u8 *buf, const __u8 *dns, size_t dns_len,
			     __u16 sport, __u16 dport, __u8 nexthdr,
			     int override_payload_len)
{
	size_t udp_len = 8 + dns_len;

	memset(buf, 0, 48);
	buf[0] = 0x60;
	put_be16_at(buf + 4, (__u16)(override_payload_len >= 0 ?
				     (size_t)override_payload_len : udp_len));
	buf[6] = nexthdr;
	buf[7] = 64;
	buf[8] = 0x20;
	buf[9] = 0x01;
	buf[10] = 0x0d;
	buf[11] = 0xb8;
	buf[23] = 1;
	buf[24] = 0x20;
	buf[25] = 0x01;
	buf[26] = 0x0d;
	buf[27] = 0xb8;
	buf[39] = 53;

	put_be16_at(buf + 40, sport);
	put_be16_at(buf + 42, dport);
	put_be16_at(buf + 44, (__u16)udp_len);
	if (dns_len)
		memcpy(buf + 48, dns, dns_len);
	return 40 + udp_len;
}

static size_t put_wire_labels(__u8 *dst, const char *dotted)
{
	const char *p = dotted;
	size_t off = 0;

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t n = dot ? (size_t)(dot - p) : strlen(p);

		dst[off++] = (__u8)n;
		memcpy(dst + off, p, n);
		off += n;
		if (!dot)
			break;
		p = dot + 1;
	}
	dst[off++] = 0;
	return off;
}

/*
 * Allocate an exact-sized heap copy so AddressSanitizer catches any 1-byte
 * read past data_end.
 */
static __u8 *alloc_exact_pkt(const __u8 *raw, size_t len,
			     const __u8 **data_out, const __u8 **end_out)
{
	__u8 *copy = xmalloc(len);

	ASSERT_TRUE(copy);
	if (len)
		memcpy(copy, raw, len);
	*data_out = copy;
	*end_out = copy + len;
	return copy;
}

static void sim_key_from_meta(const struct dns_pkt_meta *meta, bool send,
			      __u16 id, struct dns_request_key *key)
{
	const __u32 *client = send ? meta->saddr : meta->daddr;
	const __u32 *resolver = send ? meta->daddr : meta->saddr;

	memset(key, 0, sizeof(*key));
	key->netns_cookie = 1001;
	key->family = meta->family;
	memcpy(key->client_addr, client, sizeof(key->client_addr));
	memcpy(key->resolver_addr, resolver, sizeof(key->resolver_addr));
	key->client_port = send ? meta->sport : meta->dport;
	key->resolver_port = send ? meta->dport : meta->sport;
	key->id = id;
}

static int sim_find_slot(struct sim_dns_state *st,
			 const struct dns_request_key *key)
{
	__u32 i;

	for (i = 0; i < st->capacity; i++) {
		if (st->slots[i].used &&
		    memcmp(&st->slots[i].key, key, sizeof(*key)) == 0)
			return (int)i;
	}
	return -1;
}

static void sim_delete_slot(struct sim_dns_state *st,
			    const struct dns_request_key *key)
{
	int idx = sim_find_slot(st, key);

	if (idx >= 0) {
		st->slots[idx].used = false;
		if (st->dbg[DNS_DBG_REQ_LIVE] > 0)
			st->dbg[DNS_DBG_REQ_LIVE]--;
	}
}

static void sim_insert_req(struct sim_dns_state *st,
			   const struct dns_request_key *key,
			   const struct dns_request *req, __u64 now_ns)
{
	int idx = sim_find_slot(st, key);
	__u32 i;

	if (idx >= 0) {
		if (!dns_is_req_stale(&st->slots[idx].req, now_ns))
			return;
		st->dbg[DNS_DBG_RESP_STALE]++;
		sim_delete_slot(st, key);
	}
	for (i = 0; i < st->capacity; i++) {
		if (!st->slots[i].used) {
			st->slots[i].used = true;
			st->slots[i].order = ++st->clock_seq;
			st->slots[i].key = *key;
			st->slots[i].req = *req;
			st->dbg[DNS_DBG_REQ_LIVE]++;
			st->dbg[DNS_DBG_QUERY_STORED]++;
			return;
		}
	}
	/* Simulate BPF_MAP_TYPE_LRU_HASH displacing the oldest entry. */
	idx = 0;
	for (i = 1; i < st->capacity; i++) {
		if (st->slots[i].order < st->slots[idx].order)
			idx = (int)i;
	}
	st->slots[idx].order = ++st->clock_seq;
	st->slots[idx].key = *key;
	st->slots[idx].req = *req;
	st->dbg[DNS_DBG_REQ_LRU_EVICT]++;
	st->dbg[DNS_DBG_QUERY_STORED]++;
}

static void sim_process_packet(struct sim_dns_state *st, __u16 ethertype,
			       const __u8 *raw, size_t raw_len, bool send,
			       __u64 now_ns)
{
	const __u8 *data = NULL, *data_end = NULL;
	struct dns_pkt_meta meta = {};
	struct dns_request_key rkey = {};
	enum dns_pkt_verdict v;
	__u8 *heap_pkt;

	if (ethertype == ETH_P_IP)
		st->dbg[DNS_DBG_PACKET_IPV4]++;
	else if (ethertype == ETH_P_IPV6)
		st->dbg[DNS_DBG_PACKET_IPV6]++;
	else
		return;

	heap_pkt = alloc_exact_pkt(raw, raw_len, &data, &data_end);
	v = dns_validate_packet(data, data_end, (__u32)raw_len, ethertype,
				send, &meta);
	if (v != DNS_PKT_OK) {
		if (v == DNS_PKT_FRAGMENT)
			st->dbg[DNS_DBG_PACKET_FRAGMENT]++;
		else if (v == DNS_PKT_IPV6_EXT)
			st->dbg[DNS_DBG_PACKET_IPV6_EXT]++;
		else if (v == DNS_PKT_NOT_UDP)
			st->dbg[DNS_DBG_PACKET_NOT_UDP]++;
		else if (v == DNS_PKT_PORT_SKIP)
			st->dbg[DNS_DBG_PACKET_PORT_SKIP]++;
		else if (v == DNS_PKT_OVER_BUDGET)
			st->dbg[DNS_DBG_PACKET_OVER_BUDGET]++;
		else
			st->dbg[DNS_DBG_PACKET_LEN_BAD]++;
		xfree(heap_pkt, raw_len);
		return;
	}

	if (send) {
		__u16 id, flags, qdcount, qtype, qclass;
		struct dns_request req = {};
		__u32 pos, next = 0;
		int step, replaced = 0;

		st->dbg[DNS_DBG_QUERY_PACKET]++;
		if (!dns_hdr_bounded(data, data_end, meta.dns_off,
				     meta.dns_end) ||
		    !dns_read_u16_bounded(data, data_end, meta.dns_off,
					  meta.dns_end, &id) ||
		    !dns_read_u16_bounded(data, data_end, meta.dns_off + 2,
					  meta.dns_end, &flags) ||
		    !dns_read_u16_bounded(data, data_end, meta.dns_off + 4,
					  meta.dns_end, &qdcount)) {
			st->dbg[DNS_DBG_QUERY_HDR_FAIL]++;
			goto out;
		}
		if (flags & DNS_FLAG_QR) {
			st->dbg[DNS_DBG_QUERY_IS_RESPONSE]++;
			goto out;
		}
		if (flags & DNS_OPCODE_MASK) {
			st->dbg[DNS_DBG_QUERY_BAD_OPCODE]++;
			goto out;
		}
		if (qdcount != 1) {
			st->dbg[DNS_DBG_QUERY_QDCOUNT_BAD]++;
			goto out;
		}
		pos = meta.dns_off + sizeof(struct dns_hdr);
		for (step = 0; step < DNS_MAX_NAME_STEPS; step++) {
			int c = dns_parse_label_into(data, data_end, pos,
						     meta.dns_off + sizeof(struct dns_hdr),
						     meta.dns_end, req.name);

			if (c < 0) {
				st->dbg[DNS_DBG_QUERY_NAME_FAIL]++;
				goto out;
			}
			if (c == 0) {
				next = pos + 1;
				break;
			}
			replaced |= c & DNS_NAME_REPLACED;
			c &= ~DNS_NAME_REPLACED;
			pos += (__u32)c;
			if (pos - (meta.dns_off + sizeof(struct dns_hdr)) >=
			    DNS_MAX_WIRE_NAME_BYTES) {
				st->dbg[DNS_DBG_QUERY_NAME_FAIL]++;
				goto out;
			}
		}
		if (!next) {
			st->dbg[DNS_DBG_QUERY_NAME_FAIL]++;
			goto out;
		}
		if (replaced)
			st->dbg[DNS_DBG_QUERY_NAME_REPLACED]++;
		if (!req.name[0]) {
			st->dbg[DNS_DBG_QUERY_EMPTY_NAME]++;
			goto out;
		}
		if (!dns_read_u16_bounded(data, data_end, next, meta.dns_end,
					  &qtype) ||
		    !dns_read_u16_bounded(data, data_end, next + 2,
					  meta.dns_end, &qclass)) {
			st->dbg[DNS_DBG_QUERY_QTYPE_READ_FAIL]++;
			goto out;
		}
		if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
			st->dbg[DNS_DBG_QUERY_QTYPE_UNSUPPORTED]++;
			goto out;
		}
		if (qclass != DNS_CLASS_IN) {
			st->dbg[DNS_DBG_QUERY_QCLASS_UNSUPPORTED]++;
			goto out;
		}
		req.sent_ns = now_ns;
		req.qtype = qtype;
		req.qclass = qclass;
		sim_key_from_meta(&meta, true, id, &rkey);
		sim_insert_req(st, &rkey, &req, now_ns);
	} else {
		__u16 id, flags, qdcount, ancount, qtype, qclass;
		struct dns_request req_copy;
		bool bad_flags = false;
		__u32 off, next = 0;
		int slot, qrc, i;

		st->dbg[DNS_DBG_RESP_PACKET]++;
		if (!dns_hdr_bounded(data, data_end, meta.dns_off,
				     meta.dns_end) ||
		    !dns_read_u16_bounded(data, data_end, meta.dns_off,
					  meta.dns_end, &id) ||
		    !dns_read_u16_bounded(data, data_end, meta.dns_off + 2,
					  meta.dns_end, &flags) ||
		    !dns_read_u16_bounded(data, data_end, meta.dns_off + 4,
					  meta.dns_end, &qdcount) ||
		    !dns_read_u16_bounded(data, data_end, meta.dns_off + 6,
					  meta.dns_end, &ancount)) {
			st->dbg[DNS_DBG_RESP_HDR_FAIL]++;
			goto out;
		}
		if (!(flags & DNS_FLAG_QR)) {
			st->dbg[DNS_DBG_RESP_NOT_RESPONSE]++;
			goto out;
		}
		if (flags & DNS_OPCODE_MASK) {
			st->dbg[DNS_DBG_RESP_BAD_OPCODE]++;
			bad_flags = true;
		}
		if (flags & DNS_FLAG_TC) {
			st->dbg[DNS_DBG_RESP_TRUNCATED]++;
			bad_flags = true;
		}
		if (flags & DNS_RCODE_MASK) {
			st->dbg[DNS_DBG_RESP_BAD_RCODE]++;
			bad_flags = true;
		}
		if (qdcount != 1) {
			st->dbg[DNS_DBG_RESP_QDCOUNT_BAD]++;
			goto out;
		}
		sim_key_from_meta(&meta, false, id, &rkey);
		slot = sim_find_slot(st, &rkey);
		if (slot < 0) {
			if (!bad_flags && ancount == 0)
				st->dbg[DNS_DBG_RESP_NO_ANSWER]++;
			else if (!bad_flags)
				st->dbg[DNS_DBG_RESP_REQ_MISS]++;
			goto out;
		}
		req_copy = st->slots[slot].req;
		if (dns_is_req_stale(&req_copy, now_ns)) {
			st->dbg[DNS_DBG_RESP_STALE]++;
			sim_delete_slot(st, &rkey);
			st->dbg[DNS_DBG_RESP_DELETE]++;
			goto out;
		}
		qrc = dns_match_qname_bounded(data, data_end, meta.dns_off,
					      meta.dns_end,
					      meta.dns_off + sizeof(struct dns_hdr),
					      req_copy.name, &next);
		if (qrc < 0) {
			if (qrc == -EBADMSG)
				st->dbg[DNS_DBG_RESP_QNAME_MISMATCH]++;
			else
				st->dbg[DNS_DBG_RESP_QNAME_SKIP_FAIL]++;
			goto out;
		}
		if (!dns_read_u16_bounded(data, data_end, next, meta.dns_end,
					  &qtype) ||
		    !dns_read_u16_bounded(data, data_end, next + 2,
					  meta.dns_end, &qclass)) {
			st->dbg[DNS_DBG_RESP_QTYPE_READ_FAIL]++;
			goto out;
		}
		if (qtype != req_copy.qtype) {
			st->dbg[DNS_DBG_RESP_QTYPE_MISMATCH]++;
			goto out;
		}
		if (qclass != DNS_CLASS_IN ||
		    qclass != req_copy.qclass) {
			st->dbg[DNS_DBG_RESP_QCLASS_MISMATCH]++;
			goto out;
		}
		sim_delete_slot(st, &rkey);
		st->dbg[DNS_DBG_RESP_DELETE]++;
		if (bad_flags)
			goto out;
		if (ancount == 0) {
			st->dbg[DNS_DBG_RESP_NO_ANSWER]++;
			goto out;
		}
		off = next + 4;
		for (i = 0; i < DNS_MAX_ANSWERS && i < ancount; i++) {
			struct dns_key ip = {};
			__u32 rr_next = 0, rdata_off;
			__u16 rtype, rclass, rdlen;
			int arc;

			st->dbg[DNS_DBG_RESP_ANSWER_SEEN]++;
			if (dns_skip_name_bounded(data, data_end, meta.dns_off,
						  meta.dns_end, off,
						  &rr_next) < 0) {
				st->dbg[DNS_DBG_RESP_ANSWER_SKIP_FAIL]++;
				break;
			}
			if (!dns_read_u16_bounded(data, data_end, rr_next,
						  meta.dns_end, &rtype) ||
			    !dns_read_u16_bounded(data, data_end, rr_next + 2,
						  meta.dns_end, &rclass) ||
			    !dns_read_u16_bounded(data, data_end, rr_next + 8,
						  meta.dns_end, &rdlen)) {
				st->dbg[DNS_DBG_RESP_RR_READ_FAIL]++;
				break;
			}
			rdata_off = rr_next + 10;
			if (rdata_off > meta.dns_end ||
			    rdlen > meta.dns_end - rdata_off) {
				st->dbg[DNS_DBG_RESP_RDATA_BOUNDS_FAIL]++;
				break;
			}
			arc = dns_extract_answer_addr(data, data_end, rdata_off,
						      meta.dns_end,
						      req_copy.qtype,
						      rtype, rclass, rdlen,
						      &ip);
			if (arc < 0) {
				st->dbg[DNS_DBG_RESP_RDATA_BOUNDS_FAIL]++;
				break;
			}
			if (arc == 0) {
				st->dbg[DNS_DBG_RESP_ADDR_UNSUPPORTED]++;
			} else {
				st->dbg[DNS_DBG_RESP_ADDR_PARSED]++;
				st->dbg[DNS_DBG_RESP_TOUCH]++;
				st->recorded++;
				st->last_ip = ip;
				memcpy(st->last_name, req_copy.name,
				       sizeof(st->last_name));
			}
			off = rdata_off + rdlen;
		}
		if (i == DNS_MAX_ANSWERS && ancount > DNS_MAX_ANSWERS)
			st->dbg[DNS_DBG_RESP_ANSWER_CAP]++;
	}
out:
	xfree(heap_pkt, raw_len);
}

static size_t make_dns_query(__u8 *dns, __u16 txid, __u16 flags,
			     const char *name, __u16 qtype, __u16 qclass)
{
	size_t off = 12;

	memset(dns, 0, 12);
	put_be16_at(dns + 0, txid);
	put_be16_at(dns + 2, flags);
	put_be16_at(dns + 4, 1);
	off += put_wire_labels(dns + off, name);
	put_be16_at(dns + off, qtype);
	put_be16_at(dns + off + 2, qclass);
	return off + 4;
}

static size_t append_rr(__u8 *dns, size_t off, const __u8 *owner,
			size_t owner_len, __u16 rtype, __u16 rclass,
			const __u8 *rdata, __u16 rdlen)
{
	memcpy(dns + off, owner, owner_len);
	off += owner_len;
	put_be16_at(dns + off, rtype);
	put_be16_at(dns + off + 2, rclass);
	put_be16_at(dns + off + 4, 0);
	put_be16_at(dns + off + 6, 60);
	put_be16_at(dns + off + 8, rdlen);
	off += 10;
	if (rdata && rdlen)
		memcpy(dns + off, rdata, rdlen);
	return off + rdlen;
}

static void transport_fragments_ext_headers_and_budget(void)
{
	struct sim_dns_state st = { .capacity = 4 };
	__u8 dns[1400] = {}, raw[1500] = {};
	size_t dns_len, pkt_len;

	dns_len = make_dns_query(dns, 0x1001, 0x0100, "example.com",
				 DNS_TYPE_A, DNS_CLASS_IN);

	/* IPv4 MF fragment and non-zero fragment offset are rejected. */
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 40000, 53, 0x2000,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 40000, 53, 0x0001,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_PACKET_FRAGMENT], 2u);
	EXPECT_UEQ(st.dbg[DNS_DBG_QUERY_STORED], 0u);

	/* IPv6 extension headers (Fragment=44, HopOpts=0) are rejected. */
	pkt_len = build_ipv6_udp(raw, dns, dns_len, 40000, 53,
				 IPPROTO_FRAGMENT, -1);
	sim_process_packet(&st, ETH_P_IPV6, raw, pkt_len, true, 1000);
	pkt_len = build_ipv6_udp(raw, dns, dns_len, 40000, 53,
				 IPPROTO_HOPOPTS, -1);
	sim_process_packet(&st, ETH_P_IPV6, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_PACKET_IPV6_EXT], 2u);

	/* IPv6 TCP (6) counts as NOT_UDP rather than IPV6_EXT. */
	pkt_len = build_ipv6_udp(raw, dns, 4, 40000, 53, 6, -1);
	sim_process_packet(&st, ETH_P_IPV6, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_PACKET_NOT_UDP], 1u);

	/* UDP declared length shorter than DNS payload is rejected. */
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 40000, 53, 0,
				 IPPROTO_UDP, 8, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_QUERY_HDR_FAIL], 1u);

	/* UDP declared length exceeding IP tot_len is rejected at L4 check. */
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 40000, 53, 0,
				 IPPROTO_UDP, 200, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_PACKET_LEN_BAD], 1u);

	/* Exact 1232-byte UDP packet passes budget; 1233-byte UDP fails. */
	pkt_len = build_ipv4_udp(raw, dns, 1224, 40000, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_QUERY_STORED], 1u);

	pkt_len = build_ipv4_udp(raw, dns, 1225, 40001, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_PACKET_OVER_BUDGET], 1u);
}

static void qname_case_qclass_flags_and_rr_type_matching(void)
{
	const __u8 v4_addr[4] = { 192, 0, 2, 44 };
	const __u8 v6_addr[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x44,
	};
	const __u8 ptr_qname[2] = { 0xc0, 0x0c };
	struct sim_dns_state st = { .capacity = 8 };
	__u8 dns[512] = {}, raw[600] = {};
	size_t dns_len, pkt_len;

	/* Non-IN query class and non-zero query opcode are rejected. */
	dns_len = make_dns_query(dns, 0x2001, 0x0100, "example.com",
				 DNS_TYPE_A, 3);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 41000, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_QUERY_QCLASS_UNSUPPORTED], 1u);

	dns_len = make_dns_query(dns, 0x2002, 0x0900, "example.com",
				 DNS_TYPE_A, DNS_CLASS_IN);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 41000, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	EXPECT_UEQ(st.dbg[DNS_DBG_QUERY_BAD_OPCODE], 1u);

	/* Store mixed-case A query; forged QNAME & QCLASS do not consume it. */
	dns_len = make_dns_query(dns, 0x2003, 0x0100, "Api.ExAmPlE.CoM",
				 DNS_TYPE_A, DNS_CLASS_IN);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 41000, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);
	ASSERT_UEQ(st.dbg[DNS_DBG_QUERY_STORED], 1u);

	/* Forged response with different QNAME leaves pending query intact. */
	dns_len = make_dns_query(dns, 0x2003, 0x8180, "evil.example.com",
				 DNS_TYPE_A, DNS_CLASS_IN);
	put_be16_at(dns + 6, 1);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    DNS_CLASS_IN, v4_addr, 4);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 41000, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 2000);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_QNAME_MISMATCH], 1u);
	EXPECT_UEQ(st.recorded, 0u);

	/* Response with wrong QCLASS is rejected without poisoning table. */
	dns_len = make_dns_query(dns, 0x2003, 0x8180, "api.example.com",
				 DNS_TYPE_A, 3);
	put_be16_at(dns + 6, 1);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    DNS_CLASS_IN, v4_addr, 4);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 41000, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 2000);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_QCLASS_MISMATCH], 1u);
	EXPECT_UEQ(st.recorded, 0u);

	/*
	 * Genuine case-insensitive response carrying an AAAA RR + CHAOS A RR +
	 * IN A RR records ONLY the IN A RR matching the A query!
	 */
	dns_len = make_dns_query(dns, 0x2003, 0x8180, "api.example.com",
				 DNS_TYPE_A, DNS_CLASS_IN);
	put_be16_at(dns + 6, 3);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_AAAA,
			    DNS_CLASS_IN, v6_addr, 16);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    3, v4_addr, 4);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    DNS_CLASS_IN, v4_addr, 4);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 41000, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 2500);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_ADDR_UNSUPPORTED], 2u);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_ADDR_PARSED], 1u);
	EXPECT_UEQ(st.recorded, 1u);
	EXPECT_EQ(st.last_ip.family, AF_INET);
	EXPECT_MEMEQ(&st.last_ip.addr[0], v4_addr, 4);

	/* Truncated (TC=1), bad OPCODE and NXDOMAIN (RCODE=3) never record. */
	dns_len = make_dns_query(dns, 0x2004, 0x0100, "tc.example.com",
				 DNS_TYPE_A, DNS_CLASS_IN);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 41001, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 3000);

	dns_len = make_dns_query(dns, 0x2004, 0x8380, "tc.example.com",
				 DNS_TYPE_A, DNS_CLASS_IN);
	put_be16_at(dns + 6, 1);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    DNS_CLASS_IN, v4_addr, 4);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 41001, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 3100);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_TRUNCATED], 1u);
	EXPECT_UEQ(st.recorded, 1u);

	dns_len = make_dns_query(dns, 0x2005, 0x0100, "nx.example.com",
				 DNS_TYPE_AAAA, DNS_CLASS_IN);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 41002, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 4000);

	dns_len = make_dns_query(dns, 0x2005, 0x8983, "nx.example.com",
				 DNS_TYPE_AAAA, DNS_CLASS_IN);
	put_be16_at(dns + 6, 1);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_AAAA,
			    DNS_CLASS_IN, v6_addr, 16);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 41002, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 4100);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_BAD_OPCODE], 1u);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_BAD_RCODE], 1u);
	EXPECT_UEQ(st.recorded, 1u);
}

static void compression_pointers_ttl_lru_and_answer_cap(void)
{
	const __u8 v4_addr[4] = { 198, 51, 100, 9 };
	const __u8 ptr_self[2] = { 0xc0, 0x1d };
	const __u8 ptr_hdr[2] = { 0xc0, 0x04 };
	const __u8 ptr_oob[2] = { 0xc3, 0xff };
	const __u8 ptr_qname[2] = { 0xc0, 0x0c };
	struct sim_dns_state st = { .capacity = 2 };
	__u8 dns[1300] = {}, raw[1400] = {};
	size_t dns_len, pkt_len;
	int i;

	/* Bad compression pointers (header target, OOB target, self-loop). */
	for (i = 0; i < 3; i++) {
		const __u8 *bad_owner = i == 0 ? ptr_hdr :
					i == 1 ? ptr_oob : ptr_self;

		dns_len = make_dns_query(dns, (__u16)(0x3000 + i), 0x0100,
					 "ptr.example", DNS_TYPE_A,
					 DNS_CLASS_IN);
		pkt_len = build_ipv4_udp(raw, dns, dns_len, 42000, 53, 0,
					 IPPROTO_UDP, -1, -1);
		sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);

		dns_len = make_dns_query(dns, (__u16)(0x3000 + i), 0x8180,
					 "ptr.example", DNS_TYPE_A,
					 DNS_CLASS_IN);
		put_be16_at(dns + 6, 1);
		/* Offset 0x1d is exact start of answer owner for ptr.example. */
		ASSERT_UEQ(dns_len, 0x1du);
		dns_len = append_rr(dns, dns_len, bad_owner, 2, DNS_TYPE_A,
				    DNS_CLASS_IN, v4_addr, 4);
		pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 42000, 0,
					 IPPROTO_UDP, -1, -1);
		sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 1500);
	}
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_ANSWER_SKIP_FAIL], 3u);
	EXPECT_UEQ(st.recorded, 0u);

	/* Stale pending request (> 10s TTL) is rejected and counted. */
	memset(&st, 0, sizeof(st));
	st.capacity = 2;
	dns_len = make_dns_query(dns, 0x4001, 0x0100, "ttl.example",
				 DNS_TYPE_A, DNS_CLASS_IN);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 43000, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 1000);

	dns_len = make_dns_query(dns, 0x4001, 0x8180, "ttl.example",
				 DNS_TYPE_A, DNS_CLASS_IN);
	put_be16_at(dns + 6, 1);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    DNS_CLASS_IN, v4_addr, 4);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 43000, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false,
			   1000 + DNS_REQ_TTL_NS + 1);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_STALE], 1u);
	EXPECT_UEQ(st.recorded, 0u);

	/*
	 * Duplicate in-flight query (same tuple/txid) is ignored without
	 * incrementing DNS_DBG_REQ_TABLE_FULL or DNS_DBG_REQ_LRU_EVICT;
	 * stale duplicate replaces the entry; third distinct query on a
	 * 2-slot LRU table displaces the oldest entry (0x5000) and counts
	 * DNS_DBG_REQ_LRU_EVICT.
	 */
	EXPECT_UEQ(DNS_MAX_NAME_STEPS, 144);
	dns_len = make_dns_query(dns, 0x5000, 0x0100, "dup.example",
				 DNS_TYPE_A, DNS_CLASS_IN);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 44000, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 5000);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 5500);
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_TABLE_FULL], 0u);
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_LRU_EVICT], 0u);
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_LIVE], 1u);

	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true,
			   5000 + DNS_REQ_TTL_NS + 1);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_STALE], 2u);
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_LIVE], 1u);

	for (i = 1; i <= 2; i++) {
		dns_len = make_dns_query(dns, (__u16)(0x5000 + i), 0x0100,
					 "full.example", DNS_TYPE_A,
					 DNS_CLASS_IN);
		pkt_len = build_ipv4_udp(raw, dns, dns_len, 44000, 53, 0,
					 IPPROTO_UDP, -1, -1);
		sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 6000);
	}
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_LIVE], 2u);
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_LRU_EVICT], 1u);
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_TABLE_FULL], 0u);

	/* Evicted 0x5000 misses; live 0x5002 resolves and decrements LIVE. */
	dns_len = make_dns_query(dns, 0x5000, 0x8180, "dup.example",
				 DNS_TYPE_A, DNS_CLASS_IN);
	put_be16_at(dns + 6, 1);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    DNS_CLASS_IN, v4_addr, 4);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 44000, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 6050);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_REQ_MISS], 1u);

	dns_len = make_dns_query(dns, 0x5002, 0x8180, "full.example",
				 DNS_TYPE_A, DNS_CLASS_IN);
	put_be16_at(dns + 6, 1);
	dns_len = append_rr(dns, dns_len, ptr_qname, 2, DNS_TYPE_A,
			    DNS_CLASS_IN, v4_addr, 4);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 44000, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 6050);
	EXPECT_UEQ(st.dbg[DNS_DBG_REQ_LIVE], 1u);
	EXPECT_UEQ(st.recorded, 1u);

	/* Answers past DNS_MAX_ANSWERS (75): 75 parsed, cap counter incremented. */
	memset(&st, 0, sizeof(st));
	st.capacity = 4;
	dns_len = make_dns_query(dns, 0x6001, 0x0100, "a", DNS_TYPE_A,
				 DNS_CLASS_IN);
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 45000, 53, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, true, 6000);

	dns_len = make_dns_query(dns, 0x6001, 0x8180, "a", DNS_TYPE_A,
				 DNS_CLASS_IN);
	put_be16_at(dns + 6, 76);
	for (i = 0; i < 76; i++) {
		const __u8 txt_one[1] = {};

		/* 13-byte TXT RR * 76 = 988 bytes -> fits inside 1232 UDP budget! */
		dns_len = append_rr(dns, dns_len, ptr_qname, 2, 16,
				    DNS_CLASS_IN, txt_one, 1);
	}
	pkt_len = build_ipv4_udp(raw, dns, dns_len, 53, 45000, 0,
				 IPPROTO_UDP, -1, -1);
	sim_process_packet(&st, ETH_P_IP, raw, pkt_len, false, 6100);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_ANSWER_SEEN], 75u);
	EXPECT_UEQ(st.dbg[DNS_DBG_RESP_ANSWER_CAP], 1u);
}

static const struct unit_case cases[] = {
	UNIT_CASE(transport_fragments_ext_headers_and_budget),
	UNIT_CASE(qname_case_qclass_flags_and_rr_type_matching),
	UNIT_CASE(compression_pointers_ttl_lru_and_answer_cap),
	{}
};

UNIT_SUITE(dns_obs, cases);
