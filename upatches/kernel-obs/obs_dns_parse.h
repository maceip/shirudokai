/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Wire-level IPv4/IPv6/UDP and DNS message parser shared by
 * upatches/kernel-obs/obs_dns.bpf.c and host unit tests
 * (testing/unit/dns_obs.c).
 */

#ifndef KERNEL_OBS_DNS_PARSE_H
#define KERNEL_OBS_DNS_PARSE_H

#ifdef __bpf__
#define DNS_INLINE	static __always_inline
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <shirudo/misc.h>

#define DNS_INLINE	static inline

#ifndef AF_INET
#define AF_INET		2
#endif
#ifndef AF_INET6
#define AF_INET6	10
#endif
#ifndef ETH_P_IP
#define ETH_P_IP	0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6	0x86DD
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP	17
#endif

#ifndef barrier_var
#define barrier_var(var)	__asm__ __volatile__("" : "+r"(var))
#endif

struct obs_exe {
	__u64	ino;
	__u32	dev;
	__u32	_pad;
};

struct obs_ident {
	struct obs_exe	exe;
	__u64		cgroup;
};
#endif /* __bpf__ */

#ifndef EBADMSG
#define EBADMSG		74
#endif
#ifndef EEXIST
#define EEXIST		17
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS		0
#define IPPROTO_ROUTING		43
#define IPPROTO_FRAGMENT	44
#define IPPROTO_ESP		50
#define IPPROTO_AH		51
#define IPPROTO_DSTOPTS		60
#define IPPROTO_MH		135
#endif
#ifndef IPPROTO_HIP
#define IPPROTO_HIP		139
#endif
#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6		140
#endif

#define DNS_PORT		53
#define DNS_TYPE_A		1
#define DNS_TYPE_AAAA		28
#define DNS_CLASS_IN		1

#define DNS_FLAG_QR		0x8000u
#define DNS_OPCODE_MASK		0x7800u
#define DNS_FLAG_TC		0x0200u
#define DNS_RCODE_MASK		0x000fu

#define DNS_REQ_TTL_NS		10000000000ULL

#define DNS_MAX_NAMES_PER_IP	4
#define DNS_MAX_NAME_CHARS	255
#define DNS_NAME_BYTES		(DNS_MAX_NAME_CHARS + 1)
#define DNS_MAX_WIRE_NAME_BYTES	255
#define DNS_MAX_LABEL_BYTES	63
#define DNS_MAX_LABELS		127
#define DNS_MAX_JUMPS		16
#define DNS_MAX_NAME_STEPS	(DNS_MAX_LABELS + 1 + DNS_MAX_JUMPS)
/* A 1232-byte UDP response can hold at most 75 minimal 16-byte A answers. */
#define DNS_MAX_ANSWERS		75
#define DNS_MAX_UDP_BYTES	1232
#define DNS_MAX_IP_HEADER_BYTES	60
#define DNS_MAX_PACKET_BYTES	(DNS_MAX_UDP_BYTES + DNS_MAX_IP_HEADER_BYTES)
#define DNS_REQ_MAP_ENTRIES	1024
#define DNS_COMPRESSED_MASK	0xc0
/* Set in what the label and name parsers return, above any label's length. */
#define DNS_NAME_REPLACED	0x100

/*
 * Indices 0..41 remain fixed so existing packet-matrix counter ordinals stay
 * compatible; new counters append after DNS_DBG_PACKET_PORT_SKIP.
 */
enum dns_debug_counter {
	DNS_DBG_QUERY_PACKET,
	DNS_DBG_QUERY_NO_UID,
	DNS_DBG_QUERY_HDR_FAIL,
	DNS_DBG_QUERY_IS_RESPONSE,
	DNS_DBG_QUERY_QDCOUNT_BAD,
	DNS_DBG_QUERY_SCRATCH_MISS,
	DNS_DBG_QUERY_NAME_FAIL,
	DNS_DBG_QUERY_NAME_REPLACED,
	DNS_DBG_QUERY_EMPTY_NAME,
	DNS_DBG_QUERY_QTYPE_READ_FAIL,
	DNS_DBG_QUERY_QTYPE_UNSUPPORTED,
	DNS_DBG_QUERY_STORED,
	DNS_DBG_RESP_PACKET,
	DNS_DBG_RESP_HDR_FAIL,
	DNS_DBG_RESP_NOT_RESPONSE,
	DNS_DBG_RESP_QDCOUNT_BAD,
	DNS_DBG_RESP_NO_ANSWER,
	DNS_DBG_RESP_REQ_MISS,
	DNS_DBG_RESP_QNAME_SKIP_FAIL,
	DNS_DBG_RESP_QTYPE_READ_FAIL,
	DNS_DBG_RESP_QTYPE_MISMATCH,
	DNS_DBG_RESP_ANSWER_SEEN,
	DNS_DBG_RESP_ANSWER_SKIP_FAIL,
	DNS_DBG_RESP_RR_READ_FAIL,
	DNS_DBG_RESP_RDATA_BOUNDS_FAIL,
	DNS_DBG_RESP_ADDR_UNSUPPORTED,
	DNS_DBG_RESP_ADDR_PARSED,
	DNS_DBG_RESP_TOUCH,
	DNS_DBG_RESP_DELETE,
	DNS_DBG_TOUCH_CALLED,
	DNS_DBG_TOUCH_INIT_FAIL,
	DNS_DBG_TOUCH_HIT,
	DNS_DBG_ALLOC_ATTEMPT,
	DNS_DBG_ALLOC_BAD_IDX,
	DNS_DBG_ALLOC_OK,
	DNS_DBG_ALLOC_ENTRY_MISS,
	DNS_DBG_CAS_OK,
	DNS_DBG_CAS_FAIL,
	DNS_DBG_PACKET_IPV4,
	DNS_DBG_PACKET_IPV6,
	DNS_DBG_PACKET_NOT_UDP,
	DNS_DBG_PACKET_PORT_SKIP,
	DNS_DBG_QUERY_BAD_OPCODE,
	DNS_DBG_QUERY_QCLASS_UNSUPPORTED,
	DNS_DBG_REQ_TABLE_FULL,
	DNS_DBG_REQ_LRU_EVICT,
	DNS_DBG_REQ_LIVE,
	DNS_DBG_RESP_BAD_OPCODE,
	DNS_DBG_RESP_BAD_RCODE,
	DNS_DBG_RESP_TRUNCATED,
	DNS_DBG_RESP_STALE,
	DNS_DBG_RESP_QNAME_MISMATCH,
	DNS_DBG_RESP_QCLASS_MISMATCH,
	DNS_DBG_RESP_ANSWER_CAP,
	DNS_DBG_PACKET_FRAGMENT,
	DNS_DBG_PACKET_LEN_BAD,
	DNS_DBG_PACKET_OVER_BUDGET,
	DNS_DBG_PACKET_IPV6_EXT,
	DNS_DBG_MAX,
};

struct dns_key {
	struct obs_ident	ident;
	__u8			family;
	__u8			_pad[7];
	__u32			addr[4];
};

struct dns_name {
	__u64	seen;
	__u64	last_ns;
	char	name[DNS_NAME_BYTES];
};

struct dns_val {
	__u64		count;
	__u64		first_ns;
	__u64		last_ns;
	struct dns_name	names[DNS_MAX_NAMES_PER_IP];
};

struct dns_request {
	struct obs_exe	exe;
	__u64		cgroup;
	__u64		sent_ns;
	char		name[DNS_NAME_BYTES];
	__u16		qtype;
	__u16		qclass;
	__u32		_pad;
};

/*
 * Canonical client-to-resolver tuple. Packet address and port bytes stay
 * in network order, so reversing an ingress response produces the query
 * key.
 */
struct dns_request_key {
	__u64	netns_cookie;
	__u32	client_addr[4];
	__u32	resolver_addr[4];
	__u16	id;
	__u16	client_port;
	__u16	resolver_port;
	__u8	family;
	__u8	_pad;
};

struct dns_scratch {
	struct dns_request	req;
	/* Tailroom lets the verifier bound a full final-label direct copy. */
	char			verifier_bounds[DNS_MAX_LABEL_BYTES];
};

struct dns_hdr {
	__u16	id;
	__u16	flags;
	__u16	qdcount;
	__u16	ancount;
	__u16	nscount;
	__u16	arcount;
};

enum dns_pkt_verdict {
	DNS_PKT_OK = 0,
	DNS_PKT_IGNORE,
	DNS_PKT_LEN_BAD,
	DNS_PKT_FRAGMENT,
	DNS_PKT_IPV6_EXT,
	DNS_PKT_NOT_UDP,
	DNS_PKT_PORT_SKIP,
	DNS_PKT_OVER_BUDGET,
};

struct dns_pkt_meta {
	__u8	family;
	__u8	_pad[3];
	__u16	sport;
	__u16	dport;
	__u32	saddr[4];
	__u32	daddr[4];
	__u32	dns_off;
	__u32	dns_end;
};

DNS_INLINE __u8 dns_ascii_lower(__u8 c)
{
	if (c >= 'A' && c <= 'Z')
		return (__u8)(c + ('a' - 'A'));
	return c;
}

/*
 * A label may hold any byte, but the recorded name is a C string with dots
 * between its labels: a NUL in a label would end the name there and a dot
 * would split the label in two, either recording another name than the
 * one resolved. Such a byte is recorded as '?', as is any other outside
 * printable ASCII, rather than the name refused, which would leave the
 * query unrecorded.
 */
DNS_INLINE bool dns_label_byte_recordable(__u8 byte)
{
	return byte > ' ' && byte <= '~' && byte != '.';
}

DNS_INLINE bool dns_is_ipv6_ext_hdr(__u8 nexthdr)
{
	return nexthdr == IPPROTO_HOPOPTS ||
	       nexthdr == IPPROTO_ROUTING ||
	       nexthdr == IPPROTO_FRAGMENT ||
	       nexthdr == IPPROTO_ESP ||
	       nexthdr == IPPROTO_AH ||
	       nexthdr == IPPROTO_DSTOPTS ||
	       nexthdr == IPPROTO_MH ||
	       nexthdr == IPPROTO_HIP ||
	       nexthdr == IPPROTO_SHIM6;
}

DNS_INLINE void dns_copy_raw_u32(const __u8 *src, __u32 *dst_word)
{
	__u8 *dst = (__u8 *)dst_word;

	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
}

DNS_INLINE bool dns_is_req_stale(const struct dns_request *req, __u64 now_ns)
{
	if (!req)
		return true;
	return now_ns > req->sent_ns && (now_ns - req->sent_ns) > DNS_REQ_TTL_NS;
}

/*
 * Validate IPv4/IPv6 and UDP headers directly against the packet bounds,
 * rejecting IPv4 fragments, IPv6 extension headers, inconsistent IP/UDP
 * lengths, non-53 ports, and UDP datagrams exceeding the 1232-byte budget.
 */
DNS_INLINE enum dns_pkt_verdict
dns_validate_packet(const __u8 *data, const __u8 *data_end, __u32 wire_len,
		    __u16 ethertype, bool send, struct dns_pkt_meta *meta)
{
	__u32 l4_off = 0, ip_payload_len = 0, dns_end;
	__u16 sport, dport, udp_len, want_port;
	const __u8 *udp;

	if (!meta)
		return DNS_PKT_LEN_BAD;
	__builtin_memset(meta, 0, sizeof(*meta));

	if (ethertype == ETH_P_IP) {
		__u16 tot_len, frag_off;
		__u32 ihl;

		if (wire_len < 20 || data + 20 > data_end)
			return DNS_PKT_LEN_BAD;
		if ((data[0] >> 4) != 4)
			return DNS_PKT_LEN_BAD;
		ihl = (__u32)(data[0] & 0x0f) * 4u;
		if (ihl < 20 || ihl > DNS_MAX_IP_HEADER_BYTES ||
		    wire_len < ihl || data + ihl > data_end)
			return DNS_PKT_LEN_BAD;
		tot_len = ((__u16)data[2] << 8) | (__u16)data[3];
		if (tot_len < ihl || (__u32)tot_len > wire_len)
			return DNS_PKT_LEN_BAD;
		frag_off = ((__u16)data[6] << 8) | (__u16)data[7];
		if (frag_off & 0x3fffu)
			return DNS_PKT_FRAGMENT;
		if (data[9] != IPPROTO_UDP)
			return DNS_PKT_NOT_UDP;
		meta->family = AF_INET;
		dns_copy_raw_u32(data + 12, &meta->saddr[0]);
		dns_copy_raw_u32(data + 16, &meta->daddr[0]);
		l4_off = ihl;
		ip_payload_len = (__u32)tot_len - ihl;
	} else if (ethertype == ETH_P_IPV6) {
		__u16 payload_len;
		__u8 nexthdr;

		if (wire_len < 40 || data + 40 > data_end)
			return DNS_PKT_LEN_BAD;
		if ((data[0] >> 4) != 6)
			return DNS_PKT_LEN_BAD;
		payload_len = ((__u16)data[4] << 8) | (__u16)data[5];
		if (40u + (__u32)payload_len > wire_len)
			return DNS_PKT_LEN_BAD;
		nexthdr = data[6];
		if (nexthdr != IPPROTO_UDP) {
			if (dns_is_ipv6_ext_hdr(nexthdr))
				return DNS_PKT_IPV6_EXT;
			return DNS_PKT_NOT_UDP;
		}
		meta->family = AF_INET6;
		dns_copy_raw_u32(data + 8, &meta->saddr[0]);
		dns_copy_raw_u32(data + 12, &meta->saddr[1]);
		dns_copy_raw_u32(data + 16, &meta->saddr[2]);
		dns_copy_raw_u32(data + 20, &meta->saddr[3]);
		dns_copy_raw_u32(data + 24, &meta->daddr[0]);
		dns_copy_raw_u32(data + 28, &meta->daddr[1]);
		dns_copy_raw_u32(data + 32, &meta->daddr[2]);
		dns_copy_raw_u32(data + 36, &meta->daddr[3]);
		l4_off = 40;
		ip_payload_len = (__u32)payload_len;
	} else {
		return DNS_PKT_IGNORE;
	}

	barrier_var(l4_off);
	if (l4_off > DNS_MAX_IP_HEADER_BYTES || ip_payload_len < 8)
		return DNS_PKT_LEN_BAD;
	udp = data + l4_off;
	if (udp + 8 > data_end)
		return DNS_PKT_LEN_BAD;

	/* Keep ports in network byte order to match struct dns_request_key. */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	meta->sport = ((__u16)udp[0] << 8) | (__u16)udp[1];
	meta->dport = ((__u16)udp[2] << 8) | (__u16)udp[3];
#else
	meta->sport = (__u16)(((__u16)udp[1] << 8) | (__u16)udp[0]);
	meta->dport = (__u16)(((__u16)udp[3] << 8) | (__u16)udp[2]);
#endif
	sport = ((__u16)udp[0] << 8) | (__u16)udp[1];
	dport = ((__u16)udp[2] << 8) | (__u16)udp[3];
	want_port = send ? dport : sport;
	if (want_port != DNS_PORT)
		return DNS_PKT_PORT_SKIP;

	udp_len = ((__u16)udp[4] << 8) | (__u16)udp[5];
	if (udp_len < 8 || (__u32)udp_len > ip_payload_len)
		return DNS_PKT_LEN_BAD;
	if (udp_len > DNS_MAX_UDP_BYTES || ip_payload_len > DNS_MAX_UDP_BYTES)
		return DNS_PKT_OVER_BUDGET;

	dns_end = l4_off + (__u32)udp_len;
	barrier_var(dns_end);
	if (dns_end > DNS_MAX_PACKET_BYTES || data + dns_end > data_end)
		return DNS_PKT_LEN_BAD;

	meta->dns_off = l4_off + 8;
	meta->dns_end = dns_end;
	return DNS_PKT_OK;
}

DNS_INLINE bool dns_hdr_bounded(const __u8 *data, const __u8 *data_end,
				__u32 dns_off, __u32 dns_end)
{
	const __u8 *hdr;

	barrier_var(dns_off);
	barrier_var(dns_end);
	if (dns_end > DNS_MAX_PACKET_BYTES ||
	    dns_off > DNS_MAX_PACKET_BYTES - sizeof(struct dns_hdr) ||
	    dns_off + sizeof(struct dns_hdr) > dns_end)
		return false;
	hdr = data + dns_off;
	return hdr + sizeof(struct dns_hdr) <= data_end;
}

/*
 * Inlined, off comes from a caller's int that clang knows to be positive,
 * and clang 23 then tests it as signed 32-bit and sign-extends it, which
 * the verifier cannot bound. The barrier keeps it the __u32 it is.
 */
DNS_INLINE bool dns_read_u16_bounded(const __u8 *data, const __u8 *data_end,
				     __u32 off, __u32 dns_end, __u16 *value)
{
	const __u8 *src;

	barrier_var(off);
	barrier_var(dns_end);
	if (!value || dns_end > DNS_MAX_PACKET_BYTES ||
	    dns_end < sizeof(*value) || off > dns_end - sizeof(*value))
		return false;
	src = data + off;
	if (src + sizeof(*value) > data_end)
		return false;
	*value = ((__u16)src[0] << 8) | (__u16)src[1];
	return true;
}

DNS_INLINE bool dns_read_u32_raw_bounded(const __u8 *data,
					 const __u8 *data_end, __u32 off,
					 __u32 dns_end, __u32 *value)
{
	const __u8 *src;

	barrier_var(off);
	barrier_var(dns_end);
	if (!value || dns_end > DNS_MAX_PACKET_BYTES ||
	    dns_end < sizeof(*value) || off > dns_end - sizeof(*value))
		return false;
	src = data + off;
	if (src + sizeof(*value) > data_end)
		return false;
	dns_copy_raw_u32(src, value);
	return true;
}

/*
 * Copies one uncompressed label at [off, dns_end) into out (DNS_NAME_BYTES)
 * and returns the wire bytes consumed, 0 at the root label, with
 * DNS_NAME_REPLACED set when any byte was normalized to '?'.
 */
DNS_INLINE int dns_parse_label_into(const __u8 *data, const __u8 *data_end,
				    __u32 off, __u32 start, __u32 dns_end,
				    char *out)
{
	__u32 wire_offset, dst, i;
	int replaced = 0;
	const __u8 *src;
	__u8 len, byte;

	barrier_var(off);
	barrier_var(dns_end);
	if (!out || dns_end > DNS_MAX_PACKET_BYTES ||
	    off < start || off >= dns_end)
		return -EINVAL;
	wire_offset = off - start;
	if (wire_offset >= DNS_MAX_WIRE_NAME_BYTES)
		return -EINVAL;

	src = data + off;
	if (src + 1 > data_end)
		return -EINVAL;
	len = *src;
	if (len & DNS_COMPRESSED_MASK)
		return -EINVAL;
	src++;

	if (len == 0) {
		dst = wire_offset ? wire_offset - 1 : 0;
		barrier_var(dst);
		if (dst >= DNS_MAX_NAME_CHARS)
			return -EINVAL;
		out[dst] = 0;
		return 0;
	}
	if (len > DNS_MAX_LABEL_BYTES)
		return -EINVAL;
	if ((__u32)len > dns_end - off - 1)
		return -EINVAL;

	dst = wire_offset;
	barrier_var(dst);
	if (dst >= DNS_MAX_NAME_CHARS)
		return -EINVAL;
	if (dst)
		out[dst - 1] = '.';
	if (len > DNS_MAX_NAME_CHARS - dst)
		return -EINVAL;

	/* The verifier needs the packet bound checked for each direct read. */
#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
	for (i = 0; i < len; i++) {
		__u32 out_idx = dst + i;

		if (src + i + 1 > data_end)
			return -EINVAL;
		barrier_var(out_idx);
		if (out_idx >= DNS_MAX_NAME_CHARS)
			return -EINVAL;
		byte = src[i];
		if (!dns_label_byte_recordable(byte)) {
			byte = '?';
			replaced = DNS_NAME_REPLACED;
		}
		out[out_idx] = (char)byte;
	}
	return ((int)len + 1) | replaced;
}

/*
 * Walk a DNS domain name starting at off within [dns_off + 12, dns_end),
 * validating every compression pointer target (strictly backward, inside the
 * DNS payload past the 12-byte header, bounded to DNS_MAX_JUMPS jumps, and
 * terminating at a valid root label within 255 expanded wire bytes).
 */
DNS_INLINE int dns_skip_name_bounded(const __u8 *data, const __u8 *data_end,
				     __u32 dns_off, __u32 dns_end, __u32 off,
				     __u32 *next_off)
{
	__u32 cur = off, after_first = 0, wire_bytes = 0, jumps = 0;
	bool jumped = false;
	int step;

	barrier_var(dns_off);
	barrier_var(dns_end);
	if (!next_off || dns_end > DNS_MAX_PACKET_BYTES ||
	    dns_off > DNS_MAX_PACKET_BYTES - sizeof(struct dns_hdr) ||
	    dns_off + sizeof(struct dns_hdr) > dns_end)
		return -EINVAL;

#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
	for (step = 0; step < DNS_MAX_NAME_STEPS; step++) {
		__u32 label_len, ptr_rel, target;
		const __u8 *src;
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
		if (src + 1 + label_len > data_end)
			return -EINVAL;
		wire_bytes += 1 + label_len;
		cur += 1 + label_len;
	}
	return -EINVAL;
}

/*
 * Compare one non-empty uncompressed label at cur (length 1..63, already
 * bounds-checked against dns_end) case-insensitively against expected_name
 * starting at name_pos, returning the updated name_pos or a negative errno
 * (-EINVAL on packet truncation, -EBADMSG on character/length mismatch).
 */
DNS_INLINE int dns_match_label_chars(const __u8 *data, const __u8 *data_end,
				     __u32 cur, __u32 len,
				     const char *expected_name,
				     __u32 name_pos)
{
	const __u8 *src;
	__u32 i;

	barrier_var(cur);
	barrier_var(name_pos);
	if (!expected_name || cur >= DNS_MAX_PACKET_BYTES ||
	    len == 0 || len > DNS_MAX_LABEL_BYTES)
		return -EINVAL;
	src = data + cur;
	if (src + 1 > data_end)
		return -EINVAL;

	if (name_pos > 0) {
		if (name_pos >= DNS_MAX_NAME_CHARS)
			return -EBADMSG;
		if (expected_name[name_pos] != '.')
			return -EBADMSG;
		name_pos++;
	}
	if (name_pos > DNS_MAX_NAME_CHARS || len > DNS_MAX_NAME_CHARS - name_pos)
		return -EBADMSG;

#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
	for (i = 0; i < len; i++) {
		__u32 idx = name_pos + i;
		__u8 b, eb;

		if (src + 1 + i + 1 > data_end)
			return -EINVAL;
		barrier_var(idx);
		if (idx >= DNS_MAX_NAME_CHARS)
			return -EBADMSG;
		b = src[1 + i];
		if (!dns_label_byte_recordable(b))
			b = '?';
		eb = (__u8)expected_name[idx];
		if (eb == '\0' || dns_ascii_lower(b) != dns_ascii_lower(eb))
			return -EBADMSG;
	}
	return (int)(name_pos + len);
}

/*
 * Walk a response QNAME starting at off within [dns_off + 12, dns_end) and
 * verify it equals expected_name (DNS_NAME_BYTES) case-insensitively.
 * Returns 0 on match, -EBADMSG on a well-formed QNAME that differs from
 * expected_name, and -EINVAL on malformed wire encoding or bounds failure.
 */
DNS_INLINE int dns_match_qname_bounded(const __u8 *data, const __u8 *data_end,
				       __u32 dns_off, __u32 dns_end, __u32 off,
				       const char *expected_name,
				       __u32 *next_off)
{
	__u32 cur = off, after_first = 0, wire_bytes = 0, jumps = 0;
	__u32 name_pos = 0;
	bool jumped = false;
	int step;

	barrier_var(dns_off);
	barrier_var(dns_end);
	if (!expected_name || !next_off || dns_end > DNS_MAX_PACKET_BYTES ||
	    dns_off > DNS_MAX_PACKET_BYTES - sizeof(struct dns_hdr) ||
	    dns_off + sizeof(struct dns_hdr) > dns_end)
		return -EINVAL;

#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
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
			if (expected_name[name_pos] != '\0')
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
		next_pos = dns_match_label_chars(data, data_end, cur,
						 label_len, expected_name,
						 name_pos);
		if (next_pos < 0)
			return next_pos;
		name_pos = (__u32)next_pos;
		wire_bytes += 1 + label_len;
		cur += 1 + label_len;
	}
	return -EINVAL;
}

/*
 * Parse one A or AAAA RDATA matching req->qtype and DNS_CLASS_IN.
 * Returns 1 when an address matching the query was extracted into *key,
 * 0 when the RR type/class does not match the query (skipped cleanly),
 * or -EINVAL when RDLENGTH / packet bounds are invalid.
 */
DNS_INLINE int dns_extract_answer_addr(const __u8 *data, const __u8 *data_end,
				       __u32 rdata_off, __u32 dns_end,
				       __u16 req_qtype, __u16 rtype,
				       __u16 rclass, __u16 rdlen,
				       struct dns_key *key)
{
	__builtin_memset(key, 0, sizeof(*key));
	if (rclass != DNS_CLASS_IN || rtype != req_qtype)
		return 0;
	if (rtype == DNS_TYPE_A) {
		if (rdlen != 4)
			return 0;
		key->family = AF_INET;
		if (!dns_read_u32_raw_bounded(data, data_end, rdata_off,
					      dns_end, &key->addr[0]))
			return -EINVAL;
		return 1;
	}
	if (rtype == DNS_TYPE_AAAA) {
		if (rdlen != 16)
			return 0;
		key->family = AF_INET6;
		if (!dns_read_u32_raw_bounded(data, data_end, rdata_off,
					      dns_end, &key->addr[0]) ||
		    !dns_read_u32_raw_bounded(data, data_end, rdata_off + 4,
					      dns_end, &key->addr[1]) ||
		    !dns_read_u32_raw_bounded(data, data_end, rdata_off + 8,
					      dns_end, &key->addr[2]) ||
		    !dns_read_u32_raw_bounded(data, data_end, rdata_off + 12,
					      dns_end, &key->addr[3]))
			return -EINVAL;
		return 1;
	}
	return 0;
}

#endif /* KERNEL_OBS_DNS_PARSE_H */
