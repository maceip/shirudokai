#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3019 -- TCX ingress/egress sections, named device classes, XDP/TCX
# interface-name and driver glob filters, multi-TCX chaining in one
# upatch, and struct_ops (.struct_ops.link) upatch building and
# validation.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SH="../shirudo"
SHB="../tools/shirudo-build/shirudo-build"
CHECK="helper/test-upatch-prog-metadata"

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$SH" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/signing_key.pem" \
	-outform DER -out "$WORK/cert.der" -days 1 -subj "/CN=t3019" \
	>/dev/null 2>&1 || test_skip_all "OpenSSL ML-DSA-87 keygen unavailable"

SH_ABS="$(cd .. && pwd)/shirudo"
SHB_ABS="$(cd .. && pwd)/tools/shirudo-build/shirudo-build"

build_upatch() {
	src="$1"
	out="$2"
	name="$3"
	( cd .. && SHIRUDO_BUILD="$SHB_ABS" "$SH_ABS" build "$src" \
		-o "$out" --name "$name" \
		--vmlinux vendor/linux/vmlinux.h \
		--keys-dir "$WORK" )
}

build_tcx_single() {
	cat >"$WORK/tcx.bpf.c" <<-EOF
	// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
	#include "vmlinux.h"
	#include <bpf/bpf_helpers.h>
	char _license[] SEC("license") = "Dual BSD/GPL";
	SEC("$1")
	int handle_pkt(struct __sk_buff *skb) { return TCX_NEXT; }
	EOF
	build_upatch "$WORK/tcx.bpf.c" "$WORK/tcx.upatch" tcx-single >"$WORK/tcx.log" 2>&1
}

build_xdp_single() {
	cat >"$WORK/xdp-filt.bpf.c" <<-EOF
	// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
	#include "vmlinux.h"
	#include <bpf/bpf_helpers.h>
	char _license[] SEC("license") = "Dual BSD/GPL";
	SEC("$1")
	int handle_xdp(struct xdp_md *ctx) { return XDP_PASS; }
	EOF
	build_upatch "$WORK/xdp-filt.bpf.c" "$WORK/xdp-filt.upatch" xdp-filt >"$WORK/xdp.log" 2>&1
}

test_expect_success 'bare tcx/ingress and tcx/egress sign class mask 27' '
	build_tcx_single "tcx/ingress" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-ingress 27 &&
	"$SH" upatch info "$WORK/tcx.upatch" --json >"$WORK/tcx-info.json" &&
	python3 - "$WORK/tcx-info.json" "$WORK/tcx.upatch" <<-\PY &&
	import json, struct, sys
	doc = json.load(open(sys.argv[1], encoding="utf-8"))
	nr_maps, nr_progs = struct.unpack_from("<II", open(sys.argv[2], "rb").read(), 340)
	assert nr_progs == 1
	assert doc["attach_metadata_len"] == 16 + 160 * 1
	assert doc["mode"] == "enforce"
	PY
	build_tcx_single "tcx/egress" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-egress 27
'

test_expect_success 'tcx named classes and decimal masks sign matching masks' '
	build_tcx_single "tcx/ingress/network" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-ingress 1 &&
	build_tcx_single "tcx/egress/network+virtual" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-egress 3 &&
	build_tcx_single "tcx/ingress/vm+unknown" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-ingress 24 &&
	build_tcx_single "tcx/egress/9" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-egress 9
'

test_expect_success 'tcx and xdp sign ifname and driver glob filters' '
	build_tcx_single "tcx/ingress/ifname=eth*" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-ingress 27 "ifname=eth*" &&
	build_tcx_single "tcx/egress/network:driver=mlx5*" &&
	"$CHECK" "$WORK/tcx.upatch" tcx-egress 1 "driver=mlx5*" &&
	build_xdp_single "xdp/1:ifname=enp*s0" &&
	"$CHECK" "$WORK/xdp-filt.upatch" xdp 1 "ifname=enp*s0" &&
	build_xdp_single "xdp/8:driver=virtio_net" &&
	"$CHECK" "$WORK/xdp-filt.upatch" xdp 8 "driver=virtio_net"
'

test_expect_success 'multiple tcx programs and xdp share device classes in one upatch' '
	cat >"$WORK/chain.bpf.c" <<-\EOF &&
	// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
	#include "vmlinux.h"
	#include <bpf/bpf_helpers.h>
	char _license[] SEC("license") = "Dual BSD/GPL";
	SEC("tcx/ingress/network")
	int first_in(struct __sk_buff *skb) { return TCX_NEXT; }
	SEC("tcx/ingress/network:ifname=eth*")
	int second_in(struct __sk_buff *skb) { return TCX_NEXT; }
	SEC("tcx/egress/network")
	int first_out(struct __sk_buff *skb) { return TCX_NEXT; }
	SEC("xdp/1:driver=mlx5*")
	int early_xdp(struct xdp_md *ctx) { return XDP_PASS; }
	EOF
	build_upatch "$WORK/chain.bpf.c" "$WORK/chain.upatch" dataplane-chain &&
	"$SH" upatch info "$WORK/chain.upatch" --json >"$WORK/chain.json" &&
	python3 - "$WORK/chain.json" "$WORK/chain.upatch" <<-\PY
	import json, struct, sys
	doc = json.load(open(sys.argv[1], encoding="utf-8"))
	nr_maps, nr_progs = struct.unpack_from("<II", open(sys.argv[2], "rb").read(), 340)
	assert nr_progs == 4
	assert doc["attach_metadata_len"] == 16 + 160 * 4
	PY
'

test_expect_success 'malformed tcx sections and invalid netdev filters are refused' '
	for bad in tcx tcx/ tcx/other tcx/ingress/4 tcx/ingress/bogus \
		tcx/ingress/network+ tcx/ingress/ifname= \
		tcx/ingress/ifname=eth0/1 "tcx/egress/driver=a|b"; do
		if build_tcx_single "$bad"; then
			return 1
		fi
	done &&
	for bad_xdp in xdp/1: xdp/1:eth0 xdp/1:ifname= xdp/1:ifname=a,b; do
		if build_xdp_single "$bad_xdp"; then
			return 1
		fi
	done
'

cat >"$WORK/struct-ops.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} inits SEC(".maps");

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("struct_ops/shirudo_t3019_init")
void BPF_PROG(shirudo_t3019_init, struct sock *sk)
{
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&inits, &key);

	if (val)
		__sync_fetch_and_add(val, 1);
}

SEC("struct_ops/shirudo_t3019_ssthresh")
__u32 BPF_PROG(shirudo_t3019_ssthresh, struct sock *sk)
{
	return 2;
}

SEC("struct_ops/shirudo_t3019_cong_avoid")
void BPF_PROG(shirudo_t3019_cong_avoid, struct sock *sk, __u32 ack,
	      __u32 acked)
{
}

SEC("struct_ops/shirudo_t3019_undo_cwnd")
__u32 BPF_PROG(shirudo_t3019_undo_cwnd, struct sock *sk)
{
	return 2;
}

SEC(".struct_ops.link")
struct tcp_congestion_ops shirudo_t3019_cc = {
	.init		= (void *)shirudo_t3019_init,
	.ssthresh	= (void *)shirudo_t3019_ssthresh,
	.cong_avoid	= (void *)shirudo_t3019_cong_avoid,
	.undo_cwnd	= (void *)shirudo_t3019_undo_cwnd,
	.name		= "t3019_cc",
};
EOF

test_expect_success 'struct_ops upatch with .struct_ops.link builds and signs role 3' '
	build_upatch "$WORK/struct-ops.bpf.c" "$WORK/struct-ops.upatch" struct-ops-cc &&
	"$CHECK" "$WORK/struct-ops.upatch" struct-ops &&
	"$SH" upatch info "$WORK/struct-ops.upatch" --json >"$WORK/st.json" &&
	python3 - "$WORK/st.json" "$WORK/struct-ops.upatch" <<-\PY
	import json, struct, sys
	doc = json.load(open(sys.argv[1], encoding="utf-8"))
	nr_maps, nr_progs = struct.unpack_from("<II", open(sys.argv[2], "rb").read(), 340)
	assert nr_progs == 4
	assert nr_maps >= 2
	assert doc["attach_metadata_len"] == 16 + 160 * 4
	PY
'

test_expect_success 'struct_ops map outside .struct_ops.link and unreferenced callback are refused' '
	sed "s/\"\.struct_ops\.link\"/\".struct_ops\"/" "$WORK/struct-ops.bpf.c" >"$WORK/no-link.bpf.c" &&
	! build_upatch "$WORK/no-link.bpf.c" "$WORK/no-link.upatch" no-link 2>"$WORK/no-link.err" &&
	grep -q "must be in SEC(\".struct_ops.link\")" "$WORK/no-link.err" &&
	[ ! -e "$WORK/no-link.upatch" ] &&
	cat "$WORK/struct-ops.bpf.c" - >"$WORK/stray.bpf.c" <<-\EOF &&
	SEC("struct_ops/shirudo_t3019_stray")
	void BPF_PROG(shirudo_t3019_stray, struct sock *sk) {}
	EOF
	! build_upatch "$WORK/stray.bpf.c" "$WORK/stray.upatch" stray 2>"$WORK/stray.err" &&
	grep -q "referenced anywhere" "$WORK/stray.err" &&
	[ ! -e "$WORK/stray.upatch" ] &&
	cat "$WORK/struct-ops.bpf.c" - >"$WORK/two-ops.bpf.c" <<-\EOF &&
	SEC(".struct_ops.link")
	struct tcp_congestion_ops shirudo_t3019_cc2 = {
		.init		= (void *)shirudo_t3019_init,
		.ssthresh	= (void *)shirudo_t3019_ssthresh,
		.cong_avoid	= (void *)shirudo_t3019_cong_avoid,
		.undo_cwnd	= (void *)shirudo_t3019_undo_cwnd,
		.name		= "t3019_c2",
	};
	EOF
	! build_upatch "$WORK/two-ops.bpf.c" "$WORK/two-ops.upatch" two-ops 2>"$WORK/two-ops.err" &&
	grep -q "at most one struct_ops map" "$WORK/two-ops.err" &&
	[ ! -e "$WORK/two-ops.upatch" ]
'

test_done
