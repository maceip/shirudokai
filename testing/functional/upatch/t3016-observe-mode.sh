#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3016 -- signed observe mode (`shirudo build --observe`), `bpf/lib/shield.h`
# helper compilation, `.rodata` `shirudo_observe_mode` signing, unsigned
# header flag-flip rejection, and `shirudo upatch check` reproducer verdict.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S="$(pwd)/../shirudo"
SHB="$(pwd)/../tools/shirudo-build/shirudo-build"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj /CN=t3016 \
	>/dev/null 2>&1 || test_skip_all "OpenSSL ML-DSA unavailable"
chmod 600 "$WORK/k.pem"

cat >"$WORK/shield.bpf.c" <<-'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shield.h"

#define EPERM 1

char _license[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 shirudo_observe_mode = 0;

SHIELD_COUNTERS_MAP(shield_counters);
SHIELD_STACK_MAP(shield_stacks, 128);
SHIELD_STACK_ID_COUNTS_MAP(shield_stack_ids, 128);

SEC("lsm/socket_create")
int BPF_PROG(shield_socket_create, int family, int type, int protocol, int kern,
	     int ret)
{
	if (ret)
		return ret;
	shield_count_activity(&shield_counters);
	if (family == 38) {
		return shield_decide_stack(shirudo_observe_mode != 0,
					   &shield_counters, &shield_stacks,
					   &shield_stack_ids, 0, ctx, EPERM);
	}
	return 0;
}

SEC("syscall")
int shirudo_test__repro(void *ctx)
{
	shield_count_activity(&shield_counters);
	return shield_decide(shirudo_observe_mode != 0, &shield_counters,
			     &shield_stacks, ctx, EPERM);
}
EOF

build_shield() {
	(cd .. && SHIRUDO_BUILD="$SHB" "$S" build "$@" \
		--vmlinux vendor/linux/vmlinux.h \
		--key "$WORK/k.pem" --cert "$WORK/c.der")
}

test_expect_success 'build real BPF shield in enforce and observe modes' '
	build_shield "$WORK/shield.bpf.c" --name cve-shield \
		-o "$WORK/enforce.upatch" >"$WORK/enforce.log" 2>&1 &&
	build_shield --observe "$WORK/shield.bpf.c" --name cve-shield \
		-o "$WORK/observe.upatch" >"$WORK/observe.log" 2>&1
'

test_expect_success 'upatch info surfaces enforce vs observe mode and distinct payload_sha256' '
	"$S" upatch info "$WORK/enforce.upatch" | grep -q "^Mode: *enforce$" &&
	"$S" upatch info "$WORK/observe.upatch" | grep -q "^Mode: *observe$" &&
	"$S" upatch info "$WORK/observe.upatch" | grep -q "^  Mode: *observe$" &&
	"$S" upatch info --json "$WORK/enforce.upatch" >"$WORK/enforce.info.json" &&
	"$S" upatch info --json "$WORK/observe.upatch" >"$WORK/observe.info.json" &&
	python3 - "$WORK/enforce.info.json" "$WORK/observe.info.json" <<-\PY
	import json, sys
	enf = json.load(open(sys.argv[1]))
	obs = json.load(open(sys.argv[2]))
	assert enf["mode"] == "enforce", enf
	assert obs["mode"] == "observe", obs
	assert enf["payload_sha256"] != obs["payload_sha256"]
	PY
'

test_expect_success 'signed .rodata shirudo_observe_mode is 0 in enforce and 1 in observe' '
	openssl x509 -inform DER -in "$WORK/c.der" -out "$WORK/c.pem" &&
	python3 - "$WORK/enforce.upatch" "$WORK/observe.upatch" "$WORK" <<-\PY &&
	import hashlib, struct, sys
	work = sys.argv[3]
	for idx, (path, want_mode, want_flags) in enumerate([
	    (sys.argv[1], 0, 0),
	    (sys.argv[2], 1, 2),
	]):
	    b = open(path, "rb").read()
	    flags, = struct.unpack_from("<I", b, 12)
	    payload_hash = b[272:304].hex()
	    insns_off, insns_len, sig_off, sig_len = struct.unpack_from("<IIII", b, 304)
	    data_off, data_len = struct.unpack_from("<II", b, 328)
	    rodata_off, = struct.unpack_from("<I", b, 348)
	    assert flags == want_flags, (flags, want_flags)
	    insns = b[insns_off:insns_off + insns_len]
	    data = b[data_off:data_off + data_len]
	    sig = b[sig_off:sig_off + sig_len]
	    assert hashlib.sha256(insns + data).hexdigest() == payload_hash
	    rodata_val, = struct.unpack_from("<I", data, rodata_off)
	    assert rodata_val == want_mode, (rodata_val, want_mode)
	    open(f"{work}/payload.{idx}", "wb").write(insns + data)
	    open(f"{work}/sig.{idx}", "wb").write(sig)
	PY
	openssl cms -verify -binary -inform DER -in "$WORK/sig.0" \
		-content "$WORK/payload.0" -certfile "$WORK/c.pem" \
		-CAfile "$WORK/c.pem" >/dev/null 2>&1 &&
	openssl cms -verify -binary -inform DER -in "$WORK/sig.1" \
		-content "$WORK/payload.1" -certfile "$WORK/c.pem" \
		-CAfile "$WORK/c.pem" >/dev/null 2>&1
'

test_expect_success 'unsigned DIRECTIVE_OBSERVE bit flip in header is rejected' '
	python3 - "$WORK/enforce.upatch" "$WORK/observe.upatch" \
		"$WORK/flip-enf.upatch" "$WORK/flip-obs.upatch" <<-\PY &&
	import struct, sys
	for src, dst in [(sys.argv[1], sys.argv[3]), (sys.argv[2], sys.argv[4])]:
	    b = bytearray(open(src, "rb").read())
	    flags, = struct.unpack_from("<I", b, 12)
	    struct.pack_into("<I", b, 12, flags ^ 2)
	    open(dst, "wb").write(b)
	PY
	! "$S" upatch info "$WORK/flip-enf.upatch" >/dev/null 2>&1 &&
	! "$S" upatch info "$WORK/flip-obs.upatch" >/dev/null 2>&1
'

test_expect_success 'shirudo build refuses --observe for a program without shirudo_observe_mode' '
	sed "/shirudo_observe_mode = 0/d; s/shirudo_observe_mode != 0/false/" \
		"$WORK/shield.bpf.c" >"$WORK/blind.bpf.c" &&
	! grep -q shirudo_observe_mode "$WORK/blind.bpf.c" &&
	build_shield "$WORK/blind.bpf.c" --name blind-shield \
		-o "$WORK/blind.upatch" >/dev/null 2>&1 &&
	! build_shield --observe "$WORK/blind.bpf.c" --name blind-shield \
		-o "$WORK/blind-obs.upatch" >"$WORK/blind.log" 2>&1 &&
	grep -q "needs a 32-bit shirudo_observe_mode" "$WORK/blind.log" &&
	test ! -e "$WORK/blind-obs.upatch"
'

test_expect_success 'shirudo build refuses --observe combined with --unload' '
	p=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[\"payload_sha256\"])" \
		"$WORK/observe.info.json") &&
	! build_shield --observe --unload cve-shield --payload-sha256 "$p" \
		-o "$WORK/bad.unload.upatch" >/dev/null 2>&1
'

test_expect_success 'shirudo upatch check passes valid reproducer snapshots and reports stack IDs' '
	cat >"$WORK/before.json" <<-\EOF &&
	{"activity":100,"hits":0,"enforced":0,"observed":0,"missed_runs":0,"stack_ids":[]}
	EOF
	cat >"$WORK/after_exp.json" <<-\EOF &&
	{"activity":105,"hits":3,"enforced":0,"observed":3,"missed_runs":0,"stack_ids":[204,41,204]}
	EOF
	cat >"$WORK/after_ben.json" <<-\EOF &&
	{"activity":250,"hits":3,"enforced":0,"observed":3,"missed_runs":0,"stack_ids":[204,41]}
	EOF
	"$S" upatch check cve-shield --before "$WORK/before.json" \
		--after-exploit "$WORK/after_exp.json" \
		--after-benign "$WORK/after_ben.json" | grep -q "^Verdict: *PASS$" &&
	"$S" upatch check cve-shield --before "$WORK/before.json" \
		--after-exploit "$WORK/after_exp.json" \
		--after-benign "$WORK/after_ben.json" --json >"$WORK/verdict.json" &&
	python3 - "$WORK/verdict.json" <<-\PY
	import json, sys
	v = json.load(open(sys.argv[1]))
	assert v["ok"] is True and v["verdict"] == "pass", v
	assert v["deltas"]["exploit_hits"] == 3, v
	assert v["deltas"]["benign_hits"] == 0, v
	assert v["deltas"]["missed_runs"] == 0, v
	assert v["stack_ids"] == [41, 204], v
	PY
'

test_expect_success 'shirudo upatch check rejects benign false positives and missed runs' '
	cat >"$WORK/benign_hit.json" <<-\EOF &&
	{"activity":250,"hits":4,"enforced":0,"observed":4,"missed_runs":0,"stack_ids":[204,41]}
	EOF
	cat >"$WORK/missed.json" <<-\EOF &&
	{"activity":250,"hits":3,"enforced":0,"observed":3,"missed_runs":1,"stack_ids":[204,41]}
	EOF
	! "$S" upatch check cve-shield --before "$WORK/before.json" \
		--after-exploit "$WORK/after_exp.json" \
		--after-benign "$WORK/benign_hit.json" --json >"$WORK/fail1.json" &&
	! "$S" upatch check cve-shield --before "$WORK/before.json" \
		--after-exploit "$WORK/after_exp.json" \
		--after-benign "$WORK/missed.json" --json >"$WORK/fail2.json" &&
	python3 - "$WORK/fail1.json" "$WORK/fail2.json" <<-\PY
	import json, sys
	f1 = json.load(open(sys.argv[1]))
	f2 = json.load(open(sys.argv[2]))
	assert f1["verdict"] == "fail" and f1["checks"]["benign_clean"] is False, f1
	assert f2["verdict"] == "fail" and f2["checks"]["no_missed_runs"] is False, f2
	PY
'

test_done
