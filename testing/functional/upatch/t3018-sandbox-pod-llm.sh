#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3018 -- workload, pod-scoped and LLM agent sandboxes in app-sandbox:
# default sandbox.toml build, --rodata-input sandbox=llm-agent.toml build,
# pod cgroup_ids + ports + families + deny.read + deny.unix + deny_ptrace
# BTF .rodata round-trip via shirudo bpm info data --json, invalid TOML
# rejection in gen_policy.py, and bpf_ Coccinelle rules on app-sandbox.bpf.c
# and web-worker-guard.bpf.c.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
S="$REPO/shirudo"
SHB="$REPO/tools/shirudo-build/shirudo-build"
VMLINUX="$REPO/vendor/linux/vmlinux.h"

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -f "$VMLINUX" ] || test_skip_all "vendor/linux/vmlinux.h not generated"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/keys" "$WORK/out"
SHIRUDO_BUILD="$SHB" "$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1 ||
	test_skip_all "shirudo genkey failed"

stage_pkg() {
	mkdir -p "$WORK/$1" &&
	cp "$REPO/upatches/app-sandbox/Beefile" \
	   "$REPO/upatches/app-sandbox/sandbox.toml" \
	   "$REPO/upatches/app-sandbox/llm-agent.toml" \
	   "$REPO/upatches/app-sandbox/gen_policy.py" \
	   "$REPO/upatches/app-sandbox/app-sandbox.bpf.c" "$WORK/$1/" &&
	ln -s "$REPO/bpf" "$WORK/$1/bpf" &&
	ln -s "$REPO/vendor" "$WORK/$1/vendor"
}

test_expect_success 'default sandbox.toml builds and keeps read_enforced/ptrace_denied zero' '
	stage_pkg default &&
	(
		cd "$WORK/out" &&
		SHIRUDO_BUILD="$SHB" "$S" bpm build "$WORK/default" \
			--version 1.0.0 --keys-dir "$WORK/keys"
	) &&
	pkg="$WORK/out/app-sandbox-1.0.0.bee" &&
	test -f "$pkg" &&
	"$S" bpm info data "$pkg" upatches/app-sandbox.upatch \
		>"$WORK/default.data" &&
	grep -qF ".sandboxes = (__u64)3," "$WORK/default.data" &&
	grep -qF ".net_enforced = (__u64)3," "$WORK/default.data" &&
	"$S" bpm info data "$pkg" upatches/app-sandbox.upatch --json \
		>"$WORK/default.json" &&
	python3 -I - "$WORK/default.json" <<-\PY
	import json, sys
	raw = json.load(open(sys.argv[1]))
	sp = next(v["value"] for v in raw["variables"] if v["name"] == "sandbox_policy")
	assert sp["sandboxes"] == 3, sp
	assert sp["net_enforced"] == 3, sp
	assert sp["read_enforced"] == 0, sp
	assert sp["unix_enforced"] == 0, sp
	assert sp["ptrace_denied"] == 0, sp
	assert sp["cgroup_scoped"] == 0, sp
	PY
'

test_expect_success 'llm-agent.toml builds via --rodata-input sandbox=... and round-trips BTF policy fields' '
	stage_pkg llm &&
	(
		cd "$WORK/out" &&
		SHIRUDO_BUILD="$SHB" "$S" bpm build "$WORK/llm" \
			--version 1.1.0 --keys-dir "$WORK/keys" \
			--rodata-input "sandbox=$REPO/upatches/app-sandbox/llm-agent.toml"
	) &&
	pkg="$WORK/out/app-sandbox-1.1.0.bee" &&
	test -f "$pkg" &&
	"$S" bpm info data "$pkg" upatches/app-sandbox.upatch --json \
		>"$WORK/llm.json" &&
	python3 -I - "$WORK/llm.json" <<-\PY
	import json, sys
	raw = json.load(open(sys.argv[1]))
	sp = next(v["value"] for v in raw["variables"] if v["name"] == "sandbox_policy")
	assert sp["sandboxes"] == 4, sp
	assert sp["families_enforced"] == 4, sp
	assert sp["net_enforced"] == 0, sp
	assert sp["net_deny_enforced"] == 4, sp
	assert sp["read_enforced"] == 4, sp
	assert sp["unix_enforced"] == 4, sp
	assert sp["ptrace_denied"] == 4, sp
	assert sp["nr_families"] == 1, sp
	# AF_UNIX (1<<1=2) | AF_INET (1<<2=4) | AF_INET6 (1<<10=1024) == 1030
	assert sp["families"][0]["sandbox"] == 4, sp["families"][0]
	assert sp["families"][0]["allowed"] == 1030, sp["families"][0]
	assert sp["nr_net"] == 7, sp["nr_net"]
	for rule in sp["net"][:7]:
	    assert rule["deny_sandboxes"] == 4, rule
	    assert rule["allow_sandboxes"] == 0, rule
	read_rules = [r for r in sp["fim"][:sp["nr_fim"]] if r["ops"] & 0x8]
	assert len(read_rules) == 6, read_rules
	contains_rules = [r for r in read_rules if r["wildcard"] == 2]
	assert len(contains_rules) == 1, contains_rules
	unix_rules = [r for r in sp["fim"][:sp["nr_fim"]] if r["ops"] & 0x30]
	assert len(unix_rules) == 4, unix_rules
	PY
'

test_expect_success 'pod-scoped cgroup_ids and TCP/UDP port allow/deny rules round-trip through BTF JSON' '
	stage_pkg pod &&
	cat >"$WORK/pod.toml" <<-\TOML &&
	[sandbox.llm-agent]
	cgroup_ids = [4294967301, 4294967302]
	families = ["inet", "inet6", "unix", "netlink", "vsock"]
	ports = [443, "tcp/8080-8090", "udp/53"]
	deny_ptrace = true

	[sandbox.llm-agent.deny]
	ports = [22, "tcp/25"]
	read = [".env*"]
	unix = ["/var/run/docker.sock", "docker.sock"]
	TOML
	(
		cd "$WORK/out" &&
		SHIRUDO_BUILD="$SHB" "$S" bpm build "$WORK/pod" \
			--version 1.2.0 --keys-dir "$WORK/keys" \
			--rodata-input "sandbox=$WORK/pod.toml"
	) &&
	pkg="$WORK/out/app-sandbox-1.2.0.bee" &&
	"$S" bpm info data "$pkg" upatches/app-sandbox.upatch --json \
		>"$WORK/pod.json" &&
	python3 -I - "$WORK/pod.json" <<-\PY
	import json, sys
	raw = json.load(open(sys.argv[1]))
	sp = next(v["value"] for v in raw["variables"] if v["name"] == "sandbox_policy")
	assert sp["cgroup_scoped"] == 4, sp
	assert sp["nr_cgroup_ids"] == 2, sp
	assert sp["cgroup_ids"][0] == {"cgroup_id": 4294967301, "sandboxes": 4}, sp["cgroup_ids"][0]
	assert sp["cgroup_ids"][1] == {"cgroup_id": 4294967302, "sandboxes": 4}, sp["cgroup_ids"][1]
	assert sp["port_enforced"] == 4, sp
	assert sp["port_deny_enforced"] == 4, sp
	assert sp["nr_ports"] == 5, sp["nr_ports"]
	expected_fam = (1 << 1) | (1 << 2) | (1 << 10) | (1 << 16) | (1 << 40)
	assert sp["families"][0]["allowed"] == expected_fam, sp["families"][0]
	PY
'

test_expect_success 'gen_policy.py rejects invalid families, ports, cgroup_ids, ptrace types and patterns' '
	stage_pkg bad &&
	check_bad() {
		printf "%s\n" "$1" >"$WORK/bad.toml" &&
		! python3 "$REPO/upatches/app-sandbox/gen_policy.py" \
			--beefile "$WORK/bad/Beefile" \
			--input "$WORK/bad.toml" \
			--symbol sandbox_policy \
			--output "$WORK/bad.bin" 2>"$WORK/bad.err"
	} &&
	check_bad "[sandbox.llm-agent]
families = [\"bluetooth\"]" &&
	check_bad "[sandbox.llm-agent]
ports = [70000]" &&
	check_bad "[sandbox.llm-agent]
ports = [\"tcp/9000-8000\"]" &&
	check_bad "[sandbox.llm-agent]
ports = [\"icmp/80\"]" &&
	check_bad "[sandbox.llm-agent]
cgroup_ids = []" &&
	check_bad "[sandbox.llm-agent]
cgroup_ids = [0]" &&
	check_bad "[sandbox.llm-agent]
deny_ptrace = \"yes\"" &&
	check_bad "[sandbox.llm-agent.deny]
read = [\"/etc/passwd\"]" &&
	check_bad "[sandbox.llm-agent.deny]
read = [\"a*b*c\"]"
'

if command -v spatch >/dev/null 2>&1; then
	test_expect_success 'app-sandbox.bpf.c and web-worker-guard.bpf.c pass bpf_ Coccinelle rules' '
		for src in \
			upatches/app-sandbox/app-sandbox.bpf.c \
			upatches/web-worker-guard/web-worker-guard.bpf.c
		do
			for rule in "$REPO"/testing/coccinelle/bpf_*.cocci; do
				out=$(cd "$REPO" && spatch -D report --very-quiet \
					--no-includes \
					--macro-file testing/coccinelle/bpf.macros \
					--sp-file "$rule" "$src") || exit 1
				test -z "$out" || { printf "%s\n" "$out" >&2; exit 1; }
			done
		done
	'
fi

test_done
