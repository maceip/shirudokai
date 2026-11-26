#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3020 -- bpm build compiles and signs upatches/kernel-obs with its
# hardened DNS wire parser, decoders, and watch-list rodata inputs.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v tar >/dev/null 2>&1 || test_skip_all "no tar"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h"
openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA' ||
	test_skip_all "openssl without ML-DSA (needs OpenSSL >= 3.5)"

REPO=$(cd .. && pwd)
S="$REPO/shirudo"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

mkdir -p "$WORK/pkg"
cp -R "$REPO/upatches/kernel-obs/." "$WORK/pkg/"
ln -s "$REPO/vendor" "$WORK/pkg/vendor"
ln -s "$REPO/bpf" "$WORK/pkg/bpf"
export SHIRUDO_BUILD="$REPO/tools/shirudo-build/shirudo-build"

test_expect_success 'generate temporary signing keypair' '
	"$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1
'

test_expect_success 'bpm build packages upatches/kernel-obs cleanly' '
	( cd "$WORK" && "$S" bpm build pkg \
		--version 1.0.0 --keys-dir "$WORK/keys" \
		--vmlinux "$REPO/vendor/linux/vmlinux.h" ) >&2 &&
	test -s "$WORK/kernel-obs-1.0.0.bee"
'

test_expect_success 'built kernel-obs upatch carries signed DNS decoder and cgroup_skb hooks' '
	"$S" bpm info upatches "$WORK/kernel-obs-1.0.0.bee" --all >"$WORK/info.txt" &&
	grep -q "kernel-obs" "$WORK/info.txt" &&
	tar -xOf "$WORK/kernel-obs-1.0.0.bee" \
		kernel-obs-1.0.0/upatches/kernel-obs.upatch \
		>"$WORK/kernel-obs.upatch" &&
	"$S" upatch info --json "$WORK/kernel-obs.upatch" >"$WORK/upatch.json" &&
	python3 -c '\''
import json, sys
u = json.load(open(sys.argv[1]))
assert u["name"] == "kernel-obs"
assert u["type"] == "load"
maps = {d["map"] for d in u["decoders"]}
assert "dns" in maps and "net" in maps and "watch_stat" in maps
'\'' "$WORK/upatch.json"
'

test_done
