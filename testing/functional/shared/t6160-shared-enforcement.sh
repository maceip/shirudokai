#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6160 -- shared enforcement, which this family's runtime image selects.
# A root process that is not shirudo creates, writes, loads and pins BPF
# objects of its own, but no LSM program, whose kfuncs write the seal's
# labels. It opens none of shirudo's maps, programs, links or pins:
# bpf2's and seal's, which carry the shirudo_ prefix, and a upatch's,
# which shirudo recorded when it loaded them.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

H=helper/test-shared-bpf
C=helper/test-bpf-cmd
[ -x "$H" ] && [ -x "$C" ] || test_skip_all "test-shared-bpf helpers not built"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'status reports shared enforcement' '
	"$SHIRUDO_BIN" status --json | report_field enforcement >"$WORK/mode" &&
	grep -qx shared "$WORK/mode" &&
	"$SHIRUDO_BIN" status | grep -Eq "^Enforcement: +shared$"
'

test_expect_success 'root creates, loads and pins BPF objects of its own' '
	[ "$(./$H own /sys/fs/bpf/t6160-map)" = ok ]
'

test_expect_success 'root loads no LSM program' '
	[ "$(./$H lsm)" = "lsm_load errno=13" ]
'

test_expect_success 'links by id, tokens and unclassified commands stay refused' '
	[ "$(./$C LINK_GET_FD_BY_ID)" = "errno=13" ] &&
	[ "$(./$C TOKEN_CREATE)" = "errno=13" ]
'

test_expect_success 'the private bpffs lists, but its pins do not open' '
	ls /run/shirudo/bpffs | grep -qx lsm_link &&
	! cat /run/shirudo/bpffs/lsm_link >/dev/null 2>"$WORK/err" &&
	grep -q "Permission denied" "$WORK/err"
'

test_expect_success 'no map or program named shirudo_ opens' '
	./$H objects >"$WORK/objects" &&
	grep -q "errno=13" "$WORK/objects" &&
	! grep -E "^(map|prog) [0-9]+ shirudo_" "$WORK/objects"
'

test_expect_success 'the programs of a upatch shirudo loads do not open' '
	./$H objects | grep "^prog " >"$WORK/before" &&
	require_loaded shirudo-test-basic &&
	./$H objects | grep "^prog " >"$WORK/after" &&
	sort "$WORK/before" >"$WORK/before.sorted" &&
	sort "$WORK/after" | comm -13 "$WORK/before.sorted" - >"$WORK/new" &&
	[ -s "$WORK/new" ] &&
	! grep -v "errno=13$" "$WORK/new"
'

test_done
