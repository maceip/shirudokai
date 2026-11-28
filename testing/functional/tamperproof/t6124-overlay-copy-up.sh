#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6124 -- an overlay mounted over the state root in a mount namespace of
# root's own copies a sealed inode up into root's upper directory before
# the first write reaches it, and the copy-up runs as the writer, so the
# copy carried the label and a load shirudo made there put its archive
# copy and its eventlog event in root's directory while the register
# moved. The seal must refuse the copy-up: the load fails, root's
# directory stays empty, and register, eventlog and pins stay as they
# were.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME"
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing lifecycle fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
W=/tmp/t6124
rm -rf "$W"
mkdir -p "$W/ov"

cleanup() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$W"
}
trap cleanup EXIT

chain() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])"
}
counter() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tamper_attempts\"][\"counters\"][\"SealCopyUp\"])"
}
CHAIN=$(chain)
LINES=$(wc -l </var/lib/shirudo/eventlog)

# The upper directory is a tmpfs of the namespace, so what it holds is
# listed from inside; the listing goes to a path outside it. A directory
# nothing opened carries no mark and may be copied up, empty: no copy of
# the eventlog and no archive entry may follow it.
test_expect_success 'a load through an overlay over the state root is refused' '
	before=$(counter) &&
	rc=0; unshare -m sh -c "mount --make-rprivate / &&
		mount -t tmpfs tmpfs $W/ov && mkdir $W/ov/up $W/ov/work &&
		mount -t overlay overlay -o lowerdir=/var/lib/shirudo,upperdir=$W/ov/up,workdir=$W/ov/work /var/lib/shirudo &&
		$SHIRUDO_BIN upatch load $LOAD --no-precheck >/dev/null 2>$W/err;
		rc=\$?; find $W/ov/up -mindepth 1 >$W/upper; exit \$rc" || rc=$?;
	[ "$rc" != 0 ] &&
	! grep -q -e /eventlog -e "\.upatch" "$W/upper" &&
	[ ! -e "$PIN" ] &&
	[ "$(counter)" -gt "$before" ] &&
	[ "$(wc -l </var/lib/shirudo/eventlog)" = "$LINES" ] &&
	[ "$(chain)" = "$CHAIN" ]
'

test_expect_success 'the same load succeeds on the sealed tree' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$PIN/link" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ]
'

test_done
