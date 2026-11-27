#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6161 -- live target qualification of the five carried kernel patches
# 0020..0024: BTF readiness reporting, TPM header validation and command
# inspection (0020), security.bpf.* label reads without caller MAY_READ on
# uncached inodes (0021), sleepable inode hooks including overlay copy-up
# (0022), trusted dentry->d_parent label reads (0023), and read-only remote
# mm access checks under CAP_PERFMON/CAP_SYS_ADMIN (0024).

cd "$(dirname "$0")/../.." || exit 1
. ./integration-lib.sh
target_guard

H=helper/test-kernel-patches
STATE=/var/lib/shirudo/eventlog
POLICY=/run/shirudo/runtime/usr/bin/shirudo-policy-probe
[ -x "$H" ] || test_skip_all "test-kernel-patches helper not built"
for c in python3 mkfs.ext4 debugfs unshare; do
	command -v "$c" >/dev/null 2>&1 || test_skip_all "no $c"
done
[ -e "$STATE" ] || test_skip_all "no labelled state at $STATE"
[ -x "$POLICY" ] || test_skip_all "runtime policy probe is missing"

WORK=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
MNT=$WORK/mnt
PROBE_PID=
cleanup() {
	if [ -n "$PROBE_PID" ]; then
		kill "$PROBE_PID" 2>/dev/null || :
		wait "$PROBE_PID" 2>/dev/null || :
	fi
	umount "$MNT" 2>/dev/null || :
	rm -rf "$WORK" 2>/dev/null || :
}
trap cleanup EXIT

python3 -c '
import os, sys
sys.stdout.buffer.write(os.getxattr(sys.argv[1], "security.bpf.shirudo"))
' "$STATE" >"$WORK/label" 2>/dev/null
[ "$(wc -c <"$WORK/label")" = 64 ] ||
	test_skip_all "$STATE does not carry a 64-byte seal label"

echo scratch >"$WORK/scratch"
{
	echo "write $WORK/scratch plain_file"
	echo "mkdir plain_dir"
	echo "write $WORK/scratch wonly"
	echo "sif /wonly mode 0100222"
	echo "mkdir wxdir"
	echo "sif /wxdir mode 040333"
	echo "write $WORK/scratch noread"
	echo "sif /noread mode 0100000"
	for d in d_mkdir d_creat d_sym d_mknod d_link ov_lower; do
		echo "mkdir $d"
	done
	echo "write $WORK/scratch ov_lower/copyup"
	for f in f_link f_flags f_acl_set f_acl_rm; do
		echo "write $WORK/scratch $f"
	done
	for e in wonly wxdir noread d_mkdir d_creat d_sym d_mknod d_link \
		f_link f_flags f_acl_set f_acl_rm ov_lower/copyup; do
		echo "ea_set -f $WORK/label /$e security.bpf.shirudo"
	done
} >"$WORK/cmds"

{
	truncate -s 64M "$WORK/img" &&
	mkfs.ext4 -q -F "$WORK/img" &&
	debugfs -w -f "$WORK/cmds" "$WORK/img" &&
	mkdir "$MNT" &&
	mount -o loop "$WORK/img" "$MNT"
} >/dev/null 2>&1 || test_skip_all "cannot build and mount an ext4 image"

test_expect_success 'kernel_abi_patch_status reports BTF readiness for 0020..0024' '
	./$H status >"$WORK/status" &&
	grep -qx "signed_loader_abi=yes" "$WORK/status" &&
	grep -qx "0020 tpm_command btf_ready" "$WORK/status" &&
	grep -qx "0021 security_bpf_xattr runtime_only" "$WORK/status" &&
	grep -qx "0022 sleepable_inode_hooks runtime_only" "$WORK/status" &&
	grep -qx "0023 trusted_dentry_parent btf_ready" "$WORK/status" &&
	grep -qx "0024 mm_read_access btf_ready" "$WORK/status"
'

test_expect_success '0020: tpm_common_write validates headers and gates register extend' '
	[ -c /dev/tpmrm0 ] &&
	[ "$(./$H tpm /dev/tpmrm0)" = ok ]
'

test_expect_success '0021: seal reads security.bpf.shirudo on uncached inodes without MAY_READ' '
	[ "$(./$H xattr-unpriv "$MNT/wonly" "$MNT/wxdir" "$MNT/noread")" = ok ]
'

test_expect_success '0022 and 0023: sleepable inode hooks and trusted dentry->d_parent refuse mutations' '
	[ "$(./$H sleepable-inode "$MNT")" = ok ]
'

test_expect_success '0022: lsm.s/inode_copy_up refuses overlay copy-up of an uncached labelled file' '
	mkdir -p "$WORK/ov" &&
	unshare -m sh -s "$WORK/ov" "$MNT/ov_lower" <<-\EOF
		set -e
		ov=$1
		lower=$2
		mount --make-rprivate /
		mount -t tmpfs tmpfs "$ov"
		mkdir "$ov/up" "$ov/work" "$ov/merged"
		mount -t overlay overlay \
			-o "lowerdir=$lower,upperdir=$ov/up,workdir=$ov/work" \
			"$ov/merged"
		set +e
		err=$( (: >>"$ov/merged/copyup") 2>&1 )
		rc=$?
		[ "$rc" -ne 0 ] || exit 1
		case "$err" in
		*[Pp]ermission\ denied*|*[Oo]peration\ not\ permitted*) exit 0 ;;
		*) printf "%s\n" "$err" >&2; exit 1 ;;
		esac
	EOF
'

test_expect_success '0024: lsm/mm_read_access refuses read-only /proc/<pid> inspection under root' '
	"$POLICY" wait "$WORK/ready" &
	PROBE_PID=$!
	for _ in $(seq 100); do
		[ -s "$WORK/ready" ] && break
		sleep 0.05
	done &&
	[ -s "$WORK/ready" ] &&
	[ "$(./$H mm-read "$PROBE_PID")" = ok ]
'

test_done
