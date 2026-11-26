#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the Java runtime guard agent jar with pure JDK tools (release 21+),
# then build the signed .bee package into the current directory:
#   upatches/java-runtime-guard/build.sh [--jar-only] <version> [bpm build options...]

set -eu

jar_only=0
if [ "${1:-}" = --jar-only ]; then jar_only=1; shift; fi
if [ "$jar_only" -eq 0 ]; then
	[ $# -ge 1 ] || { echo "usage: $0 [--jar-only] <version> [bpm build options...]" >&2; exit 2; }
	version=$1
	shift
fi
pkg=$(cd "$(dirname "$0")" && pwd)
start=$PWD

cd "$pkg"
rm -rf target
mkdir -p target/classes
javac --release 21 -d target/classes src/com/shirudo/runtimeguard/*.java
cat > target/MANIFEST.MF <<'MF'
Manifest-Version: 1.0
Premain-Class: com.shirudo.runtimeguard.RuntimeGuardAgent
Agent-Class: com.shirudo.runtimeguard.RuntimeGuardAgent
Main-Class: com.shirudo.runtimeguard.RuntimeGuardAgent
MF
jar cfm java-runtime-guard.jar target/MANIFEST.MF -C target/classes .

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec "${SHIRUDO:-shirudo}" bpm build "$pkg" --version "$version" "$@"
