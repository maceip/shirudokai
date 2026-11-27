#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3017 -- runtime shields past Base64: deterministic zero-backtracking
# SqlLexer self-tests, pure-JDK java-runtime-guard .bee + -javaagent suite,
# and web-worker-guard BPF LSM package + Coccinelle checks.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
S="$REPO/shirudo"
SHB="$REPO/tools/shirudo-build/shirudo-build"
VMLINUX="$REPO/vendor/linux/vmlinux.h"

command -v javac >/dev/null 2>&1 || test_skip_all "no javac"
command -v java >/dev/null 2>&1 || test_skip_all "no java"
command -v jar >/dev/null 2>&1 || test_skip_all "no jar"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v tar >/dev/null 2>&1 || test_skip_all "no tar"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -f "$VMLINUX" ] || test_skip_all "vendor/linux/vmlinux.h not generated"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/keys" "$WORK/out"
SHIRUDO_BUILD="$SHB" "$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1 ||
	test_skip_all "shirudo genkey failed"

test_expect_success 'SqlLexer deterministic state-machine self-tests pass' '
	mkdir -p "$WORK/sql-classes" &&
	javac --release 21 -d "$WORK/sql-classes" \
		"$REPO/upatches/java-sql-inj/agent/src/main/java/com/security/rasp/SqlLexer.java" \
		"$REPO/upatches/java-sql-inj/agent/src/test/java/com/security/rasp/SqlLexerTest.java" &&
	java -cp "$WORK/sql-classes" com.security.rasp.SqlLexerTest
'

test_expect_success 'RaspAgent and SqlInjectionAdvisor compile and guard Statement/Connection SQL' '
	mkdir -p "$WORK/bb/net/bytebuddy/asm" \
		"$WORK/bb/net/bytebuddy/matcher" \
		"$WORK/bb/net/bytebuddy/agent/builder" &&
	cat >"$WORK/bb/net/bytebuddy/asm/Advice.java" <<-\JAVA &&
	package net.bytebuddy.asm;
	import java.lang.annotation.*;
	public final class Advice {
	    @Retention(RetentionPolicy.RUNTIME)
	    public @interface OnMethodEnter { boolean inline() default true; }
	    @Retention(RetentionPolicy.RUNTIME)
	    public @interface Argument { int value(); }
	    public static Advice to(Class<?> cls) { return new Advice(); }
	}
	JAVA
	cat >"$WORK/bb/net/bytebuddy/matcher/ElementMatchers.java" <<-\JAVA &&
	package net.bytebuddy.matcher;
	public final class ElementMatchers {
	    public interface Junction<T> {
	        default Junction<T> and(Junction<? super T> o) { return this; }
	        default Junction<T> or(Junction<? super T> o) { return this; }
	    }
	    public static <T> Junction<T> isSubTypeOf(Class<?> c) { return new Junction<>() {}; }
	    public static <T> Junction<T> not(Junction<? super T> m) { return new Junction<>() {}; }
	    public static <T> Junction<T> isInterface() { return new Junction<>() {}; }
	    public static <T> Junction<T> nameStartsWith(String p) { return new Junction<>() {}; }
	    public static <T> Junction<T> named(String n) { return new Junction<>() {}; }
	    public static <T> Junction<T> namedOneOf(String... n) { return new Junction<>() {}; }
	    public static <T> Junction<T> takesArgument(int i, Class<?> c) { return new Junction<>() {}; }
	}
	JAVA
	cat >"$WORK/bb/net/bytebuddy/agent/builder/AgentBuilder.java" <<-\JAVA &&
	package net.bytebuddy.agent.builder;
	import java.lang.instrument.Instrumentation;
	import java.security.ProtectionDomain;
	import net.bytebuddy.asm.Advice;
	import net.bytebuddy.matcher.ElementMatchers.Junction;
	public interface AgentBuilder {
	    interface Builder {
	        Receiver method(Junction<?> m);
	        interface Receiver { Builder intercept(Advice a); }
	    }
	    interface Transformer {
	        Builder transform(Builder b, Object td, ClassLoader cl, Object mod, ProtectionDomain pd);
	    }
	    interface Identified {
	        AgentBuilder transform(Transformer t);
	    }
	    Identified type(Junction<?> m);
	    void installOn(Instrumentation inst);
	    class Default implements AgentBuilder {
	        public Identified type(Junction<?> m) { return t -> this; }
	        public void installOn(Instrumentation inst) {}
	    }
	}
	JAVA
	cat >"$WORK/bb/AdvisorCheck.java" <<-\JAVA &&
	import com.security.rasp.RaspAgent;
	import com.security.rasp.SqlInjectionAdvisor;
	public final class AdvisorCheck {
	    public static void main(String[] args) {
	        RaspAgent.premain("", null);
	        SqlInjectionAdvisor.onEnter("SELECT * FROM users WHERE id = ? AND role = ?");
	        SqlInjectionAdvisor.onEnter("{call audit_event(?, ?)}");
	        boolean blocked = false;
	        try {
	            SqlInjectionAdvisor.onEnter("SELECT * FROM users WHERE id = ? OR -1 = -1");
	        } catch (SecurityException expected) {
	            blocked = true;
	        }
	        if (!blocked) {
	            throw new AssertionError("Expected SqlInjectionAdvisor to block SQLi");
	        }
	    }
	}
	JAVA
	javac --release 21 -cp "$WORK/sql-classes" -d "$WORK/sql-classes" \
		"$WORK/bb/net/bytebuddy/asm/Advice.java" \
		"$WORK/bb/net/bytebuddy/matcher/ElementMatchers.java" \
		"$WORK/bb/net/bytebuddy/agent/builder/AgentBuilder.java" \
		"$REPO/upatches/java-sql-inj/agent/src/main/java/com/security/rasp/SqlInjectionAdvisor.java" \
		"$REPO/upatches/java-sql-inj/agent/src/main/java/com/security/rasp/RaspAgent.java" \
		"$WORK/bb/AdvisorCheck.java" &&
	java -cp "$WORK/sql-classes" AdvisorCheck
'

test_expect_success 'java-runtime-guard builds signed .bee with pure JDK tools' '
	cp -R "$REPO/upatches/java-runtime-guard" "$WORK/java-runtime-guard" &&
	chmod +x "$WORK/java-runtime-guard/build.sh" &&
	(
		cd "$WORK/out" &&
		SHIRUDO="$S" SHIRUDO_BUILD="$SHB" \
			"$WORK/java-runtime-guard/build.sh" 1.0.0 \
			--keys-dir "$WORK/keys"
	) &&
	pkg="$WORK/out/java-runtime-guard-1.0.0.bee" &&
	test -f "$pkg" &&
	"$S" bpm info upatches "$pkg" --all >"$WORK/jrg.members" &&
	test "$(grep -c "\.upatch$" "$WORK/jrg.members")" -eq 2 &&
	member=$("$S" bpm info upatches "$pkg") &&
	tar -xOf "$pkg" "java-runtime-guard-1.0.0/$member" >"$WORK/jrg.upatch" &&
	"$S" upatch info "$WORK/jrg.upatch" --json >"$WORK/jrg.json" &&
	python3 -I - "$WORK/jrg.json" <<-\PY
	import json, sys
	d = json.load(open(sys.argv[1]))
	assert d["type"] == "load", d
	assert d["payload_type"] == "java", d
	assert d["signature_len"] > 0, d
	assert d["jar_len"] > 0, d
	PY
'

test_expect_success 'RuntimeGuardTest passes under -javaagent (JNDI, deserialization, ShellExecGuard helper, observe/enforce)' '
	mkdir -p "$WORK/jrg-test-classes" &&
	javac --release 21 \
		-cp "$WORK/java-runtime-guard/java-runtime-guard.jar" \
		-d "$WORK/jrg-test-classes" \
		"$WORK/java-runtime-guard/test/com/shirudo/runtimeguard/RuntimeGuardTest.java" &&
	java -Dshirudo.guard.mode=enforce \
		"-javaagent:$WORK/java-runtime-guard/java-runtime-guard.jar" \
		-cp "$WORK/jrg-test-classes" \
		com.shirudo.runtimeguard.RuntimeGuardTest
'

test_expect_success 'web-worker-guard builds signed BPF LSM .bee and declares web-worker policy' '
	cp -R "$REPO/upatches/web-worker-guard" "$WORK/web-worker-guard" &&
	ln -s "$REPO/bpf" "$WORK/web-worker-guard/bpf" &&
	ln -s "$REPO/vendor" "$WORK/web-worker-guard/vendor" &&
	(
		cd "$WORK/out" &&
		SHIRUDO_BUILD="$SHB" "$S" bpm build "$WORK/web-worker-guard" \
			--version 1.0.0 --keys-dir "$WORK/keys"
	) &&
	pkg="$WORK/out/web-worker-guard-1.0.0.bee" &&
	test -f "$pkg" &&
	member=$("$S" bpm info upatches "$pkg") &&
	tar -xOf "$pkg" "web-worker-guard-1.0.0/$member" >"$WORK/wwg.upatch" &&
	"$S" upatch info "$WORK/wwg.upatch" --json >"$WORK/wwg.json" &&
	python3 -I - "$WORK/wwg.json" <<-\PY
	import json, sys
	d = json.load(open(sys.argv[1]))
	assert d["type"] == "load", d
	assert d["payload_type"] == "bpf", d
	assert d["signature_len"] > 0, d
	PY
'

if command -v spatch >/dev/null 2>&1; then
	test_expect_success 'web-worker-guard.bpf.c passes bpf_ Coccinelle rules' '
		for rule in "$REPO"/testing/coccinelle/bpf_*.cocci; do
			out=$(cd "$REPO" && spatch -D report --very-quiet \
				--no-includes \
				--macro-file testing/coccinelle/bpf.macros \
				--sp-file "$rule" \
				upatches/web-worker-guard/web-worker-guard.bpf.c) || exit 1
			test -z "$out" || { printf "%s\n" "$out" >&2; exit 1; }
		done
	'
fi

test_done
