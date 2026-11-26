// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.lang.instrument.Instrumentation;

/**
 * Pure-JDK runtime guard agent installing JNDI scheme protections and
 * JVM-wide ObjectInputFilter gadget protections at startup or dynamic attach.
 * It does not hook process creation: ShellExecGuard checks only what an
 * application passes to it.
 */
public final class RuntimeGuardAgent {

    private static volatile boolean installed;

    private RuntimeGuardAgent() {}

    public static void premain(String args, Instrumentation instrumentation) throws Exception {
        installAll();
    }

    public static void agentmain(String args, Instrumentation instrumentation) throws Exception {
        installAll();
    }

    public static void main(String[] args) {
        System.out.println("shirudo java-runtime-guard agent (mode="
                + (GuardMode.isObserve() ? "observe" : "enforce") + ")");
    }

    public static synchronized void installAll() throws Exception {
        if (installed) {
            return;
        }
        boolean jndi = JndiGuard.install();
        boolean deser = DeserializationGuard.install();
        installed = jndi && deser;
        System.err.println("java-runtime-guard " + (installed ? "installed" : "PARTLY installed")
                + " (jndi=" + (jndi ? "on" : "off") + " deser=" + (deser ? "on" : "off")
                + " mode=" + (GuardMode.isObserve() ? "observe" : "enforce") + ")");
    }
}
