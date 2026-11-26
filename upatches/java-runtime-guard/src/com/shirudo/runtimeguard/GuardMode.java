// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.util.concurrent.atomic.AtomicLong;

/** Shared mode and telemetry counters for java-runtime-guard. */
public final class GuardMode {
    public static final String MODE_PROPERTY = "shirudo.guard.mode";

    private static final AtomicLong OBSERVED = new AtomicLong();
    private static final AtomicLong ENFORCED = new AtomicLong();

    private GuardMode() {}

    public static boolean isObserve() {
        String raw = System.getProperty(MODE_PROPERTY, "enforce");
        return "observe".equalsIgnoreCase(raw.trim());
    }

    public static long observedCount() {
        return OBSERVED.get();
    }

    public static long enforcedCount() {
        return ENFORCED.get();
    }

    public static void recordObserve(String subsystem, String detail) {
        OBSERVED.incrementAndGet();
        System.err.println("[SHIRUDO GUARD OBSERVE] " + subsystem + ": " + detail);
    }

    public static void recordEnforce(String subsystem, String detail) {
        ENFORCED.incrementAndGet();
        System.err.println("[SHIRUDO GUARD] " + subsystem + ": " + detail);
    }
}
