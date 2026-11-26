// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

import net.bytebuddy.asm.Advice;

public class SqlInjectionAdvisor {

    @Advice.OnMethodEnter(inline = false)
    public static void onEnter(@Advice.Argument(0) String sql) {
        SqlLexer.guard(sql);
    }
}
