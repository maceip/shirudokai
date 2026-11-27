// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

import java.lang.instrument.Instrumentation;
import java.sql.Connection;
import java.sql.Statement;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

public class RaspAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        install(inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        install(inst);
    }

    private static void install(Instrumentation inst) {
        System.out.println("[RASP Agent] Initializing SQL Injection Shield...");

        new AgentBuilder.Default()
            // Every class that implements JDBC Statement: execute* and addBatch(String).
            .type(ElementMatchers.isSubTypeOf(Statement.class)
                    .and(ElementMatchers.not(ElementMatchers.isInterface())))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(
                    (ElementMatchers.nameStartsWith("execute")
                        .or(ElementMatchers.named("addBatch")))
                        .and(ElementMatchers.takesArgument(0, String.class))
                )
                .intercept(Advice.to(SqlInjectionAdvisor.class))
            )
            // Every class that implements JDBC Connection: prepareStatement and prepareCall.
            .type(ElementMatchers.isSubTypeOf(Connection.class)
                    .and(ElementMatchers.not(ElementMatchers.isInterface())))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(
                    ElementMatchers.namedOneOf("prepareStatement", "prepareCall")
                        .and(ElementMatchers.takesArgument(0, String.class))
                )
                .intercept(Advice.to(SqlInjectionAdvisor.class))
            )
            .installOn(inst);
    }
}
