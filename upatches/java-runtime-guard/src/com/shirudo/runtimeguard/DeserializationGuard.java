// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.io.ObjectInputFilter;
import java.util.Set;

/**
 * Installs a JVM-wide ObjectInputFilter blocking known deserialization gadget
 * classes while allowing normal JDK and application serializable types.
 */
public final class DeserializationGuard {

    private static final Set<String> BLOCKED_CLASSES = Set.of(
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "org.apache.xalan.xsltc.trax.TemplatesImpl",
            "sun.reflect.annotation.AnnotationInvocationHandler",
            "org.apache.commons.collections.functors.InvokerTransformer",
            "org.apache.commons.collections.functors.ChainedTransformer",
            "org.apache.commons.collections.functors.InstantiateTransformer",
            "org.apache.commons.collections4.functors.InvokerTransformer",
            "org.apache.commons.collections4.functors.ChainedTransformer",
            "org.apache.commons.collections4.functors.InstantiateTransformer",
            "com.sun.rowset.JdbcRowSetImpl",
            "org.apache.commons.beanutils.BeanComparator",
            "javax.management.BadAttributeValueExpException",
            "java.rmi.server.UnicastRemoteObject",
            "org.codehaus.groovy.runtime.ConvertedClosure",
            "org.codehaus.groovy.runtime.MethodClosure",
            "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
            "com.mchange.v2.c3p0.JndiRefForwardingDataSource"
    );

    private static final String[] BLOCKED_PREFIXES = {
            "org.apache.commons.collections.functors.",
            "org.apache.commons.collections4.functors.",
            "org.springframework.beans.factory.config.PropertyPathFactoryBean"
    };

    private static volatile boolean installed;

    private DeserializationGuard() {}

    /** Returns whether the JVM-wide filter holds the guard. */
    public static synchronized boolean install() {
        if (installed) {
            return true;
        }
        ObjectInputFilter existing = ObjectInputFilter.Config.getSerialFilter();
        ObjectInputFilter guardFilter = DeserializationGuard::check;
        ObjectInputFilter combined = (existing != null)
                ? ObjectInputFilter.merge(guardFilter, existing)
                : guardFilter;
        try {
            ObjectInputFilter.Config.setSerialFilter(combined);
            installed = true;
        } catch (IllegalStateException e) {
            System.err.println("[SHIRUDO GUARD] deser: the JVM-wide serial filter is"
                    + " already set; gadget classes are NOT rejected");
        }
        return installed;
    }

    public static boolean isBlockedClassName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (BLOCKED_CLASSES.contains(name)) {
            return true;
        }
        for (String prefix : BLOCKED_PREFIXES) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static ObjectInputFilter.Status check(ObjectInputFilter.FilterInfo info) {
        Class<?> serialClass = info.serialClass();
        if (serialClass == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        while (serialClass.isArray()) {
            serialClass = serialClass.getComponentType();
        }
        String className = serialClass.getName();
        if (!isBlockedClassName(className)) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        if (GuardMode.isObserve()) {
            GuardMode.recordObserve("deser", "would reject gadget class " + className);
            return ObjectInputFilter.Status.UNDECIDED;
        }
        GuardMode.recordEnforce("deser", "rejected gadget class " + className);
        return ObjectInputFilter.Status.REJECTED;
    }
}
