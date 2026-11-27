// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.io.ObjectInputFilter;
import java.util.Set;
import java.util.function.BinaryOperator;

/**
 * Installs a JVM-wide JEP 415 ObjectInputFilter and serial filter factory
 * blocking known deserialization gadget classes even when individual streams
 * install custom per-stream filters via ObjectInputStream.setObjectInputFilter.
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

    /**
     * Installs both the JVM-wide serial filter and the JEP 415 serial filter
     * factory so per-stream filters cannot drop the guard.
     */
    public static synchronized boolean install() {
        if (installed) {
            return true;
        }
        ObjectInputFilter existing = ObjectInputFilter.Config.getSerialFilter();
        ObjectInputFilter combined = withGuard(existing);
        boolean filterSet = false;
        try {
            ObjectInputFilter.Config.setSerialFilter(combined);
            filterSet = true;
        } catch (IllegalStateException e) {
            System.err.println("[SHIRUDO GUARD] deser: the JVM-wide serial filter is"
                    + " already set; gadget classes may NOT be rejected on existing streams");
        }

        BinaryOperator<ObjectInputFilter> prevFactory =
                ObjectInputFilter.Config.getSerialFilterFactory();
        BinaryOperator<ObjectInputFilter> guardFactory = (current, next) -> {
            ObjectInputFilter delegated = (prevFactory != null)
                    ? prevFactory.apply(current, next)
                    : next;
            return withGuard(delegated);
        };
        boolean factorySet = false;
        try {
            ObjectInputFilter.Config.setSerialFilterFactory(guardFactory);
            factorySet = true;
        } catch (IllegalStateException e) {
            System.err.println("[SHIRUDO GUARD] deser: the JVM-wide serial filter factory"
                    + " is already set; per-stream filters can override the guard");
        }
        installed = filterSet && factorySet;
        return installed;
    }

    private static ObjectInputFilter withGuard(ObjectInputFilter filter) {
        if (filter instanceof GuardedFilter) {
            return filter;
        }
        return new GuardedFilter(filter);
    }

    private static final class GuardedFilter implements ObjectInputFilter {
        private final ObjectInputFilter merged;

        GuardedFilter(ObjectInputFilter downstream) {
            ObjectInputFilter guardFilter = DeserializationGuard::check;
            this.merged = (downstream != null)
                    ? ObjectInputFilter.merge(guardFilter, downstream)
                    : guardFilter;
        }

        @Override
        public Status checkInput(FilterInfo filterInfo) {
            return merged.checkInput(filterInfo);
        }
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
