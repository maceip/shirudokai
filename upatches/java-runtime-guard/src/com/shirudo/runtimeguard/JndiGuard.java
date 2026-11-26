// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.util.Collections;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.naming.Binding;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NameClassPair;
import javax.naming.NameNotFoundException;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.Reference;
import javax.naming.spi.InitialContextFactory;
import javax.naming.spi.InitialContextFactoryBuilder;
import javax.naming.spi.NamingManager;
import javax.naming.spi.ObjectFactory;
import javax.naming.spi.ObjectFactoryBuilder;

/**
 * Blocks remote JNDI lookup schemes (ldap, ldaps, rmi, dns, iiop, corba)
 * and remote Reference factory codebases while preserving local java: lookups.
 */
public final class JndiGuard {

    private static final Set<String> BLOCKED_SCHEMES = Set.of(
            "ldap", "ldaps", "rmi", "dns", "iiop", "iiopname", "corba",
            "corbaname", "nis", "nds"
    );

    private static final Set<String> REMOTE_CODEBASE_SCHEMES = Set.of(
            "http", "https", "ftp", "ldap", "ldaps", "rmi"
    );

    private static final Map<String, Object> LOCAL_BINDINGS = new ConcurrentHashMap<>();
    private static volatile boolean installed;

    private JndiGuard() {}

    /**
     * The JVM takes one builder of each kind and never a second, so an
     * application or container that set its own leaves that part of the
     * guard out. Returns whether both parts are in place.
     */
    public static synchronized boolean install() throws NamingException {
        if (installed) {
            return true;
        }
        boolean contexts = false;
        boolean references = false;
        if (!NamingManager.hasInitialContextFactoryBuilder()) {
            NamingManager.setInitialContextFactoryBuilder(new GuardContextFactoryBuilder());
            contexts = true;
        } else {
            System.err.println("[SHIRUDO GUARD] jndi: an InitialContextFactoryBuilder is"
                    + " already set; remote JNDI names are NOT checked");
        }
        try {
            NamingManager.setObjectFactoryBuilder(new GuardObjectFactoryBuilder());
            references = true;
        } catch (IllegalStateException e) {
            System.err.println("[SHIRUDO GUARD] jndi: an ObjectFactoryBuilder is"
                    + " already set; remote Reference codebases are NOT checked");
        }
        installed = contexts && references;
        return installed;
    }

    public static void checkTarget(String name) throws NamingException {
        if (name == null) {
            return;
        }
        String scheme = extractScheme(name);
        if (scheme == null || !BLOCKED_SCHEMES.contains(scheme)) {
            return;
        }
        if (GuardMode.isObserve()) {
            GuardMode.recordObserve("jndi", "would block remote JNDI lookup " + name);
            return;
        }
        GuardMode.recordEnforce("jndi", "blocked remote JNDI lookup " + name);
        throw new SecurityException("Blocked remote JNDI lookup scheme '" + scheme + "': " + name);
    }

    static String extractScheme(String raw) {
        String s = raw.trim();
        int colon = s.indexOf(':');
        if (colon <= 0) {
            return null;
        }
        for (int i = 0; i < colon; i++) {
            char c = s.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '+' && c != '-' && c != '.') {
                return null;
            }
        }
        return s.substring(0, colon).toLowerCase(Locale.ROOT);
    }

    private static final class GuardContextFactoryBuilder implements InitialContextFactoryBuilder {
        @Override
        public InitialContextFactory createInitialContextFactory(Hashtable<?, ?> env)
                throws NamingException {
            Object configured = (env != null) ? env.get(Context.INITIAL_CONTEXT_FACTORY) : null;
            if (configured instanceof String factoryName && !factoryName.isEmpty()) {
                try {
                    Class<?> cls = Class.forName(factoryName, false,
                            Thread.currentThread().getContextClassLoader());
                    InitialContextFactory delegate =
                            (InitialContextFactory) cls.getDeclaredConstructor().newInstance();
                    return e -> new GuardContext(delegate.getInitialContext(e), e, "");
                } catch (Exception ex) {
                    NamingException ne = new NamingException(
                            "Cannot instantiate InitialContextFactory " + factoryName);
                    ne.setRootCause(ex);
                    throw ne;
                }
            }
            return e -> new GuardContext(null, e, "");
        }
    }

    private static final class GuardObjectFactoryBuilder implements ObjectFactoryBuilder {
        @Override
        public ObjectFactory createObjectFactory(Object obj, Hashtable<?, ?> env) {
            return (object, name, nameCtx, environment) -> {
                if (object instanceof Reference ref) {
                    String location = ref.getFactoryClassLocation();
                    if (location != null && !location.isEmpty()) {
                        String scheme = extractScheme(location);
                        if (scheme != null && REMOTE_CODEBASE_SCHEMES.contains(scheme)) {
                            if (GuardMode.isObserve()) {
                                GuardMode.recordObserve("jndi-ref",
                                        "would block remote Reference codebase " + location);
                                return null;
                            }
                            GuardMode.recordEnforce("jndi-ref",
                                    "blocked remote Reference codebase " + location);
                            throw new SecurityException(
                                    "Blocked remote JNDI Reference codebase: " + location);
                        }
                    }
                }
                return object;
            };
        }
    }

    private static final class GuardContext implements Context {
        private final Context delegate;
        private final Hashtable<Object, Object> env;
        private final String prefix;

        GuardContext(Context delegate, Hashtable<?, ?> env, String prefix) {
            this.delegate = delegate;
            this.env = new Hashtable<>();
            if (env != null) {
                this.env.putAll(env);
            }
            this.prefix = prefix;
        }

        private String fullKey(String name) {
            if (prefix.isEmpty()) {
                return name;
            }
            if (name.isEmpty()) {
                return prefix;
            }
            return prefix + "/" + name;
        }

        @Override
        public Object lookup(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return delegate.lookup(name);
            }
            String key = fullKey(name);
            if (LOCAL_BINDINGS.containsKey(key)) {
                return LOCAL_BINDINGS.get(key);
            }
            if (key.equals("java:") || key.equals("java:comp")
                    || key.equals("java:comp/env")
                    || key.startsWith("java:comp/env/")) {
                if (key.equals("java:") || key.equals("java:comp")
                        || key.equals("java:comp/env")) {
                    return new GuardContext(null, env, key);
                }
            }
            throw new NameNotFoundException(key);
        }

        @Override
        public Object lookup(Name name) throws NamingException {
            return lookup(name.toString());
        }

        @Override
        public void bind(String name, Object obj) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.bind(name, obj);
                return;
            }
            LOCAL_BINDINGS.put(fullKey(name), obj);
        }

        @Override
        public void bind(Name name, Object obj) throws NamingException {
            bind(name.toString(), obj);
        }

        @Override
        public void rebind(String name, Object obj) throws NamingException {
            bind(name, obj);
        }

        @Override
        public void rebind(Name name, Object obj) throws NamingException {
            bind(name.toString(), obj);
        }

        @Override
        public void unbind(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.unbind(name);
                return;
            }
            LOCAL_BINDINGS.remove(fullKey(name));
        }

        @Override
        public void unbind(Name name) throws NamingException {
            unbind(name.toString());
        }

        @Override
        public void rename(String oldName, String newName) throws NamingException {
            checkTarget(oldName);
            checkTarget(newName);
            if (delegate != null) {
                delegate.rename(oldName, newName);
                return;
            }
            Object val = LOCAL_BINDINGS.remove(fullKey(oldName));
            if (val == null) {
                throw new NameNotFoundException(oldName);
            }
            LOCAL_BINDINGS.put(fullKey(newName), val);
        }

        @Override
        public void rename(Name oldName, Name newName) throws NamingException {
            rename(oldName.toString(), newName.toString());
        }

        @Override
        public NamingEnumeration<NameClassPair> list(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return delegate.list(name);
            }
            return new EmptyEnum<>();
        }

        @Override
        public NamingEnumeration<NameClassPair> list(Name name) throws NamingException {
            return list(name.toString());
        }

        @Override
        public NamingEnumeration<Binding> listBindings(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return delegate.listBindings(name);
            }
            return new EmptyEnum<>();
        }

        @Override
        public NamingEnumeration<Binding> listBindings(Name name) throws NamingException {
            return listBindings(name.toString());
        }

        @Override
        public void destroySubcontext(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.destroySubcontext(name);
            }
        }

        @Override
        public void destroySubcontext(Name name) throws NamingException {
            destroySubcontext(name.toString());
        }

        @Override
        public Context createSubcontext(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return new GuardContext(delegate.createSubcontext(name), env, "");
            }
            return new GuardContext(null, env, fullKey(name));
        }

        @Override
        public Context createSubcontext(Name name) throws NamingException {
            return createSubcontext(name.toString());
        }

        @Override
        public Object lookupLink(String name) throws NamingException {
            return lookup(name);
        }

        @Override
        public Object lookupLink(Name name) throws NamingException {
            return lookup(name.toString());
        }

        @Override
        public NameParser getNameParser(String name) throws NamingException {
            checkTarget(name);
            return CompositeName::new;
        }

        @Override
        public NameParser getNameParser(Name name) throws NamingException {
            return getNameParser(name.toString());
        }

        @Override
        public Name composeName(Name name, Name prefixName) throws NamingException {
            Name result = (Name) prefixName.clone();
            result.addAll(name);
            return result;
        }

        @Override
        public String composeName(String name, String prefixName) {
            return prefixName.isEmpty() ? name : prefixName + "/" + name;
        }

        @Override
        public Object addToEnvironment(String propName, Object propVal) {
            return env.put(propName, propVal);
        }

        @Override
        public Object removeFromEnvironment(String propName) {
            return env.remove(propName);
        }

        @Override
        public Hashtable<?, ?> getEnvironment() {
            return new Hashtable<>(env);
        }

        @Override
        public void close() throws NamingException {
            if (delegate != null) {
                delegate.close();
            }
        }

        @Override
        public String getNameInNamespace() throws NamingException {
            if (delegate != null) {
                return delegate.getNameInNamespace();
            }
            return prefix;
        }
    }

    private static final class EmptyEnum<T> implements NamingEnumeration<T> {
        private final java.util.Enumeration<T> empty = Collections.emptyEnumeration();

        @Override
        public T next() throws NamingException {
            throw new OperationNotSupportedException("empty");
        }

        @Override
        public boolean hasMore() {
            return false;
        }

        @Override
        public void close() {}

        @Override
        public boolean hasMoreElements() {
            return empty.hasMoreElements();
        }

        @Override
        public T nextElement() {
            return empty.nextElement();
        }
    }
}
