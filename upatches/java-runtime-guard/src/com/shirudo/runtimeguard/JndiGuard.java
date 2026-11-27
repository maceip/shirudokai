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
import javax.naming.Referenceable;
import javax.naming.spi.InitialContextFactory;
import javax.naming.spi.InitialContextFactoryBuilder;
import javax.naming.spi.NamingManager;
import javax.naming.spi.ObjectFactory;
import javax.naming.spi.ObjectFactoryBuilder;

/**
 * Blocks remote JNDI lookup schemes (ldap, ldaps, rmi, dns, iiop, corba),
 * remote InitialContextFactory / PROVIDER_URL configurations, and external
 * Reference factory codebases while preserving local java: lookups and local
 * ObjectFactory instantiation.
 */
public final class JndiGuard {

    private static final Set<String> BLOCKED_SCHEMES = Set.of(
            "ldap", "ldaps", "rmi", "dns", "iiop", "iiopname", "corba",
            "corbaname", "nis", "nds"
    );

    private static final String[] BLOCKED_FACTORY_PREFIXES = {
            "com.sun.jndi.ldap.",
            "com.sun.jndi.rmi.",
            "com.sun.jndi.dns.",
            "com.sun.jndi.cosnaming.",
            "com.sun.jndi.nis.",
            "com.sun.jndi.nds.",
            "com.sun.jndi.url.ldap",
            "com.sun.jndi.url.ldaps",
            "com.sun.jndi.url.rmi",
            "com.sun.jndi.url.dns",
            "com.sun.jndi.url.iiop",
            "com.sun.jndi.url.corba",
            "com.sun.jndi.url.nis",
            "com.sun.jndi.url.nds"
    };

    private static final Set<String> BLOCKED_FACTORY_SIMPLE_NAMES = Set.of(
            "LdapCtxFactory",
            "RegistryContextFactory",
            "DnsContextFactory",
            "CNCtxFactory",
            "NISCtxFactory",
            "NdsCtxFactory"
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
        if (name == null || name.isEmpty()) {
            return;
        }
        String scheme = findBlockedScheme(name);
        if (scheme == null) {
            return;
        }
        if (GuardMode.isObserve()) {
            GuardMode.recordObserve("jndi", "would block remote JNDI lookup " + name);
            return;
        }
        GuardMode.recordEnforce("jndi", "blocked remote JNDI lookup " + name);
        throw new SecurityException("Blocked remote JNDI lookup scheme '" + scheme + "': " + name);
    }

    public static void checkTarget(Name name) throws NamingException {
        if (name == null) {
            return;
        }
        for (int i = 0; i < name.size(); i++) {
            String comp = name.get(i);
            String scheme = findBlockedScheme(comp);
            if (scheme != null) {
                if (GuardMode.isObserve()) {
                    GuardMode.recordObserve("jndi", "would block remote JNDI lookup " + name);
                    return;
                }
                GuardMode.recordEnforce("jndi", "blocked remote JNDI lookup " + name);
                throw new SecurityException(
                        "Blocked remote JNDI lookup scheme '" + scheme + "': " + name);
            }
        }
        checkTarget(name.toString());
    }

    static boolean isBlockedInitialContextFactory(String rawFactory) {
        if (rawFactory == null) {
            return false;
        }
        String name = rawFactory.trim();
        if (name.isEmpty()) {
            return false;
        }
        for (String prefix : BLOCKED_FACTORY_PREFIXES) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        if (BLOCKED_FACTORY_SIMPLE_NAMES.contains(name)) {
            return true;
        }
        int dot = Math.max(name.lastIndexOf('.'), name.lastIndexOf('$'));
        return dot >= 0 && BLOCKED_FACTORY_SIMPLE_NAMES.contains(name.substring(dot + 1));
    }

    static void checkFactoryClassName(String rawFactory) {
        if (!isBlockedInitialContextFactory(rawFactory)) {
            return;
        }
        String factoryName = rawFactory.trim();
        if (GuardMode.isObserve()) {
            GuardMode.recordObserve("jndi",
                    "would block remote InitialContextFactory " + factoryName);
            return;
        }
        GuardMode.recordEnforce("jndi", "blocked remote InitialContextFactory " + factoryName);
        throw new SecurityException("Blocked remote JNDI InitialContextFactory: " + factoryName);
    }

    static void checkProviderUrl(String providerUrl) throws NamingException {
        if (providerUrl == null || providerUrl.isBlank()) {
            return;
        }
        String wholeScheme = findBlockedScheme(providerUrl);
        if (wholeScheme != null) {
            if (GuardMode.isObserve()) {
                GuardMode.recordObserve("jndi",
                        "would block remote JNDI provider URL " + providerUrl);
                return;
            }
            GuardMode.recordEnforce("jndi", "blocked remote JNDI provider URL " + providerUrl);
            throw new SecurityException(
                    "Blocked remote JNDI provider URL scheme '" + wholeScheme + "': "
                            + providerUrl);
        }
        int len = providerUrl.length();
        int i = 0;
        while (i < len) {
            while (i < len && Character.isWhitespace(providerUrl.charAt(i))) {
                i++;
            }
            int start = i;
            while (i < len && !Character.isWhitespace(providerUrl.charAt(i))) {
                i++;
            }
            if (start < i) {
                checkTarget(providerUrl.substring(start, i));
            }
        }
    }

    static void checkEnvironment(Hashtable<?, ?> env) throws NamingException {
        if (env == null) {
            return;
        }
        Object configured = env.get(Context.INITIAL_CONTEXT_FACTORY);
        if (configured instanceof String factoryName && !factoryName.isBlank()) {
            checkFactoryClassName(factoryName);
        }
        Object provider = env.get(Context.PROVIDER_URL);
        if (provider instanceof String providerUrl && !providerUrl.isBlank()) {
            checkProviderUrl(providerUrl);
        }
    }

    private static String findBlockedScheme(String raw) throws NamingException {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        String direct = extractScheme(raw);
        if (direct != null && BLOCKED_SCHEMES.contains(direct)) {
            return direct;
        }
        try {
            CompositeName cn = new CompositeName(raw);
            for (int i = 0; i < cn.size(); i++) {
                String comp = cn.get(i);
                String s = extractScheme(comp);
                if (s != null && BLOCKED_SCHEMES.contains(s)) {
                    return s;
                }
                String stripped = stripQuotesAndEscapes(comp);
                s = extractScheme(stripped);
                if (s != null && BLOCKED_SCHEMES.contains(s)) {
                    return s;
                }
            }
        } catch (NamingException e) {
            String stripped = stripQuotesAndEscapes(raw);
            String s = extractScheme(stripped);
            if (s != null && BLOCKED_SCHEMES.contains(s)) {
                return s;
            }
            throw e;
        }
        return null;
    }

    private static String stripQuotesAndEscapes(String raw) {
        int n = raw.length();
        int start = 0;
        while (start < n) {
            char c = raw.charAt(start);
            if (Character.isWhitespace(c) || c == '"' || c == '\'' || c == '\\') {
                start++;
            } else {
                break;
            }
        }
        return raw.substring(start);
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

    private static String firstScheme(String raw) throws NamingException {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        String direct = extractScheme(raw);
        if (direct != null) {
            return direct;
        }
        CompositeName cn = new CompositeName(raw);
        if (cn.size() > 0) {
            return extractScheme(cn.get(0));
        }
        return null;
    }

    private static Class<?> loadLocalClass(String className) throws ClassNotFoundException {
        ClassLoader ctxLoader = Thread.currentThread().getContextClassLoader();
        if (ctxLoader != null) {
            try {
                return Class.forName(className, false, ctxLoader);
            } catch (ClassNotFoundException ignored) {
                // fall back to system classloader
            }
        }
        return Class.forName(className, false, ClassLoader.getSystemClassLoader());
    }

    private static final class GuardContextFactoryBuilder implements InitialContextFactoryBuilder {
        @Override
        public InitialContextFactory createInitialContextFactory(Hashtable<?, ?> env)
                throws NamingException {
            checkEnvironment(env);
            Object configured = (env != null) ? env.get(Context.INITIAL_CONTEXT_FACTORY) : null;
            if (configured instanceof String rawFactory && !rawFactory.isBlank()) {
                String factoryName = rawFactory.trim();
                try {
                    Class<?> cls = loadLocalClass(factoryName);
                    InitialContextFactory delegate =
                            (InitialContextFactory) cls.getDeclaredConstructor().newInstance();
                    return e -> {
                        if (e != env) {
                            checkEnvironment(e);
                        }
                        return new GuardContext(delegate.getInitialContext(e), e, "");
                    };
                } catch (SecurityException ex) {
                    throw ex;
                } catch (Exception ex) {
                    NamingException ne = new NamingException(
                            "Cannot instantiate InitialContextFactory " + factoryName);
                    ne.setRootCause(ex);
                    throw ne;
                }
            }
            return e -> {
                if (e != env) {
                    checkEnvironment(e);
                }
                return new GuardContext(null, e, "");
            };
        }
    }

    private static final class GuardObjectFactoryBuilder implements ObjectFactoryBuilder {
        @Override
        public ObjectFactory createObjectFactory(Object obj, Hashtable<?, ?> env) {
            return (object, name, nameCtx, environment) -> {
                Reference ref = null;
                if (object instanceof Reference r) {
                    ref = r;
                } else if (object instanceof Referenceable referenceable) {
                    ref = referenceable.getReference();
                }
                if (ref == null) {
                    if (object instanceof ObjectFactory of) {
                        return of.getObjectInstance(object, name, nameCtx, environment);
                    }
                    return object;
                }
                String location = ref.getFactoryClassLocation();
                if (location != null && !location.isBlank()) {
                    if (GuardMode.isObserve()) {
                        GuardMode.recordObserve("jndi-ref",
                                "would block remote Reference codebase " + location);
                    } else {
                        GuardMode.recordEnforce("jndi-ref",
                                "blocked remote Reference codebase " + location);
                        throw new SecurityException(
                                "Blocked remote JNDI Reference codebase: " + location);
                    }
                }
                String factoryClassName = ref.getFactoryClassName();
                if (factoryClassName == null || factoryClassName.isBlank()) {
                    return ref;
                }
                Class<?> cls;
                try {
                    cls = loadLocalClass(factoryClassName.trim());
                } catch (ClassNotFoundException e) {
                    NamingException ne = new NamingException(
                            "Cannot load local ObjectFactory " + factoryClassName);
                    ne.setRootCause(e);
                    throw ne;
                }
                if (!ObjectFactory.class.isAssignableFrom(cls)) {
                    throw new NamingException(
                            "Not a javax.naming.spi.ObjectFactory: " + factoryClassName);
                }
                ObjectFactory factory =
                        (ObjectFactory) cls.getDeclaredConstructor().newInstance();
                return factory.getObjectInstance(ref, name, nameCtx, environment);
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

        private Object wrapIfContext(Object value) {
            if (value instanceof Context ctx && !(value instanceof GuardContext)) {
                return new GuardContext(ctx, env, "");
            }
            return value;
        }

        private Context resolveUrlContext(String name) throws NamingException {
            if (!prefix.isEmpty()) {
                return null;
            }
            String scheme = firstScheme(name);
            if (scheme == null) {
                return null;
            }
            return NamingManager.getURLContext(scheme, env);
        }

        private Context resolveUrlContext(Name name) throws NamingException {
            if (!prefix.isEmpty() || name.isEmpty()) {
                return null;
            }
            String scheme = extractScheme(name.get(0));
            if (scheme == null) {
                return null;
            }
            return NamingManager.getURLContext(scheme, env);
        }

        private Object lookupLocal(String name) throws NamingException {
            String key = fullKey(name);
            if (LOCAL_BINDINGS.containsKey(key)) {
                Object bound = LOCAL_BINDINGS.get(key);
                if (bound instanceof Reference || bound instanceof Referenceable) {
                    try {
                        return NamingManager.getObjectInstance(
                                bound, new CompositeName(key), this, env);
                    } catch (SecurityException | NamingException e) {
                        throw e;
                    } catch (Exception e) {
                        NamingException ne = new NamingException(
                                "Failed to resolve JNDI Reference at " + key);
                        ne.setRootCause(e);
                        throw ne;
                    }
                }
                return bound;
            }
            if (key.equals("java:") || key.equals("java:comp")
                    || key.equals("java:comp/env")) {
                return new GuardContext(null, env, key);
            }
            throw new NameNotFoundException(key);
        }

        @Override
        public Object lookup(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return wrapIfContext(delegate.lookup(name));
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return wrapIfContext(urlCtx.lookup(name));
            }
            return lookupLocal(name);
        }

        @Override
        public Object lookup(Name name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return wrapIfContext(delegate.lookup(name));
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return wrapIfContext(urlCtx.lookup(name));
            }
            return lookupLocal(name.toString());
        }

        @Override
        public void bind(String name, Object obj) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.bind(name, obj);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.bind(name, obj);
                return;
            }
            LOCAL_BINDINGS.put(fullKey(name), obj);
        }

        @Override
        public void bind(Name name, Object obj) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.bind(name, obj);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.bind(name, obj);
                return;
            }
            LOCAL_BINDINGS.put(fullKey(name.toString()), obj);
        }

        @Override
        public void rebind(String name, Object obj) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.rebind(name, obj);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.rebind(name, obj);
                return;
            }
            LOCAL_BINDINGS.put(fullKey(name), obj);
        }

        @Override
        public void rebind(Name name, Object obj) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.rebind(name, obj);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.rebind(name, obj);
                return;
            }
            LOCAL_BINDINGS.put(fullKey(name.toString()), obj);
        }

        @Override
        public void unbind(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.unbind(name);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.unbind(name);
                return;
            }
            LOCAL_BINDINGS.remove(fullKey(name));
        }

        @Override
        public void unbind(Name name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.unbind(name);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.unbind(name);
                return;
            }
            LOCAL_BINDINGS.remove(fullKey(name.toString()));
        }

        @Override
        public void rename(String oldName, String newName) throws NamingException {
            checkTarget(oldName);
            checkTarget(newName);
            if (delegate != null) {
                delegate.rename(oldName, newName);
                return;
            }
            Context urlCtx = resolveUrlContext(oldName);
            if (urlCtx != null) {
                urlCtx.rename(oldName, newName);
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
            checkTarget(oldName);
            checkTarget(newName);
            if (delegate != null) {
                delegate.rename(oldName, newName);
                return;
            }
            Context urlCtx = resolveUrlContext(oldName);
            if (urlCtx != null) {
                urlCtx.rename(oldName, newName);
                return;
            }
            Object val = LOCAL_BINDINGS.remove(fullKey(oldName.toString()));
            if (val == null) {
                throw new NameNotFoundException(oldName.toString());
            }
            LOCAL_BINDINGS.put(fullKey(newName.toString()), val);
        }

        @Override
        public NamingEnumeration<NameClassPair> list(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return delegate.list(name);
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return urlCtx.list(name);
            }
            return new EmptyEnum<>();
        }

        @Override
        public NamingEnumeration<NameClassPair> list(Name name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return delegate.list(name);
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return urlCtx.list(name);
            }
            return new EmptyEnum<>();
        }

        @Override
        public NamingEnumeration<Binding> listBindings(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return delegate.listBindings(name);
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return urlCtx.listBindings(name);
            }
            return new EmptyEnum<>();
        }

        @Override
        public NamingEnumeration<Binding> listBindings(Name name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return delegate.listBindings(name);
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return urlCtx.listBindings(name);
            }
            return new EmptyEnum<>();
        }

        @Override
        public void destroySubcontext(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.destroySubcontext(name);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.destroySubcontext(name);
            }
        }

        @Override
        public void destroySubcontext(Name name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                delegate.destroySubcontext(name);
                return;
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                urlCtx.destroySubcontext(name);
            }
        }

        @Override
        public Context createSubcontext(String name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return new GuardContext(delegate.createSubcontext(name), env, "");
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return new GuardContext(urlCtx.createSubcontext(name), env, "");
            }
            return new GuardContext(null, env, fullKey(name));
        }

        @Override
        public Context createSubcontext(Name name) throws NamingException {
            checkTarget(name);
            if (delegate != null) {
                return new GuardContext(delegate.createSubcontext(name), env, "");
            }
            Context urlCtx = resolveUrlContext(name);
            if (urlCtx != null) {
                return new GuardContext(urlCtx.createSubcontext(name), env, "");
            }
            return new GuardContext(null, env, fullKey(name.toString()));
        }

        @Override
        public Object lookupLink(String name) throws NamingException {
            return lookup(name);
        }

        @Override
        public Object lookupLink(Name name) throws NamingException {
            return lookup(name);
        }

        @Override
        public NameParser getNameParser(String name) throws NamingException {
            checkTarget(name);
            return CompositeName::new;
        }

        @Override
        public NameParser getNameParser(Name name) throws NamingException {
            checkTarget(name);
            return CompositeName::new;
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
        public Object addToEnvironment(String propName, Object propVal) throws NamingException {
            if (Context.INITIAL_CONTEXT_FACTORY.equals(propName)
                    && propVal instanceof String factoryName) {
                checkFactoryClassName(factoryName);
            } else if (Context.PROVIDER_URL.equals(propName)
                    && propVal instanceof String providerUrl) {
                checkProviderUrl(providerUrl);
            }
            if (delegate != null) {
                delegate.addToEnvironment(propName, propVal);
            }
            return env.put(propName, propVal);
        }

        @Override
        public Object removeFromEnvironment(String propName) throws NamingException {
            if (delegate != null) {
                delegate.removeFromEnvironment(propName);
            }
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
