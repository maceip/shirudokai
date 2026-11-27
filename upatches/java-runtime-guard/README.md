# java-runtime-guard

The `java-runtime-guard` package installs the `java-runtime-guard` Java
upatch: a pure-JDK instrumentation agent with zero third-party
dependencies that hardens JVMs on JDK 21 and newer against two classes
of runtime exploitation, and ships a helper for a third:

- **Remote JNDI lookups**: installs `InitialContextFactoryBuilder` and
  `ObjectFactoryBuilder` hooks through `javax.naming.spi.NamingManager`
  to refuse remote `ldap://`, `ldaps://`, `rmi://`, `dns://`, `iiop://`,
  `iiopname://`, `corba://` and `corbaname://` schemes (including
  `CompositeName` quoted or escaped forms and `PROVIDER_URL` tokens),
  remote `INITIAL_CONTEXT_FACTORY` classes, and external `Reference` /
  `Referenceable` factory codebases while delegating allowed URL schemes
  through `NamingManager.getURLContext()` and instantiating local
  `ObjectFactory` classes.
- **Deserialization gadgets**: installs both a JVM-wide `ObjectInputFilter`
  and a JEP 415 `serialFilterFactory` (so per-stream
  `ObjectInputStream.setObjectInputFilter()` calls keep the guard active)
  blocking known gadget classes (`TemplatesImpl`,
  `AnnotationInvocationHandler`, `InvokerTransformer`,
  `ChainedTransformer`, `InstantiateTransformer`, `JdbcRowSetImpl`,
  `BeanComparator`, `BadAttributeValueExpException`,
  `UnicastRemoteObject`, Groovy closures and C3P0 data sources) while
  allowing standard JDK and application types.
- **Shell command injection, as a helper only**: `ShellExecGuard`
  refuses shell wrappers (`sh -c`, `bash -c`) and command strings
  carrying shell chaining or substitution metacharacters in what an
  application passes to it. The agent does **not** hook
  `ProcessBuilder.start()` or `Runtime.exec()`: an application that does
  not call `ShellExecGuard.checkCommand()` or `checkProcessBuilder()`
  itself gets no protection against command injection from this package.

Set `-Dshirudo.guard.mode=observe` to log and count matches without
blocking; the default mode is `enforce`. In observe mode a remote JNDI
lookup goes on to the network as it would without the guard.

## Limits

- The JVM accepts one `InitialContextFactoryBuilder`, one
  `ObjectFactoryBuilder`, one JVM-wide serial filter and one JEP 415
  serial filter factory. Where the application or its container set one
  first, that part of the guard is not installed. The agent says so on
  standard error (`PARTLY installed (jndi=off ...)`) and the JVM runs
  without it.
- The mode is read from the system property at each check, so code in
  the JVM that calls `System.setProperty("shirudo.guard.mode",
  "observe")` turns blocking off. The guard mitigates a bug in an
  application; it is no boundary against code that already runs in the
  JVM.

## Build

Needs a JDK of release 21 or newer (`javac` and `jar` on `PATH`), with
no external downloads:

```sh
upatches/java-runtime-guard/build.sh 1.0.0 --keys-dir <keys>
```

Pass `--jar-only` to build `java-runtime-guard.jar` alone.
