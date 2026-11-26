# java-runtime-guard

The `java-runtime-guard` package installs the `java-runtime-guard` Java
upatch: a pure-JDK instrumentation agent with zero third-party
dependencies that hardens JVMs on JDK 21 and newer against three classes
of runtime exploitation:

- **Remote JNDI lookups**: installs `InitialContextFactoryBuilder` and
  `ObjectFactoryBuilder` hooks through `javax.naming.spi.NamingManager`
  to refuse remote `ldap://`, `ldaps://`, `rmi://`, `dns://`, `iiop://`,
  `iiopname://`, `corba://` and `corbaname://` schemes and remote
  `Reference` factory codebases while preserving local `java:` (`java:comp/env`)
  contexts.
- **Deserialization gadgets**: installs a JVM-wide `ObjectInputFilter`
  blocking known gadget classes (`TemplatesImpl`,
  `AnnotationInvocationHandler`, `InvokerTransformer`,
  `ChainedTransformer`, `InstantiateTransformer`, `JdbcRowSetImpl`,
  `BeanComparator`, `BadAttributeValueExpException`,
  `UnicastRemoteObject`, Groovy closures and C3P0 data sources) while
  allowing standard JDK and application types.
- **Shell command injection**: exposes `ShellExecGuard` to refuse shell
  wrappers (`sh -c`, `bash -c`) and command strings carrying shell
  chaining or substitution metacharacters.

Set `-Dshirudo.guard.mode=observe` to log and count matches without
blocking; the default mode is `enforce`.

## Build

Needs a JDK of release 21 or newer (`javac` and `jar` on `PATH`), with
no external downloads:

```sh
upatches/java-runtime-guard/build.sh 1.0.0 --keys-dir <keys>
```

Pass `--jar-only` to build `java-runtime-guard.jar` alone.
