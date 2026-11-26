# java-sql-inj

The `java-sql-inj` package installs the `java-sql-inj` Java upatch: a
Byte Buddy agent that instruments every JDBC `Statement` and inspects
`execute`, `executeQuery` and `executeUpdate` queries with `SqlLexer`, a
deterministic single-pass state-machine SQL lexer with no regular
expressions or backtracking. It detects structural SQL injection across
single-quoted (`'...'`), double-quoted (`"..."`) and backtick (`` `...` ``)
tokens, escaped quotes (`''`, `\'`), `--`, `#` and `/*...*/` comments,
MySQL `/*! ... */` conditional comments, stacked statements (`;`),
`UNION [ALL] SELECT` queries, and boolean or numeric tautologies (`OR
1=1`, `'a'='a'`).

The agent does not know which database reads a statement. MySQL and
MariaDB take `\'` in a string as an escaped quote; PostgreSQL with
`standard_conforming_strings`, SQL Server, Oracle and SQLite end the
string there. A statement with a backslash is read both ways and refused
when either reading is an injection.

It does not detect blind or time-based injection (`SLEEP()`,
`pg_sleep()`), which changes no structure, MariaDB `/*M! ... */`
comments, or PostgreSQL dollar-quoted strings (`$$...$$`).

Set `-Dshirudo.sql.mode=observe` to log and count structural SQL
injection matches without throwing `SecurityException`; the default mode
is `enforce`, which throws `SecurityException` before the statement
reaches the database.

The package also ships `vulnerable-app.jar`, a small application that
concatenates its argument into a query against an in-memory H2
database, and `sql_inj_vuln`, which runs it with the options the
loaded Java upatches set.

The agent reaches only JVMs that start with
`JAVA_TOOL_OPTIONS` from `/run/environment.d/shirudo.conf`, which
systemd's user managers read, and only after it is loaded. Root can
start a JVM without it. It is a mitigation inside the application, not
a boundary against root; see `Documentation/upatches/write/java-agents.rst`.

## Build and test

`SqlLexer` and `SqlLexerTest` use only the JDK standard library and run
directly without Maven:

```sh
javac -d /tmp/sqli-classes \
	upatches/java-sql-inj/agent/src/main/java/com/security/rasp/SqlLexer.java \
	upatches/java-sql-inj/agent/src/test/java/com/security/rasp/SqlLexerTest.java
java -cp /tmp/sqli-classes com.security.rasp.SqlLexerTest
```

Building the full Byte Buddy agent and H2 demo application needs Maven
and a JDK of release 11 or newer:

```sh
upatches/java-sql-inj/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-sql-inj-0.1.0.bee` into the current directory.

## Try it on a target

Install the package, then run the application from the package
directory, once with the default request, which is blocked, and once
with a benign one, which runs:

```sh
sudo shirudo bpm install <repository>/java-sql-inj
sql_inj_vuln
sql_inj_vuln admin
```

`sudo shirudo bpm uninstall java-sql-inj` removes the agent; JVMs
started afterwards run without it.
