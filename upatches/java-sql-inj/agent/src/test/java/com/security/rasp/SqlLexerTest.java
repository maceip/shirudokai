// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

/**
 * Pure-JDK test suite for SqlLexer and observe/enforce mode switching.
 * Runs directly with javac + java without Maven or network downloads.
 */
public final class SqlLexerTest {

    private SqlLexerTest() {}

    private static void assertBlocked(String sql, String expectedReason) {
        SqlLexer.Analysis res = SqlLexer.analyze(sql);
        if (!res.malicious) {
            throw new AssertionError("Expected malicious SQL to be flagged: " + sql);
        }
        if (expectedReason != null && !expectedReason.equals(res.reason)) {
            throw new AssertionError("Expected reason '" + expectedReason
                    + "' but got '" + res.reason + "' for: " + sql);
        }
    }

    private static void assertAllowed(String sql) {
        SqlLexer.Analysis res = SqlLexer.analyze(sql);
        if (res.malicious) {
            throw new AssertionError("Expected benign SQL to pass (" + res.reason
                    + "): " + sql);
        }
    }

    public static void main(String[] args) {
        // Benign queries, including escaped quotes, identifiers, and trailing ';'.
        assertAllowed("SELECT * FROM users WHERE username = 'admin'");
        assertAllowed("SELECT * FROM users WHERE surname = 'O''Reilly'");
        assertAllowed("SELECT * FROM notes WHERE body = 'it\\'s safe\\\\'");
        assertAllowed("SELECT `id`, \"user_name\" FROM `users` WHERE `id` = 42;");
        assertAllowed("/* ORM query hint */ SELECT u.id FROM users u WHERE u.active = TRUE AND u.role = 'staff'");
        assertAllowed("INSERT INTO audit_log (actor, msg) VALUES ('svc', 'semi;colon -- inside # literal /* ok */')");

        // Quotes, unterminated literals, and comment truncation.
        assertBlocked("SELECT * FROM users WHERE username = 'admin' OR 1=1'",
                "unterminated_quote_or_comment");
        assertBlocked("SELECT * FROM users WHERE username = 'admin'-- '",
                "comment_after_literal");
        assertBlocked("SELECT * FROM users WHERE username = 'admin' # comment",
                "comment_after_literal");

        // Boolean and numeric/string tautologies.
        assertBlocked("SELECT * FROM users WHERE username = '' OR 1=1",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = 'x' OR 'a'='a'",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = \"x\" OR \"a\"=\"a\"",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE id = 5 OR 2 > 1",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = 'admin' AND '1'='1'",
                "boolean_tautology");

        // UNION [ALL] SELECT and comment-split bypasses.
        assertBlocked("SELECT id, name FROM items WHERE id = 1 UNION SELECT username, password FROM users",
                "union_select");
        assertBlocked("SELECT id, name FROM items WHERE id = 1 UNION ALL SELECT username, password FROM users",
                "union_select");
        assertBlocked("SELECT id FROM items WHERE id = 1 UNION/**/SELECT password FROM users",
                "union_select");
        assertBlocked("SELECT id FROM items WHERE id = 1 /*!50000 UNION SELECT password FROM users */",
                "mysql_conditional_comment");

        // A backslash before a quote ends the string on PostgreSQL with
        // standard_conforming_strings, SQL Server, Oracle and SQLite.
        assertBlocked("SELECT * FROM users WHERE name = '\\' UNION SELECT password FROM users --'",
                "comment_after_literal");
        assertBlocked("SELECT * FROM users WHERE name = '\\' OR 1=1 --'", null);
        assertAllowed("SELECT * FROM files WHERE path = 'C:\\\\temp\\\\a.txt'");
        assertAllowed("SELECT * FROM users WHERE name = 'O\\'Brien'");

        // Stacked statements.
        assertBlocked("SELECT * FROM users WHERE id = 1; DROP TABLE users",
                "stacked_statement");
        assertBlocked("SELECT * FROM `users` WHERE `name` = 'a'; DELETE FROM `users`",
                "stacked_statement");

        // Enforce mode throws SecurityException.
        System.setProperty("shirudo.sql.mode", "enforce");
        long enforcedBefore = SqlLexer.enforcedCount();
        boolean threw = false;
        try {
            SqlLexer.guard("SELECT * FROM users WHERE username = '' OR 'a'='a'");
        } catch (SecurityException expected) {
            threw = true;
        }
        if (!threw || SqlLexer.enforcedCount() != enforcedBefore + 1) {
            throw new AssertionError("Enforce mode did not throw SecurityException");
        }

        // Observe mode logs and increments counter without throwing.
        System.setProperty("shirudo.sql.mode", "observe");
        long observedBefore = SqlLexer.observedCount();
        SqlLexer.guard("SELECT * FROM users WHERE id = 1 UNION SELECT secret FROM keys");
        if (SqlLexer.observedCount() != observedBefore + 1) {
            throw new AssertionError("Observe mode did not record SQLi hit");
        }

        System.setProperty("shirudo.sql.mode", "enforce");
        System.out.println("SqlLexerTest: all assertions passed");
    }
}
