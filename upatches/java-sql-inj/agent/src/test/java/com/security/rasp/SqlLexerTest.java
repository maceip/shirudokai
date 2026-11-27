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
        // Benign queries, including escaped quotes, identifiers, trailing ';',
        // and JDBC '?' / '$1' parameterized prepared/callable statements.
        assertAllowed("SELECT * FROM users WHERE username = 'admin'");
        assertAllowed("SELECT * FROM users WHERE surname = 'O''Reilly'");
        assertAllowed("SELECT * FROM notes WHERE body = 'it\\'s safe\\\\'");
        assertAllowed("SELECT * FROM users WHERE first = 'O\\'Brien' AND last = 'Smith'");
        assertAllowed("SELECT `id`, \"user_name\" FROM `users` WHERE `id` = 42;");
        assertAllowed("/* ORM query hint */ SELECT u.id FROM users u WHERE u.active = TRUE AND u.role = 'staff'");
        assertAllowed("INSERT INTO audit_log (actor, msg) VALUES ('svc', 'semi;colon -- inside # literal /* ok */')");
        assertAllowed("SELECT id, email FROM users WHERE username = ? AND password_hash = ?");
        assertAllowed("SELECT * FROM orders WHERE tenant_id = ? AND (status = ? OR priority >= -1) ORDER BY created_at DESC LIMIT ?");
        assertAllowed("INSERT INTO events (kind, payload, retry_count) VALUES (?, ?, -1)");
        assertAllowed("UPDATE users SET deleted_at = NULL WHERE id = ? AND deleted_at IS NOT NULL");
        assertAllowed("SELECT * FROM users WHERE active = TRUE AND \"role\" != 'guest' AND username LIKE '%admin%'");
        assertAllowed("{call fetch_account_summary(?, ?)}");
        assertAllowed("SELECT * FROM accounts WHERE id = $1 AND status = $2");

        // Quotes, unterminated literals (including dollar quotes), and comment truncation.
        assertBlocked("SELECT * FROM users WHERE username = 'admin' OR 1=1'",
                "unterminated_quote_or_comment");
        assertBlocked("SELECT * FROM users WHERE username = $$admin",
                "unterminated_quote_or_comment");
        assertBlocked("SELECT * FROM users WHERE username = $tag$admin$other$",
                "unterminated_quote_or_comment");
        assertBlocked("SELECT * FROM users WHERE username = 'admin'-- '",
                "comment_after_literal");
        assertBlocked("SELECT * FROM users WHERE username = 'admin' # comment",
                "comment_after_literal");

        // Block-comment quote spanning and comment-after-literal pivots.
        assertBlocked("SELECT * FROM users WHERE username = 'admin'/*' AND password = '*/ OR role = 'admin'",
                "block_comment_bypass");
        assertBlocked("SELECT * FROM users WHERE username = 'admin'/**/OR role = 'admin'",
                "block_comment_bypass");
        assertBlocked("SELECT * FROM users WHERE username = 'admin'/*x*/AND role = 'admin'",
                "block_comment_bypass");

        // Boolean, signed numeric, distinct literal, IS [NOT] NULL, LIKE '%', and dollar-quote tautologies.
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
        assertBlocked("SELECT * FROM users WHERE username = '' OR -1 = -1",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR -1 < +2",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR -1",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR 'a' != 'b'",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR 'a' <> 'b'",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR '1' != 2",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR TRUE != FALSE",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR NULL IS NULL",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR 'x' IS NOT NULL",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR 1 IS NOT NULL",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR 'abc' LIKE '%'",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR 'abc' ILIKE 'A%'",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR 'abc' NOT LIKE 'xyz'",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR $$a$$ = $$a$$",
                "boolean_tautology");
        assertBlocked("SELECT * FROM users WHERE username = '' OR $q$x$q$ <> $q$y$q$",
                "boolean_tautology");

        // UNION [ALL | DISTINCT] SELECT / VALUES / TABLE and conditional comments.
        assertBlocked("SELECT id, name FROM items WHERE id = 1 UNION SELECT username, password FROM users",
                "union_select");
        assertBlocked("SELECT id, name FROM items WHERE id = 1 UNION ALL SELECT username, password FROM users",
                "union_select");
        assertBlocked("SELECT id, name FROM items WHERE id = 1 UNION VALUES (1, 'admin')",
                "union_select");
        assertBlocked("SELECT id, name FROM items WHERE id = 1 UNION ALL TABLE users",
                "union_select");
        assertBlocked("SELECT id FROM items WHERE id = 1 UNION/**/SELECT password FROM users",
                "union_select");
        assertBlocked("SELECT id FROM items WHERE id = 1 /*!50000 UNION SELECT password FROM users */",
                "mysql_conditional_comment");
        assertBlocked("SELECT id FROM items WHERE id = 1 /*M!100100 UNION SELECT password FROM users */",
                "mysql_conditional_comment");
        assertBlocked("SELECT id FROM items WHERE id = 1 /*m! OR 1=1 */",
                "mysql_conditional_comment");

        // Backslash-quote ANSI vs MySQL readings AND MySQL two-parameter \' split smuggling.
        assertBlocked("SELECT * FROM users WHERE name = '\\' UNION SELECT password FROM users --'",
                "comment_after_literal");
        assertBlocked("SELECT * FROM users WHERE name = '\\' OR 1=1 --'", null);
        assertBlocked("SELECT * FROM users WHERE username = '\\' AND password = ' OR role = 'admin'",
                "backslash_quote_smuggling");
        assertBlocked("INSERT INTO admins (u) VALUES ('\\'), ('), ('attacker'), ('x')",
                "backslash_quote_smuggling");
        assertAllowed("SELECT * FROM files WHERE path = 'C:\\\\temp\\\\a.txt'");
        assertAllowed("SELECT * FROM users WHERE name = 'O\\'Brien'");

        // Stacked statements (including preparedStatement concatenation).
        assertBlocked("SELECT * FROM users WHERE id = 1; DROP TABLE users",
                "stacked_statement");
        assertBlocked("SELECT * FROM `users` WHERE `name` = 'a'; DELETE FROM `users`",
                "stacked_statement");
        assertBlocked("SELECT * FROM users WHERE id = ? AND name = 'x'; DROP TABLE users",
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
