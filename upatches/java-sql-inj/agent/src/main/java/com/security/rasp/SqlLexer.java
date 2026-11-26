// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Deterministic single-pass O(n) SQL lexer and structural injection detector.
 * No regular expressions or backtracking are used.
 */
public final class SqlLexer {

    public enum TokenType {
        WORD,
        STRING,
        DOUBLE_QUOTED,
        BACKTICK_IDENT,
        NUMBER,
        OPERATOR,
        SEMICOLON,
        LPAREN,
        RPAREN,
        COMMA,
        LINE_COMMENT,
        CONDITIONAL_COMMENT,
        UNTERMINATED
    }

    public static final class Token {
        public final TokenType type;
        public final String value;
        public final String upper;

        public Token(TokenType type, String value) {
            this.type = type;
            this.value = value;
            this.upper = (type == TokenType.WORD)
                    ? value.toUpperCase(Locale.ROOT)
                    : value;
        }
    }

    public static final class Analysis {
        public final boolean malicious;
        public final String reason;
        public final List<Token> tokens;

        private Analysis(boolean malicious, String reason, List<Token> tokens) {
            this.malicious = malicious;
            this.reason = reason;
            this.tokens = tokens;
        }
    }

    private static final AtomicLong OBSERVED_COUNT = new AtomicLong();
    private static final AtomicLong ENFORCED_COUNT = new AtomicLong();

    private SqlLexer() {}

    public static long observedCount() {
        return OBSERVED_COUNT.get();
    }

    public static long enforcedCount() {
        return ENFORCED_COUNT.get();
    }

    public static boolean isObserveMode() {
        String mode = System.getProperty("shirudo.sql.mode", "enforce");
        return "observe".equalsIgnoreCase(mode.trim());
    }

    public static void guard(String sql) {
        if (sql == null || sql.isEmpty()) {
            return;
        }
        Analysis res = analyze(sql);
        if (!res.malicious) {
            return;
        }
        if (isObserveMode()) {
            OBSERVED_COUNT.incrementAndGet();
            System.err.println("[RASP OBSERVE] SQL Injection Attempt Detected ("
                    + res.reason + "): " + sql);
            return;
        }
        ENFORCED_COUNT.incrementAndGet();
        System.err.println("[RASP ALERT] SQL Injection Attempt Detected: " + sql);
        throw new SecurityException(
                "Request blocked by RASP: Malicious SQL patterns detected ("
                        + res.reason + ").");
    }

    public static List<Token> tokenize(String sql) {
        return tokenize(sql, true);
    }

    /**
     * MySQL and MariaDB take a backslash in a quoted string as an escape.
     * PostgreSQL with standard_conforming_strings, SQL Server, Oracle and
     * SQLite take it as a character, so that \' ends the string there.
     */
    public static List<Token> tokenize(String sql, boolean backslashEscape) {
        List<Token> out = new ArrayList<>();
        if (sql == null) {
            return out;
        }
        final int n = sql.length();
        int i = 0;
        int condCommentDepth = 0;

        while (i < n) {
            char c = sql.charAt(i);

            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }

            // End of an unwrapped MySQL /*! ... */ conditional comment.
            if (condCommentDepth > 0 && c == '*' && i + 1 < n && sql.charAt(i + 1) == '/') {
                condCommentDepth--;
                i += 2;
                continue;
            }

            // Single-quoted string literal: handles '' and \' and \\.
            if (c == '\'') {
                i = readQuoted(sql, i, '\'', backslashEscape, TokenType.STRING, out);
                continue;
            }

            // Double-quoted identifier or string: handles "" and \" and \\.
            if (c == '"') {
                i = readQuoted(sql, i, '"', backslashEscape, TokenType.DOUBLE_QUOTED, out);
                continue;
            }

            // Backtick-quoted identifier: handles ``.
            if (c == '`') {
                i = readQuoted(sql, i, '`', false, TokenType.BACKTICK_IDENT, out);
                continue;
            }

            // -- line comment.
            if (c == '-' && i + 1 < n && sql.charAt(i + 1) == '-') {
                int start = i;
                i += 2;
                while (i < n && sql.charAt(i) != '\n' && sql.charAt(i) != '\r') {
                    i++;
                }
                out.add(new Token(TokenType.LINE_COMMENT, sql.substring(start, i)));
                continue;
            }

            // MySQL # line comment.
            if (c == '#') {
                int start = i;
                i++;
                while (i < n && sql.charAt(i) != '\n' && sql.charAt(i) != '\r') {
                    i++;
                }
                out.add(new Token(TokenType.LINE_COMMENT, sql.substring(start, i)));
                continue;
            }

            // /* ... */ block comment or /*! ... */ MySQL conditional comment.
            if (c == '/' && i + 1 < n && sql.charAt(i + 1) == '*') {
                if (i + 2 < n && sql.charAt(i + 2) == '!') {
                    out.add(new Token(TokenType.CONDITIONAL_COMMENT, "/*!"));
                    i += 3;
                    // Optional 5-6 digit MySQL version prefix inside /*!50000 ... */
                    int digits = 0;
                    while (i + digits < n && digits < 6
                            && Character.isDigit(sql.charAt(i + digits))) {
                        digits++;
                    }
                    if (digits >= 5) {
                        i += digits;
                    }
                    condCommentDepth++;
                    continue;
                }
                i += 2;
                boolean closed = false;
                while (i + 1 < n) {
                    if (sql.charAt(i) == '*' && sql.charAt(i + 1) == '/') {
                        i += 2;
                        closed = true;
                        break;
                    }
                    i++;
                }
                if (!closed) {
                    out.add(new Token(TokenType.UNTERMINATED, "/*"));
                    return out;
                }
                continue;
            }

            if (c == ';') {
                out.add(new Token(TokenType.SEMICOLON, ";"));
                i++;
                continue;
            }
            if (c == '(') {
                out.add(new Token(TokenType.LPAREN, "("));
                i++;
                continue;
            }
            if (c == ')') {
                out.add(new Token(TokenType.RPAREN, ")"));
                i++;
                continue;
            }
            if (c == ',') {
                out.add(new Token(TokenType.COMMA, ","));
                i++;
                continue;
            }

            // Numeric literal (decimal or 0x hex).
            if (Character.isDigit(c)) {
                int start = i;
                if (c == '0' && i + 1 < n
                        && (sql.charAt(i + 1) == 'x' || sql.charAt(i + 1) == 'X')) {
                    i += 2;
                    while (i < n && isHexDigit(sql.charAt(i))) {
                        i++;
                    }
                } else {
                    while (i < n && Character.isDigit(sql.charAt(i))) {
                        i++;
                    }
                    if (i < n && sql.charAt(i) == '.' && i + 1 < n
                            && Character.isDigit(sql.charAt(i + 1))) {
                        i++;
                        while (i < n && Character.isDigit(sql.charAt(i))) {
                            i++;
                        }
                    }
                }
                out.add(new Token(TokenType.NUMBER, sql.substring(start, i)));
                continue;
            }

            // Bare identifier / SQL keyword.
            if (isIdentStart(c)) {
                int start = i;
                i++;
                while (i < n && isIdentPart(sql.charAt(i))) {
                    i++;
                }
                out.add(new Token(TokenType.WORD, sql.substring(start, i)));
                continue;
            }

            // Multi-character comparison & logical operators.
            if (i + 1 < n) {
                String two = sql.substring(i, i + 2);
                if ("!=".equals(two) || "<>".equals(two) || "<=".equals(two)
                        || ">=".equals(two) || "||".equals(two)
                        || "&&".equals(two) || ":=".equals(two)) {
                    out.add(new Token(TokenType.OPERATOR, two));
                    i += 2;
                    continue;
                }
            }
            out.add(new Token(TokenType.OPERATOR, String.valueOf(c)));
            i++;
        }

        if (condCommentDepth > 0) {
            out.add(new Token(TokenType.UNTERMINATED, "/*!"));
        }
        return out;
    }

    private static int readQuoted(String sql, int start, char quote,
                                  boolean backslashEscape, TokenType type,
                                  List<Token> out) {
        final int n = sql.length();
        StringBuilder sb = new StringBuilder();
        int i = start + 1;
        while (i < n) {
            char ch = sql.charAt(i);
            if (backslashEscape && ch == '\\') {
                if (i + 1 >= n) {
                    out.add(new Token(TokenType.UNTERMINATED, String.valueOf(quote)));
                    return n;
                }
                sb.append(sql.charAt(i + 1));
                i += 2;
                continue;
            }
            if (ch == quote) {
                if (i + 1 < n && sql.charAt(i + 1) == quote) {
                    sb.append(quote);
                    i += 2;
                    continue;
                }
                out.add(new Token(type, sb.toString()));
                return i + 1;
            }
            sb.append(ch);
            i++;
        }
        out.add(new Token(TokenType.UNTERMINATED, String.valueOf(quote)));
        return n;
    }

    /**
     * The agent does not know which database reads the statement, so a
     * statement with a backslash is read both ways and refused when
     * either reading is an injection. A string that MySQL ends properly
     * is often unterminated in the other reading, 'it\\'s', so that
     * reading alone does not refuse a statement for an open quote.
     */
    public static Analysis analyze(String sql) {
        Analysis escaped = analyze(tokenize(sql, true));
        if (escaped.malicious || sql == null || sql.indexOf('\\') < 0) {
            return escaped;
        }
        Analysis literal = analyze(tokenize(sql, false));
        if (literal.malicious
                && !"unterminated_quote_or_comment".equals(literal.reason)) {
            return literal;
        }
        return escaped;
    }

    private static Analysis analyze(List<Token> raw) {
        List<Token> significant = new ArrayList<>(raw.size());
        boolean sawLiteral = false;

        for (Token t : raw) {
            if (t.type == TokenType.UNTERMINATED) {
                return new Analysis(true, "unterminated_quote_or_comment", raw);
            }
            if (t.type == TokenType.CONDITIONAL_COMMENT) {
                return new Analysis(true, "mysql_conditional_comment", raw);
            }
            if (t.type == TokenType.STRING || t.type == TokenType.DOUBLE_QUOTED) {
                sawLiteral = true;
            }
            if (t.type == TokenType.LINE_COMMENT) {
                if (sawLiteral) {
                    return new Analysis(true, "comment_after_literal", raw);
                }
                continue;
            }
            significant.add(t);
        }

        final int m = significant.size();
        for (int i = 0; i < m; i++) {
            Token cur = significant.get(i);

            // Stacked query: semicolon followed by any statement token.
            if (cur.type == TokenType.SEMICOLON && i + 1 < m) {
                return new Analysis(true, "stacked_statement", raw);
            }

            // UNION [ALL | DISTINCT] [(]* SELECT
            if (cur.type == TokenType.WORD && "UNION".equals(cur.upper)) {
                int j = i + 1;
                if (j < m && significant.get(j).type == TokenType.WORD
                        && ("ALL".equals(significant.get(j).upper)
                        || "DISTINCT".equals(significant.get(j).upper))) {
                    j++;
                }
                while (j < m && significant.get(j).type == TokenType.LPAREN) {
                    j++;
                }
                if (j < m && significant.get(j).type == TokenType.WORD
                        && "SELECT".equals(significant.get(j).upper)) {
                    return new Analysis(true, "union_select", raw);
                }
            }

            // Logical OR / || / AND / && followed by a tautology.
            boolean isOr = (cur.type == TokenType.WORD && "OR".equals(cur.upper))
                    || (cur.type == TokenType.OPERATOR && "||".equals(cur.value));
            boolean isAnd = (cur.type == TokenType.WORD && "AND".equals(cur.upper))
                    || (cur.type == TokenType.OPERATOR && "&&".equals(cur.value));
            if (isOr || isAnd) {
                int j = i + 1;
                while (j < m && significant.get(j).type == TokenType.LPAREN) {
                    j++;
                }
                if (j < m && isTautologyAt(significant, j, isOr)) {
                    return new Analysis(true, "boolean_tautology", raw);
                }
            }
        }

        return new Analysis(false, null, raw);
    }

    private static boolean isTautologyAt(List<Token> toks, int pos, boolean fromOr) {
        final int m = toks.size();
        Token left = toks.get(pos);

        // OR TRUE / OR NOT FALSE / OR NOT 0 / OR 1 (at clause boundary)
        if (fromOr) {
            if (left.type == TokenType.WORD && "TRUE".equals(left.upper)
                    && isClauseEnd(toks, pos + 1)) {
                return true;
            }
            if (left.type == TokenType.WORD && "NOT".equals(left.upper) && pos + 1 < m) {
                Token arg = toks.get(pos + 1);
                if (((arg.type == TokenType.WORD && "FALSE".equals(arg.upper))
                        || (arg.type == TokenType.NUMBER && parseDouble(arg.value) == 0.0))
                        && isClauseEnd(toks, pos + 2)) {
                    return true;
                }
            }
            if (left.type == TokenType.NUMBER && parseDouble(left.value) != 0.0
                    && isClauseEnd(toks, pos + 1)) {
                return true;
            }
        }

        if (pos + 2 >= m) {
            return false;
        }
        Token op = toks.get(pos + 1);
        Token right = toks.get(pos + 2);
        if (op.type != TokenType.OPERATOR || !isComparisonOp(op.value)) {
            return false;
        }

        if (left.type == TokenType.NUMBER && right.type == TokenType.NUMBER) {
            double a = parseDouble(left.value);
            double b = parseDouble(right.value);
            return evalCompare(Double.compare(a, b), op.value);
        }

        if ((left.type == TokenType.STRING && right.type == TokenType.STRING)
                || (left.type == TokenType.DOUBLE_QUOTED
                && right.type == TokenType.DOUBLE_QUOTED)) {
            return evalCompare(left.value.compareTo(right.value), op.value);
        }

        if (fromOr && isIdentifierToken(left) && isIdentifierToken(right)
                && "=".equals(op.value)
                && left.value.equalsIgnoreCase(right.value)) {
            return true;
        }

        return false;
    }

    private static boolean isClauseEnd(List<Token> toks, int idx) {
        if (idx >= toks.size()) {
            return true;
        }
        Token t = toks.get(idx);
        if (t.type == TokenType.RPAREN || t.type == TokenType.SEMICOLON) {
            return true;
        }
        return t.type == TokenType.WORD
                && ("OR".equals(t.upper) || "AND".equals(t.upper)
                || "ORDER".equals(t.upper) || "GROUP".equals(t.upper)
                || "LIMIT".equals(t.upper) || "UNION".equals(t.upper));
    }

    private static boolean isIdentifierToken(Token t) {
        return t.type == TokenType.WORD || t.type == TokenType.BACKTICK_IDENT;
    }

    private static boolean isComparisonOp(String op) {
        return "=".equals(op) || "!=".equals(op) || "<>".equals(op)
                || "<".equals(op) || ">".equals(op)
                || "<=".equals(op) || ">=".equals(op);
    }

    private static boolean evalCompare(int cmp, String op) {
        switch (op) {
            case "=":
                return cmp == 0;
            case "!=":
            case "<>":
                return cmp != 0;
            case "<":
                return cmp < 0;
            case ">":
                return cmp > 0;
            case "<=":
                return cmp <= 0;
            case ">=":
                return cmp >= 0;
            default:
                return false;
        }
    }

    private static double parseDouble(String s) {
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                return (double) Long.parseUnsignedLong(s.substring(2), 16);
            }
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return Double.NaN;
        }
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }

    private static boolean isIdentStart(char c) {
        return Character.isLetter(c) || c == '_' || c == '$' || c == '@';
    }

    private static boolean isIdentPart(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$' || c == '.';
    }
}
