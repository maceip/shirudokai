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
        BLOCK_COMMENT,
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

    public enum Dialect {
        AUTO,
        MYSQL,
        POSTGRES
    }

    public static final String DIALECT_PROPERTY = "shirudo.sql.dialect";

    private static final AtomicLong OBSERVED_COUNT = new AtomicLong();
    private static final AtomicLong ENFORCED_COUNT = new AtomicLong();

    private SqlLexer() {}

    public static Dialect currentDialect() {
        String raw = System.getProperty(DIALECT_PROPERTY, "auto");
        String norm = raw.trim().toLowerCase(Locale.ROOT);
        if ("mysql".equals(norm) || "mariadb".equals(norm)) {
            return Dialect.MYSQL;
        }
        if ("postgres".equals(norm) || "postgresql".equals(norm) || "ansi".equals(norm)) {
            return Dialect.POSTGRES;
        }
        return Dialect.AUTO;
    }

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
        return tokenize(sql, true, false);
    }

    public static List<Token> tokenize(String sql, boolean backslashEscape) {
        return tokenize(sql, backslashEscape, false);
    }

    /**
     * MySQL and MariaDB take a backslash in a quoted string as an escape.
     * PostgreSQL with standard_conforming_strings, SQL Server, Oracle and
     * SQLite take it as a character, so that \' ends the string there
     * (except PostgreSQL E'...' escape strings when dialect is POSTGRES).
     */
    public static List<Token> tokenize(String sql, boolean backslashEscape,
                                       boolean hashCommentAlways) {
        return tokenize(sql, backslashEscape, hashCommentAlways, false);
    }

    private static List<Token> tokenize(String sql, boolean backslashEscape,
                                        boolean hashCommentAlways,
                                        boolean postgresEscapeStrings) {
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

            // End of an unwrapped MySQL /*! ... */ or MariaDB /*M! ... */ conditional comment.
            if (condCommentDepth > 0 && c == '*' && i + 1 < n && sql.charAt(i + 1) == '/') {
                condCommentDepth--;
                i += 2;
                continue;
            }

            // PostgreSQL E'...' / e'...' escape string literal.
            if (postgresEscapeStrings && (c == 'E' || c == 'e')
                    && (i == 0 || !isIdentPart(sql.charAt(i - 1)))
                    && i + 1 < n && sql.charAt(i + 1) == '\'') {
                i = readQuoted(sql, i + 1, '\'', true, TokenType.STRING, out);
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

            // PostgreSQL / H2 $$...$$ and $tag$...$tag$ dollar-quoted string literal.
            if (c == '$') {
                int tagEnd = readDollarTagEnd(sql, i);
                if (tagEnd > i) {
                    String delim = sql.substring(i, tagEnd + 1);
                    int closePos = sql.indexOf(delim, tagEnd + 1);
                    if (closePos < 0) {
                        out.add(new Token(TokenType.UNTERMINATED, delim));
                        return out;
                    }
                    out.add(new Token(TokenType.STRING, sql.substring(tagEnd + 1, closePos)));
                    i = closePos + delim.length();
                    continue;
                }
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

            // MySQL # line comment. In PostgreSQL, #> and #>> are JSON operators;
            // in AUTO mode only treat # as a comment when not followed by '>'.
            if (c == '#' && (hashCommentAlways
                    || (currentDialect() != Dialect.POSTGRES
                        && !(i + 1 < n && sql.charAt(i + 1) == '>')))) {
                int start = i;
                i++;
                while (i < n && sql.charAt(i) != '\n' && sql.charAt(i) != '\r') {
                    i++;
                }
                out.add(new Token(TokenType.LINE_COMMENT, sql.substring(start, i)));
                continue;
            }

            // /* ... */ block comment, /*! ... */ MySQL or /*M! ... */ MariaDB conditional comment.
            if (c == '/' && i + 1 < n && sql.charAt(i + 1) == '*') {
                boolean mysqlBang = (i + 2 < n && sql.charAt(i + 2) == '!');
                boolean mariaBang = (i + 3 < n
                        && (sql.charAt(i + 2) == 'M' || sql.charAt(i + 2) == 'm')
                        && sql.charAt(i + 3) == '!');
                if (mysqlBang || mariaBang) {
                    out.add(new Token(TokenType.CONDITIONAL_COMMENT,
                            mariaBang ? sql.substring(i, i + 4) : "/*!"));
                    i += mariaBang ? 4 : 3;
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
                int commentStart = i;
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
                out.add(new Token(TokenType.BLOCK_COMMENT, sql.substring(commentStart, i)));
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
                        || "&&".equals(two) || ":=".equals(two)
                        || "#>".equals(two)) {
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

    private static int readDollarTagEnd(String sql, int start) {
        final int n = sql.length();
        if (start + 1 >= n) {
            return -1;
        }
        char first = sql.charAt(start + 1);
        if (first == '$') {
            return start + 1;
        }
        if (!Character.isLetter(first) && first != '_') {
            return -1;
        }
        int k = start + 2;
        while (k < n && (Character.isLetterOrDigit(sql.charAt(k)) || sql.charAt(k) == '_')) {
            k++;
        }
        return (k < n && sql.charAt(k) == '$') ? k : -1;
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
     * In AUTO dialect, the agent does not know which database reads the
     * statement, so a statement with a backslash is read both ways and
     * refused when either reading is malicious or when the two readings
     * disagree on termination (one unterminated, the other not).
     */
    public static Analysis analyze(String sql) {
        return analyze(sql, currentDialect());
    }

    public static Analysis analyze(String sql, Dialect dialect) {
        if (dialect == Dialect.MYSQL) {
            return analyze(tokenize(sql, true, true, false));
        }
        if (dialect == Dialect.POSTGRES) {
            return analyze(tokenize(sql, false, false, true));
        }
        Analysis escaped = analyze(tokenize(sql, true, false, false));
        if (escaped.malicious || sql == null || sql.indexOf('\\') < 0) {
            return escaped;
        }
        Analysis literal = analyze(tokenize(sql, false, false, false));
        if (literal.malicious) {
            return literal;
        }
        return escaped;
    }

    private static Analysis analyze(List<Token> raw) {
        final int rawSize = raw.size();
        List<Token> significant = new ArrayList<>(rawSize);
        boolean sawLiteral = false;
        boolean suspiciousBlockComment = false;

        for (int idx = 0; idx < rawSize; idx++) {
            Token t = raw.get(idx);
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
            if (t.type == TokenType.BLOCK_COMMENT) {
                if (t.value.indexOf('\'') >= 0) {
                    suspiciousBlockComment = true;
                } else if (sawLiteral && followedByInjectionPivot(raw, idx + 1)) {
                    suspiciousBlockComment = true;
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

            // UNION [ALL | DISTINCT] [(]* (SELECT | VALUES | TABLE)
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
                        && ("SELECT".equals(significant.get(j).upper)
                        || "VALUES".equals(significant.get(j).upper)
                        || "TABLE".equals(significant.get(j).upper))) {
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

        if (suspiciousBlockComment) {
            return new Analysis(true, "block_comment_bypass", raw);
        }

        return new Analysis(false, null, raw);
    }

    private static boolean followedByInjectionPivot(List<Token> raw, int startIdx) {
        int k = startIdx;
        while (k < raw.size()
                && (raw.get(k).type == TokenType.BLOCK_COMMENT
                || raw.get(k).type == TokenType.LPAREN)) {
            k++;
        }
        if (k >= raw.size()) {
            return false;
        }
        Token next = raw.get(k);
        if (next.type == TokenType.SEMICOLON) {
            return true;
        }
        if (next.type == TokenType.WORD) {
            return "OR".equals(next.upper) || "AND".equals(next.upper)
                    || "UNION".equals(next.upper);
        }
        return next.type == TokenType.OPERATOR
                && ("||".equals(next.value) || "&&".equals(next.value));
    }

    private static final class SignedNum {
        final double value;
        final int nextIdx;

        SignedNum(double value, int nextIdx) {
            this.value = value;
            this.nextIdx = nextIdx;
        }
    }

    private static SignedNum readSignedNumber(List<Token> toks, int idx) {
        final int m = toks.size();
        int sign = 1;
        int cur = idx;
        boolean sawSign = false;
        while (cur < m && toks.get(cur).type == TokenType.OPERATOR
                && ("+".equals(toks.get(cur).value) || "-".equals(toks.get(cur).value))) {
            if ("-".equals(toks.get(cur).value)) {
                sign = -sign;
            }
            sawSign = true;
            cur++;
        }
        if (cur < m && toks.get(cur).type == TokenType.NUMBER) {
            double v = parseDouble(toks.get(cur).value);
            if (Double.isNaN(v)) {
                return null;
            }
            return new SignedNum(sawSign ? sign * v : v, cur + 1);
        }
        return null;
    }

    private static boolean isBooleanLiteral(Token t) {
        return t.type == TokenType.WORD
                && ("TRUE".equals(t.upper) || "FALSE".equals(t.upper));
    }

    private static boolean isTautologyAt(List<Token> toks, int pos, boolean fromOr) {
        final int m = toks.size();
        Token left = toks.get(pos);
        SignedNum leftNum = readSignedNumber(toks, pos);

        // OR TRUE / OR NOT FALSE / OR NOT 0 / OR +/-1 (at clause boundary)
        if (fromOr) {
            if (left.type == TokenType.WORD && "TRUE".equals(left.upper)
                    && isClauseEnd(toks, pos + 1)) {
                return true;
            }
            if (left.type == TokenType.WORD && "NOT".equals(left.upper) && pos + 1 < m) {
                Token arg = toks.get(pos + 1);
                if (arg.type == TokenType.WORD && "FALSE".equals(arg.upper)
                        && isClauseEnd(toks, pos + 2)) {
                    return true;
                }
                SignedNum argNum = readSignedNumber(toks, pos + 1);
                if (argNum != null && argNum.value == 0.0
                        && isClauseEnd(toks, argNum.nextIdx)) {
                    return true;
                }
            }
            if (leftNum != null && leftNum.value != 0.0
                    && isClauseEnd(toks, leftNum.nextIdx)) {
                return true;
            }
        }

        int opIdx = (leftNum != null) ? leftNum.nextIdx : pos + 1;
        if (opIdx >= m) {
            return false;
        }
        Token op = toks.get(opIdx);

        // IS [NOT] NULL / IS [NOT] TRUE / IS [NOT] FALSE on literals.
        if (op.type == TokenType.WORD && "IS".equals(op.upper)) {
            boolean hasNot = (opIdx + 1 < m && toks.get(opIdx + 1).type == TokenType.WORD
                    && "NOT".equals(toks.get(opIdx + 1).upper));
            int rhsIdx = hasNot ? opIdx + 2 : opIdx + 1;
            if (rhsIdx < m && toks.get(rhsIdx).type == TokenType.WORD) {
                String rhs = toks.get(rhsIdx).upper;
                if ("NULL".equals(rhs)) {
                    boolean leftIsNull = (leftNum == null && left.type == TokenType.WORD
                            && "NULL".equals(left.upper));
                    boolean leftIsNonNullLiteral = (leftNum != null
                            || left.type == TokenType.STRING
                            || isBooleanLiteral(left));
                    return (!hasNot && leftIsNull) || (hasNot && leftIsNonNullLiteral);
                }
                if ("TRUE".equals(rhs)) {
                    if (leftNum != null) {
                        boolean truthy = leftNum.value != 0.0;
                        return hasNot ? !truthy : truthy;
                    }
                    if (isBooleanLiteral(left)) {
                        boolean truthy = "TRUE".equals(left.upper);
                        return hasNot ? !truthy : truthy;
                    }
                }
                if ("FALSE".equals(rhs)) {
                    if (leftNum != null) {
                        boolean falsy = leftNum.value == 0.0;
                        return hasNot ? !falsy : falsy;
                    }
                    if (isBooleanLiteral(left)) {
                        boolean falsy = "FALSE".equals(left.upper);
                        return hasNot ? !falsy : falsy;
                    }
                }
            }
            return false;
        }

        // [NOT] LIKE / [NOT] ILIKE on literals (e.g. 'a' LIKE '%').
        boolean likeNeg = false;
        int likeIdx = opIdx;
        if (op.type == TokenType.WORD && "NOT".equals(op.upper) && opIdx + 1 < m) {
            likeNeg = true;
            likeIdx = opIdx + 1;
        }
        if (likeIdx < m && toks.get(likeIdx).type == TokenType.WORD
                && ("LIKE".equals(toks.get(likeIdx).upper)
                || "ILIKE".equals(toks.get(likeIdx).upper))) {
            int patIdx = likeIdx + 1;
            if (patIdx < m && toks.get(patIdx).type == TokenType.STRING) {
                String lhsLiteral = null;
                if (leftNum == null && left.type == TokenType.STRING) {
                    lhsLiteral = left.value;
                } else if (leftNum != null) {
                    lhsLiteral = toks.get(opIdx - 1).value;
                }
                if (lhsLiteral != null) {
                    boolean ci = "ILIKE".equals(toks.get(likeIdx).upper);
                    boolean matched = sqlLikeMatch(lhsLiteral, toks.get(patIdx).value, ci);
                    return likeNeg ? !matched : matched;
                }
            }
            return false;
        }

        if (op.type != TokenType.OPERATOR || !isComparisonOp(op.value)) {
            return false;
        }

        int rhsStart = opIdx + 1;
        if (rhsStart >= m) {
            return false;
        }
        SignedNum rightNum = readSignedNumber(toks, rhsStart);

        if (leftNum != null && rightNum != null) {
            return evalCompare(Double.compare(leftNum.value, rightNum.value), op.value);
        }

        if (leftNum == null && rightNum == null) {
            Token right = toks.get(rhsStart);
            if ((left.type == TokenType.STRING && right.type == TokenType.STRING)
                    || (left.type == TokenType.DOUBLE_QUOTED
                    && right.type == TokenType.DOUBLE_QUOTED)) {
                return evalCompare(left.value.compareTo(right.value), op.value);
            }
            if (isBooleanLiteral(left) && isBooleanLiteral(right)) {
                int lv = "TRUE".equals(left.upper) ? 1 : 0;
                int rv = "TRUE".equals(right.upper) ? 1 : 0;
                return evalCompare(Integer.compare(lv, rv), op.value);
            }
            if (fromOr && isIdentifierToken(left) && isIdentifierToken(right)
                    && "=".equals(op.value)
                    && left.value.equalsIgnoreCase(right.value)) {
                return true;
            }
            return false;
        }

        // String literal compared to numeric literal (e.g. '1'=1, 'a'!=1, '1'<>2).
        if (leftNum == null && left.type == TokenType.STRING && rightNum != null) {
            double lv = parseDouble(left.value.trim());
            if (!Double.isNaN(lv)) {
                return evalCompare(Double.compare(lv, rightNum.value), op.value);
            }
            return ("!=".equals(op.value) || "<>".equals(op.value)) && rightNum.value != 0.0;
        }
        if (leftNum != null && toks.get(rhsStart).type == TokenType.STRING) {
            double rv = parseDouble(toks.get(rhsStart).value.trim());
            if (!Double.isNaN(rv)) {
                return evalCompare(Double.compare(leftNum.value, rv), op.value);
            }
            return ("!=".equals(op.value) || "<>".equals(op.value)) && leftNum.value != 0.0;
        }

        return false;
    }

    private static boolean sqlLikeMatch(String text, String pattern, boolean ignoreCase) {
        String s = ignoreCase ? text.toLowerCase(Locale.ROOT) : text;
        String p = ignoreCase ? pattern.toLowerCase(Locale.ROOT) : pattern;
        int ti = 0;
        int pi = 0;
        int starIdx = -1;
        int matchIdx = 0;
        while (ti < s.length()) {
            if (pi < p.length() && (p.charAt(pi) == '_' || p.charAt(pi) == s.charAt(ti))) {
                ti++;
                pi++;
            } else if (pi < p.length() && p.charAt(pi) == '%') {
                starIdx = pi++;
                matchIdx = ti;
            } else if (starIdx >= 0) {
                pi = starIdx + 1;
                ti = ++matchIdx;
            } else {
                return false;
            }
        }
        while (pi < p.length() && p.charAt(pi) == '%') {
            pi++;
        }
        return pi == p.length();
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
