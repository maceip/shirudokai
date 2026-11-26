// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.shirudo.runtimeguard;

import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Helper guard refusing shell-wrapper invocations and command strings carrying
 * shell chaining or subshell metacharacters.
 */
public final class ShellExecGuard {

    private static final Set<String> SHELL_NAMES = Set.of(
            "sh", "bash", "dash", "ash", "zsh", "ksh", "csh", "tcsh",
            "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"
    );

    private ShellExecGuard() {}

    public static void checkCommand(String command) {
        if (command == null || command.isEmpty()) {
            return;
        }
        if (hasShellMetacharacters(command)) {
            trigger("shell metacharacters in command string: " + command);
        }
    }

    public static void checkCommand(String... cmdarray) {
        if (cmdarray == null || cmdarray.length == 0) {
            return;
        }
        String exe = baseName(cmdarray[0]);
        if (SHELL_NAMES.contains(exe)) {
            for (int i = 1; i < cmdarray.length; i++) {
                String arg = cmdarray[i];
                if ("-c".equals(arg) || "/c".equalsIgnoreCase(arg)
                        || (arg != null && arg.startsWith("-") && arg.contains("c"))) {
                    trigger("shell interpreter execution flag '" + arg + "' on " + cmdarray[0]);
                    return;
                }
            }
            trigger("direct shell interpreter spawn: " + cmdarray[0]);
        }
    }

    public static void checkProcessBuilder(ProcessBuilder pb) {
        if (pb == null) {
            return;
        }
        List<String> cmd = pb.command();
        if (cmd != null && !cmd.isEmpty()) {
            checkCommand(cmd.toArray(new String[0]));
        }
    }

    private static void trigger(String reason) {
        if (GuardMode.isObserve()) {
            GuardMode.recordObserve("exec", "would block " + reason);
            return;
        }
        GuardMode.recordEnforce("exec", "blocked " + reason);
        throw new SecurityException("Blocked unsafe command execution: " + reason);
    }

    private static String baseName(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        try {
            java.nio.file.Path p = Paths.get(path).getFileName();
            return (p != null ? p.toString() : path).toLowerCase(Locale.ROOT);
        } catch (Exception ignored) {
            int slash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
            return (slash >= 0 ? path.substring(slash + 1) : path).toLowerCase(Locale.ROOT);
        }
    }

    private static boolean hasShellMetacharacters(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ';' || c == '|' || c == '&' || c == '`'
                    || c == '\n' || c == '\r' || c == '>' || c == '<') {
                return true;
            }
            if (c == '$' && i + 1 < s.length()
                    && (s.charAt(i + 1) == '(' || s.charAt(i + 1) == '{')) {
                return true;
            }
        }
        return false;
    }
}
