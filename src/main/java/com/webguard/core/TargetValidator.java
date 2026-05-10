package com.webguard.core;

import java.util.regex.Pattern;

/**
 * TargetValidator
 *
 * SAFETY LOCK — hardcoded, cannot be bypassed.
 * Red Team Module will ONLY scan localhost and RFC-1918 private addresses.
 *
 * Accepted:
 *   localhost, 127.0.0.1
 *   192.168.x.x
 *   10.x.x.x
 *   172.16.x.x – 172.31.x.x
 *
 * Rejected:
 *   Any public IP, any external domain.
 *
 * Data Structure: none (pure logic / pattern matching)
 */
public class TargetValidator {

    // Regex patterns for allowed private/local addresses
    private static final Pattern LOCALHOST = Pattern.compile(
            "^(localhost|127\\.0\\.0\\.1)$", Pattern.CASE_INSENSITIVE);

    private static final Pattern CLASS_A_PRIVATE = Pattern.compile(
            "^10\\.(\\d{1,3}\\.){2}\\d{1,3}$");

    private static final Pattern CLASS_B_PRIVATE = Pattern.compile(
            "^172\\.(1[6-9]|2\\d|3[0-1])\\.(\\d{1,3}\\.){1}\\d{1,3}$");

    private static final Pattern CLASS_C_PRIVATE = Pattern.compile(
            "^192\\.168\\.\\d{1,3}\\.\\d{1,3}$");

    /**
     * Returns true if the target is a safe local/private address.
     * Called before any subprocess is launched.
     */
    public static boolean isAllowed(String target) {
        if (target == null || target.isBlank()) return false;
        String t = target.trim();
        return LOCALHOST.matcher(t).matches()
                || CLASS_A_PRIVATE.matcher(t).matches()
                || CLASS_B_PRIVATE.matcher(t).matches()
                || CLASS_C_PRIVATE.matcher(t).matches();
    }

    /**
     * Returns a human-readable error message for the UI.
     */
    public static String getErrorMessage(String target) {
        return "⛔  BLOCKED: \"" + target + "\" is not a local/private address.\n\n"
                + "WebGuard Pro only scans:\n"
                + "  • localhost / 127.0.0.1\n"
                + "  • 192.168.x.x  (your LAN)\n"
                + "  • 10.x.x.x\n"
                + "  • 172.16–31.x.x\n\n"
                + "This tool is for educational use on your own XAMPP lab only.";
    }
}
