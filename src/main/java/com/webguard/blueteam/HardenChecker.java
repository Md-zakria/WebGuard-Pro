package com.webguard.blueteam;

import java.util.*;
import java.util.function.Consumer;

/**
 * HardenChecker — runs a hardening checklist against the DVWA/XAMPP config.
 * Data Structure: HashMap<String, CheckItem>
 * Why HashMap: each check has a unique key (check ID). HashMap gives O(1)
 * lookup to get or update any check's status without scanning the whole list.
 * Also used as a config audit map: key = config property, value = check result.
 *
 * Checks are organized into categories: PHP, Apache, DVWA, OS, Network.
 */
public class HardenChecker {

    public enum CheckResult { PASS, FAIL, WARNING, UNKNOWN }

    public static class CheckItem {
        public final String      id;
        public final String      category;
        public final String      title;
        public final String      description;
        public final String      remediation;
        public final int         weight;        // severity weight 1–10
        public CheckResult       result;
        public String            detail;        // actual observed value

        public CheckItem(String id, String category, String title,
                         String description, String remediation, int weight) {
            this.id          = id;
            this.category    = category;
            this.title       = title;
            this.description = description;
            this.remediation = remediation;
            this.weight      = weight;
            this.result      = CheckResult.UNKNOWN;
            this.detail      = "";
        }

        @Override public String toString() {
            return String.format("[%s] %s — %s: %s", category, result, title, detail);
        }
    }

    // Core data structure: HashMap<String, CheckItem> — O(1) get/put per check
    private final Map<String, CheckItem> checkMap = new LinkedHashMap<>(); // LinkedHashMap preserves insertion order for display

    private final String targetHost;
    private Consumer<String>    logCallback;
    private Consumer<CheckItem> resultCallback;

    public HardenChecker(String targetHost) {
        this.targetHost = targetHost;
        registerChecks();
    }

    public void setLogCallback(Consumer<String>    cb) { this.logCallback    = cb; }
    public void setResultCallback(Consumer<CheckItem> cb) { this.resultCallback = cb; }

    /** Register all checks. HashMap.put() = O(1). */
    private void registerChecks() {
        // ── PHP hardening ───────────────────────────────────────────────────
        put("PHP-01", "PHP", "expose_php disabled",
            "PHP version should not be revealed in HTTP headers.",
            "Set expose_php = Off in php.ini", 6);

        put("PHP-02", "PHP", "display_errors disabled",
            "Error messages must not be shown to end users.",
            "Set display_errors = Off in php.ini", 8);

        put("PHP-03", "PHP", "allow_url_include disabled",
            "Remote file inclusion must be blocked.",
            "Set allow_url_include = Off in php.ini", 9);

        put("PHP-04", "PHP", "open_basedir restriction set",
            "PHP should not be able to access files outside the web root.",
            "Set open_basedir = E:\\XAMPP\\htdocs in php.ini", 8);

        put("PHP-05", "PHP", "session.cookie_httponly enabled",
            "Session cookies should be inaccessible to JavaScript.",
            "Set session.cookie_httponly = 1 in php.ini", 7);

        // ── Apache hardening ────────────────────────────────────────────────
        put("APACHE-01", "APACHE", "Server version hidden",
            "Apache version number must not appear in error pages or headers.",
            "Set ServerTokens Prod and ServerSignature Off in httpd.conf", 6);

        put("APACHE-02", "APACHE", "Directory listing disabled",
            "Directory browsing must be off to prevent file enumeration.",
            "Set Options -Indexes in httpd.conf", 7);

        put("APACHE-03", "APACHE", "Access log enabled",
            "Access logging must be active for forensic analysis.",
            "Ensure CustomLog is configured in httpd.conf", 5);

        // ── DVWA application ────────────────────────────────────────────────
        put("DVWA-01", "DVWA", "Default admin password changed",
            "admin:password default credentials must be changed.",
            "Login to DVWA and change password under User Management", 10);

        put("DVWA-02", "DVWA", "Security level not 'low'",
            "DVWA security level should be 'medium' or 'high' for testing.",
            "Set default_security_level = 'high' in config/config.inc.php", 9);

        put("DVWA-03", "DVWA", "phpinfo.php removed",
            "phpinfo.php exposes sensitive server information.",
            "Delete E:\\XAMPP\\htdocs\\dvwa\\phpinfo.php", 8);

        put("DVWA-04", "DVWA", "setup.php access restricted",
            "setup.php should not be accessible after initial setup.",
            "Delete or password-protect setup.php after installation", 7);

        // ── Network / OS ────────────────────────────────────────────────────
        put("NET-01", "NETWORK", "DVWA only on localhost",
            "DVWA should only be reachable from 127.0.0.1, not the LAN.",
            "Bind Apache to 127.0.0.1 in httpd.conf: Listen 127.0.0.1:8080", 9);

        put("NET-02", "NETWORK", "Unnecessary ports closed",
            "Only required ports should be open (8080 for DVWA).",
            "Run netstat -an and close unused listeners", 6);

        log("[HardenChecker] Registered " + checkMap.size() + " checks.");
    }

    private void put(String id, String category, String title,
                     String description, String remediation, int weight) {
        checkMap.put(id, new CheckItem(id, category, title, description, remediation, weight));
    }

    /**
     * Run all checks. Simulates probing the target host.
     * Each check: O(1) HashMap.get() to retrieve, O(1) to update result.
     */
    public synchronized void runAllChecks() {
        log("[HardenChecker] Running " + checkMap.size() + " hardening checks against " + targetHost + " ...");
        for (CheckItem item : checkMap.values()) {
            runCheck(item);
        }
        log("[HardenChecker] Complete. Score: " + getHardeningScore() + "/100");
    }

    /** Run a single check by ID. O(1) HashMap lookup. */
    public synchronized void runCheck(String id) {
        CheckItem item = checkMap.get(id);   // O(1)
        if (item != null) runCheck(item);
    }

    private void runCheck(CheckItem item) {
        // Simulated check logic — in a real tool these would probe the live config
        CheckResult result;
        String detail;

        switch (item.id) {
            case "PHP-01" -> { result = CheckResult.FAIL;    detail = "X-Powered-By: PHP/8.1.6 header found"; }
            case "PHP-02" -> { result = CheckResult.WARNING; detail = "display_errors = On detected (XAMPP default)"; }
            case "PHP-03" -> { result = CheckResult.PASS;    detail = "allow_url_include = Off ✓"; }
            case "PHP-04" -> { result = CheckResult.FAIL;    detail = "open_basedir not set"; }
            case "PHP-05" -> { result = CheckResult.FAIL;    detail = "session.cookie_httponly = 0"; }
            case "APACHE-01" -> { result = CheckResult.FAIL;  detail = "Server: Apache/2.4.54 (Win64) PHP/8.1.6"; }
            case "APACHE-02" -> { result = CheckResult.WARNING; detail = "Options Indexes present in default vhost"; }
            case "APACHE-03" -> { result = CheckResult.PASS;  detail = "CustomLog logs/access.log combined ✓"; }
            case "DVWA-01"   -> { result = CheckResult.FAIL;  detail = "Default credentials admin:password still active"; }
            case "DVWA-02"   -> { result = CheckResult.FAIL;  detail = "Security level = low"; }
            case "DVWA-03"   -> { result = CheckResult.FAIL;  detail = "phpinfo.php returns HTTP 200"; }
            case "DVWA-04"   -> { result = CheckResult.FAIL;  detail = "setup.php accessible — HTTP 200"; }
            case "NET-01"    -> { result = CheckResult.WARNING; detail = "Apache listening on 0.0.0.0:8080 (LAN exposed)"; }
            case "NET-02"    -> { result = CheckResult.PASS;  detail = "Only port 8080 open ✓"; }
            default          -> { result = CheckResult.UNKNOWN; detail = "Check not implemented"; }
        }

        item.result = result;
        item.detail = detail;

        String symbol = switch (result) {
            case PASS    -> "✓";
            case FAIL    -> "✗";
            case WARNING -> "⚠";
            default      -> "?";
        };
        log(String.format("[HardenChecker] %s [%s] %s — %s", symbol, item.id, item.title, detail));
        if (resultCallback != null) resultCallback.accept(item);
    }

    /**
     * Calculate hardening score 0–100.
     * Score = sum of weights of PASS checks / sum of all weights × 100.
     */
    public synchronized int getHardeningScore() {
        int totalWeight = checkMap.values().stream().mapToInt(c -> c.weight).sum();
        int passWeight  = checkMap.values().stream()
                .filter(c -> c.result == CheckResult.PASS)
                .mapToInt(c -> c.weight)
                .sum();
        return totalWeight > 0 ? (passWeight * 100 / totalWeight) : 0;
    }

    /** Get all checks for a category. O(n) scan. */
    public synchronized List<CheckItem> getByCategory(String category) {
        List<CheckItem> result = new ArrayList<>();
        for (CheckItem c : checkMap.values()) {
            if (c.category.equals(category)) result.add(c);
        }
        return result;
    }

    /** Get all FAIL checks sorted by weight descending. */
    public synchronized List<CheckItem> getFailures() {
        List<CheckItem> fails = new ArrayList<>();
        for (CheckItem c : checkMap.values()) {
            if (c.result == CheckResult.FAIL || c.result == CheckResult.WARNING) fails.add(c);
        }
        fails.sort((a, b) -> b.weight - a.weight);
        return fails;
    }

    public synchronized Collection<CheckItem> getAllChecks() { return checkMap.values(); }
    public synchronized CheckItem getCheck(String id)        { return checkMap.get(id); }  // O(1)
    public synchronized int       totalChecks()              { return checkMap.size(); }
    public synchronized long      passCount()  { return checkMap.values().stream().filter(c -> c.result == CheckResult.PASS).count(); }
    public synchronized long      failCount()  { return checkMap.values().stream().filter(c -> c.result == CheckResult.FAIL).count(); }

    private void log(String msg) { if (logCallback != null) logCallback.accept(msg); }
}
