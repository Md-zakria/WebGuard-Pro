package com.webguard.blueteam;

import java.util.*;
import java.util.stream.Collectors;
import java.util.function.Consumer;

/**
 * PatchAdvisor — maps discovered vulnerabilities to patch recommendations.
 * Data Structure: ArrayList<PatchItem>
 * Why ArrayList: patch list is read far more often than written (O(1)
 * indexed access), and we need fast iteration for filtering/sorting.
 * Random access by index lets the UI render rows without a full traversal.
 *
 * Mirrors Red Team's exploit list — each exploit the Red Team ran maps
 * to one or more patches the Blue Team should apply.
 */
public class PatchAdvisor {

    public enum PatchStatus { PENDING, IN_PROGRESS, APPLIED, SKIPPED }

    public static class PatchItem {
        public final String       id;
        public final String       cveId;
        public final String       title;
        public final String       description;
        public final String       affectedComponent;
        public final String       remediation;
        public final double       cvssScore;
        public final String       relatedExploit;   // link back to Red Team module
        public PatchStatus        status;
        public String             notes;

        public PatchItem(String cveId, String title, String description,
                         String affectedComponent, String remediation,
                         double cvssScore, String relatedExploit) {
            this.id                = "PCH-" + cveId.replaceAll("[^\\d]", "");
            this.cveId             = cveId;
            this.title             = title;
            this.description       = description;
            this.affectedComponent = affectedComponent;
            this.remediation       = remediation;
            this.cvssScore         = cvssScore;
            this.relatedExploit    = relatedExploit;
            this.status            = PatchStatus.PENDING;
            this.notes             = "";
        }

        public AlertQueue.Severity severity() {
            if (cvssScore >= 9.0) return AlertQueue.Severity.CRITICAL;
            if (cvssScore >= 7.0) return AlertQueue.Severity.HIGH;
            if (cvssScore >= 4.0) return AlertQueue.Severity.MEDIUM;
            return AlertQueue.Severity.LOW;
        }

        @Override public String toString() {
            return String.format("[%s] %.1f  %s — %s (%s)",
                    cveId, cvssScore, title, affectedComponent, status);
        }
    }

    // Core data structure: ArrayList — O(1) indexed access, O(n) search
    private final ArrayList<PatchItem> patchList = new ArrayList<>();

    private Consumer<String> logCallback;

    public PatchAdvisor() {
        loadDefaultPatches();
    }

    public void setLogCallback(Consumer<String> cb) { this.logCallback = cb; }

    /** Pre-load patches corresponding to every Red Team exploit module. */
    private void loadDefaultPatches() {
        // SQL Injection — SqlInjectionExploit.java counterpart
        add(new PatchItem(
            "CVE-2023-23752",
            "SQL Injection via DVWA login",
            "Unsanitized user input passed directly to SQL query. " +
            "sqlmap confirmed --dbs --dump retrieval.",
            "DVWA login.php / sqli endpoint",
            "1. Use prepared statements (PDO / mysqli). " +
            "2. Enable DVWA security to 'high'. " +
            "3. Deploy WAF rule blocking OR/UNION keywords.",
            9.8, "SqlInjectionExploit"
        ));

        // XSS — XssInjector.java counterpart
        add(new PatchItem(
            "CVE-2022-24086",
            "Reflected XSS — name parameter",
            "6 XSS payloads reflected unescaped. " +
            "Allows session hijacking via document.cookie theft.",
            "DVWA xss_r endpoint",
            "1. htmlspecialchars() all output. " +
            "2. Set Content-Security-Policy header. " +
            "3. HttpOnly + SameSite=Strict cookie flags.",
            7.5, "XssInjector"
        ));

        // Brute Force — BruteForceExploit.java counterpart
        add(new PatchItem(
            "CVE-2021-41773",
            "No rate limiting on login endpoint",
            "Credential wordlist brute force succeeded. " +
            "No lockout or CAPTCHA after failed attempts.",
            "DVWA brute endpoint / login.php",
            "1. Account lockout after 5 failed attempts. " +
            "2. Add CAPTCHA. " +
            "3. Implement fail2ban rule for /dvwa/login.php. " +
            "4. Enforce bcrypt password hashing.",
            8.1, "BruteForceExploit"
        ));

        // Path Traversal — TraversalExploit.java counterpart
        add(new PatchItem(
            "CVE-2021-42013",
            "Local File Inclusion / Path Traversal",
            "LFI payloads (../../etc/passwd) returned sensitive file contents. " +
            "6 sensitive paths probed successfully.",
            "DVWA fi endpoint",
            "1. Whitelist allowed file names — no user-controlled paths. " +
            "2. chroot / open_basedir restriction in PHP. " +
            "3. Disable allow_url_include in php.ini.",
            9.0, "TraversalExploit"
        ));

        // DVWA configuration hardening
        add(new PatchItem(
            "CWE-16",
            "DVWA running in low security mode",
            "DVWA security level set to 'low' — all protections disabled. " +
            "Admin credentials unchanged from defaults.",
            "DVWA config.inc.php",
            "1. Set $_DVWA['default_security_level'] = 'high'. " +
            "2. Change default admin password. " +
            "3. Restrict DVWA to localhost only.",
            6.5, "Configuration"
        ));

        // phpinfo exposure
        add(new PatchItem(
            "CWE-200",
            "phpinfo() page publicly accessible",
            "phpinfo.php exposes PHP version, loaded modules, " +
            "server paths, and environment variables.",
            "DVWA phpinfo.php",
            "1. Delete or password-protect phpinfo.php. " +
            "2. Set expose_php = Off in php.ini. " +
            "3. Restrict access via .htaccess.",
            5.3, "TrafficMonitor"
        ));

        log("[PatchAdvisor] Loaded " + patchList.size() + " patch recommendations.");
    }

    /** Add a new patch item. ArrayList.add() = O(1) amortized. */
    public synchronized void add(PatchItem item) {
        patchList.add(item);
    }

    /** Get by index. O(1) random access — ArrayList's key advantage. */
    public synchronized PatchItem get(int index) {
        return patchList.get(index);
    }

    /** Update status of a patch. O(n) search then O(1) update. */
    public synchronized boolean updateStatus(String cveId, PatchStatus status, String notes) {
        for (PatchItem p : patchList) {      // O(n)
            if (p.cveId.equals(cveId)) {
                p.status = status;
                p.notes  = notes;
                log("[PatchAdvisor] " + cveId + " → " + status);
                return true;
            }
        }
        return false;
    }

    /** Filter by status — O(n) iteration, returns new list. */
    public synchronized List<PatchItem> filterByStatus(PatchStatus status) {
        return patchList.stream()
                .filter(p -> p.status == status)
                .collect(Collectors.toList());
    }

    /** Sort by CVSS score descending — returns a sorted copy. */
    public synchronized List<PatchItem> getSortedByCvss() {
        List<PatchItem> copy = new ArrayList<>(patchList);
        copy.sort((a, b) -> Double.compare(b.cvssScore, a.cvssScore));
        return copy;
    }

    /** Filter patches related to a specific Red Team exploit. */
    public synchronized List<PatchItem> getByExploit(String exploitName) {
        return patchList.stream()
                .filter(p -> p.relatedExploit.equals(exploitName))
                .collect(Collectors.toList());
    }

    public synchronized List<PatchItem> getAll() { return new ArrayList<>(patchList); }
    public synchronized int size()               { return patchList.size(); }

    private void log(String msg) { if (logCallback != null) logCallback.accept(msg); }
}
