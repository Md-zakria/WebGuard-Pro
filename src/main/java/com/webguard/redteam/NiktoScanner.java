package com.webguard.redteam;

import com.webguard.models.Vulnerability;
import com.webguard.models.VulnerabilityReport;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * NiktoScanner
 *
 * Extends ToolLauncher — Step 2 of Red Team scan sequence.
 * Runs: nikto -h http://<target>:<port> -nointeractive
 *
 * Detects:
 *   - phpMyAdmin exposed
 *   - Missing security headers (CSP, X-Frame-Options)
 *   - Apache version disclosure
 *   - TRACE method enabled
 *   - /backup or /config accessible
 */
public class NiktoScanner extends ToolLauncher {

    public NiktoScanner(String target, int port, VulnerabilityReport report,
                        Consumer<String> outputCallback,
                        Consumer<Vulnerability> findingCallback) {
        super(target, port, report, outputCallback, findingCallback);
    }

    @Override
    public String getToolName() { return "nikto"; }

    @Override
    protected String[] buildCommand() {
        return new String[]{
    "perl", "C:\\nikto\\program\\plugins\\nikto_core.plugin",
    "-h", "http://" + target + ":" + port,
    "-nointeractive", "-Tuning", "1234578"
};
    }

    @Override
    protected List<Vulnerability> parseOutput(List<String> lines) {
        List<Vulnerability> findings = new ArrayList<>();

        for (String line : lines) {
            String lower = line.toLowerCase();

            if (lower.contains("phpmyadmin")) {
                findings.add(new Vulnerability(
                    "phpMyAdmin Exposed to Network",
                    Vulnerability.Severity.CRITICAL, 9.1,
                    "/phpmyadmin",
                    line.trim(),
                    "Restrict phpMyAdmin access to localhost only via .htaccess or XAMPP config.",
                    "nikto"
                ));
            }

            if (lower.contains("x-frame-options") && lower.contains("missing")) {
                findings.add(new Vulnerability(
                    "Missing X-Frame-Options Header (Clickjacking)",
                    Vulnerability.Severity.MEDIUM, 5.4,
                    "http://" + target + ":" + port,
                    line.trim(),
                    "Add 'Header always append X-Frame-Options SAMEORIGIN' to Apache config.",
                    "nikto"
                ));
            }

            if (lower.contains("content-security-policy") && lower.contains("missing")) {
                findings.add(new Vulnerability(
                    "Missing Content-Security-Policy Header",
                    Vulnerability.Severity.MEDIUM, 5.1,
                    "http://" + target + ":" + port,
                    line.trim(),
                    "Define a strict CSP header to prevent XSS and data injection attacks.",
                    "nikto"
                ));
            }

            if (lower.contains("server:") && lower.contains("apache")) {
                findings.add(new Vulnerability(
                    "Apache Version Disclosed in Server Header",
                    Vulnerability.Severity.LOW, 3.7,
                    "http://" + target + ":" + port,
                    line.trim(),
                    "Set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf.",
                    "nikto"
                ));
            }

            if (lower.contains("trace") && lower.contains("allowed")) {
                findings.add(new Vulnerability(
                    "HTTP TRACE Method Enabled (XST Risk)",
                    Vulnerability.Severity.MEDIUM, 5.8,
                    "http://" + target + ":" + port,
                    line.trim(),
                    "Add 'TraceEnable Off' to Apache httpd.conf to disable TRACE.",
                    "nikto"
                ));
            }

            if (lower.contains("/backup") || lower.contains("/config") || lower.contains("/.env")) {
                findings.add(new Vulnerability(
                    "Sensitive Directory/File Accessible",
                    Vulnerability.Severity.HIGH, 8.2,
                    line.contains("/backup") ? "/backup" : line.contains("/.env") ? "/.env" : "/config",
                    line.trim(),
                    "Move sensitive directories outside web root or block with .htaccess.",
                    "nikto"
                ));
            }
        }
        return findings;
    }

    @Override
    protected List<String> getSimulatedOutput() {
        return List.of(
            "- Nikto v2.1.6",
            "---------------------------------------------------------------------------",
            "+ Target IP:          127.0.0.1",
            "+ Target Hostname:    localhost",
            "+ Target Port:        80",
            "+ Start Time:         2026-05-06 14:23:01",
            "---------------------------------------------------------------------------",
            "+ Server: Apache/2.4.54 (Win64) PHP/8.1.6",
            "+ The anti-clickjacking X-Frame-Options header is missing. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "+ The X-Content-Type-Options header is not set.",
            "+ Missing Content-Security-Policy header.",
            "+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD, TRACE",
            "+ HTTP TRACE method is active, which suggests the host is vulnerable to XST.",
            "+ /phpmyadmin/: phpMyAdmin directory found",
            "+ /phpmyadmin/changelog.php: phpMyAdmin is for managing MySQL, you should remove it.",
            "+ /backup/: Backup directory found. Files may be available.",
            "+ OSVDB-3268: /config/: Directory indexing found.",
            "+ 8135 requests: 0 error(s) and 12 item(s) reported on remote host",
            "+ End Time: 2026-05-06 14:24:15 (74 seconds)"
        );
    }
}
