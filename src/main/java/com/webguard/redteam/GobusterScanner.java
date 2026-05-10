package com.webguard.redteam;

import com.webguard.models.Vulnerability;
import com.webguard.models.VulnerabilityReport;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * GobusterScanner
 *
 * Extends ToolLauncher — Step 4 of Red Team scan sequence.
 * Directory brute force to find hidden paths on the target web server.
 * Runs: gobuster dir -u http://target:port -w /path/to/wordlist.txt
 *
 * Uses Stack (DFS) concept internally — directory discoveries are
 * pushed to the asset graph for further exploration if needed.
 */
public class GobusterScanner extends ToolLauncher {

    // High-value directories that are critical findings if exposed
    private static final List<String> CRITICAL_PATHS = List.of(
            "/backup", "/.env", "/.git", "/config", "/secret"
    );
    private static final List<String> HIGH_PATHS = List.of(
            "/phpmyadmin", "/admin", "/administrator", "/uploads", "/shell"
    );

    public GobusterScanner(String target, int port, VulnerabilityReport report,
                           Consumer<String> outputCallback,
                           Consumer<Vulnerability> findingCallback) {
        super(target, port, report, outputCallback, findingCallback);
    }

    @Override
    public String getToolName() { return "gobuster"; }

    @Override
    protected String[] buildCommand() {
        // Uses common.txt — adjust path for your OS
        String wordlist = System.getProperty("os.name").toLowerCase().contains("win")
                ? "D:\\Tools\\wordlists\\common.txt"
                : "/usr/share/wordlists/dirb/common.txt";

        return new String[]{
            "gobuster", "dir",
            "-u", "http://" + target + ":" + port,
            "-w", wordlist,
            "-t", "20",            // 20 threads
            "-q",                   // quiet — only results
            "--no-error"
        };
    }

    @Override
    protected List<Vulnerability> parseOutput(List<String> lines) {
        List<Vulnerability> findings = new ArrayList<>();

        for (String line : lines) {
            // Gobuster output format: /path  (Status: 200) [Size: 1234]
            if (!line.contains("Status: 200") && !line.contains("Status: 301")
                    && !line.contains("Status: 302")) continue;

            String path = line.split("\\s")[0].trim();

            for (String cp : CRITICAL_PATHS) {
                if (path.equalsIgnoreCase(cp)) {
                    findings.add(new Vulnerability(
                        "Critical Sensitive Path Exposed: " + path,
                        Vulnerability.Severity.CRITICAL, 9.3,
                        "http://" + target + ":" + port + path,
                        line.trim(),
                        "Move '" + path + "' outside the web root or block with .htaccess Deny from all.",
                        "gobuster"
                    ));
                }
            }

            for (String hp : HIGH_PATHS) {
                if (path.equalsIgnoreCase(hp)) {
                    findings.add(new Vulnerability(
                        "Admin/Sensitive Path Accessible: " + path,
                        Vulnerability.Severity.HIGH, 7.8,
                        "http://" + target + ":" + port + path,
                        line.trim(),
                        "Restrict access to '" + path + "' to localhost only via .htaccess.",
                        "gobuster"
                    ));
                }
            }
        }
        return findings;
    }

    @Override
    protected List<String> getSimulatedOutput() {
        return List.of(
            "/.hta                 (Status: 403) [Size: 302]",
            "/.htpasswd            (Status: 403) [Size: 302]",
            "/backup               (Status: 200) [Size: 1456]",
            "/config               (Status: 301) [Size: 340]",
            "/.env                 (Status: 200) [Size: 219]",
            "/index.php            (Status: 200) [Size: 10918]",
            "/phpmyadmin           (Status: 301) [Size: 351]",
            "/server-status        (Status: 403) [Size: 302]",
            "/uploads              (Status: 301) [Size: 344]",
            "/dvwa                 (Status: 301) [Size: 341]"
        );
    }
}
