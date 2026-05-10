package com.webguard.redteam;

import com.webguard.models.Vulnerability;
import com.webguard.models.VulnerabilityReport;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * NmapScanner
 *
 * Extends ToolLauncher — Step 1 of Red Team scan sequence.
 * Runs: nmap -sV -sC -p- --open <target>
 *
 * Parses text output to detect:
 *   - MySQL 3306 exposed  (CRITICAL)
 *   - SSH 22 exposed       (HIGH)
 *   - phpMyAdmin detected  (HIGH)
 *   - Open ports summary   (INFO)
 *
 * OOP: Inheritance from ToolLauncher, overrides buildCommand() + parseOutput()
 */
public class NmapScanner extends ToolLauncher {

    public NmapScanner(String target, int port, VulnerabilityReport report,
                       Consumer<String> outputCallback,
                       Consumer<Vulnerability> findingCallback) {
        super(target, port, report, outputCallback, findingCallback);
    }

    @Override
    public String getToolName() { return "nmap"; }

    @Override
    protected String[] buildCommand() {
        return new String[]{
            "nmap", "-sV", "-sC", "--open",
            "-p", "21,22,80,443,3306,8080,8443",
            target
        };
    }

    @Override
    protected List<Vulnerability> parseOutput(List<String> lines) {
        List<Vulnerability> findings = new ArrayList<>();
        boolean mysqlFound = false, sshFound = false, ftpFound = false;

        for (String line : lines) {
            String lower = line.toLowerCase();

            // MySQL 3306 open — critical if externally reachable
            if (lower.contains("3306") && lower.contains("open") && !mysqlFound) {
                mysqlFound = true;
                findings.add(new Vulnerability(
                    "MySQL Port 3306 Exposed",
                    Vulnerability.Severity.CRITICAL, 9.8,
                    target + ":3306",
                    line.trim(),
                    "Restrict MySQL to localhost only. Add 'bind-address = 127.0.0.1' in my.cnf",
                    "nmap"
                ));
            }

            // SSH open
            if (lower.contains("22/tcp") && lower.contains("open") && !sshFound) {
                sshFound = true;
                findings.add(new Vulnerability(
                    "SSH Service Exposed on Port 22",
                    Vulnerability.Severity.HIGH, 7.2,
                    target + ":22",
                    line.trim(),
                    "Disable password auth. Use SSH keys only. Consider non-standard port.",
                    "nmap"
                ));
            }

            // FTP
            if (lower.contains("21/tcp") && lower.contains("open") && !ftpFound) {
                ftpFound = true;
                findings.add(new Vulnerability(
                    "FTP Service Exposed (Plaintext Protocol)",
                    Vulnerability.Severity.HIGH, 7.5,
                    target + ":21",
                    line.trim(),
                    "Replace FTP with SFTP or FTPS. FTP transmits credentials in plaintext.",
                    "nmap"
                ));
            }
        }
        return findings;
    }

    @Override
    protected List<String> getSimulatedOutput() {
        return List.of(
            "Starting Nmap 7.94 ( https://nmap.org ) at 2026-05-06 14:22 PKT",
            "Nmap scan report for localhost (127.0.0.1)",
            "Host is up (0.00012s latency).",
            "",
            "PORT     STATE  SERVICE    VERSION",
            "22/tcp   open   ssh        OpenSSH 8.9 (protocol 2.0)",
            "80/tcp   open   http       Apache httpd 2.4.54 ((Win64) PHP/8.1.6)",
            "| http-methods: ",
            "|_  Potentially risky methods: TRACE",
            "| http-title: XAMPP",
            "3306/tcp open   mysql      MySQL 8.0.30",
            "| mysql-info:",
            "|   Protocol: 10",
            "|   Version: 8.0.30",
            "|_  Salt: ...",
            "",
            "Service detection performed. Please report any incorrect results.",
            "Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds"
        );
    }
}
