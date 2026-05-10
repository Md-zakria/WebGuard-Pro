package com.webguard.redteam;

import com.webguard.models.Vulnerability;
import com.webguard.models.VulnerabilityReport;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * ToolLauncher (Abstract)
 *
 * Abstract base class for all four Red Team tool integrations.
 * Demonstrates OOP Abstraction — defines the contract for every scanner.
 *
 * Subclasses:
 *   NmapScanner, NiktoScanner, SqlmapScanner, GobusterScanner
 *
 * Each subclass implements:
 *   buildCommand()   — constructs the subprocess command for its specific tool
 *   parseOutput()    — parses tool-specific output format into Vulnerability objects
 *   getToolName()    — display name shown in GUI
 *
 * This class handles:
 *   - Subprocess launching (common to all tools)
 *   - Live output streaming to GUI via outputCallback (uses Queue internally)
 *   - Feeding parsed findings into VulnerabilityReport
 */
public abstract class ToolLauncher {

    protected String target;
    protected int    port;
    protected VulnerabilityReport report;
    protected Consumer<String>    outputCallback;   // sends each output line to GUI
    protected Consumer<Vulnerability> findingCallback; // sends each finding to GUI live

    private Process currentProcess;

    public ToolLauncher(String target, int port, VulnerabilityReport report,
                        Consumer<String> outputCallback,
                        Consumer<Vulnerability> findingCallback) {
        this.target          = target;
        this.port            = port;
        this.report          = report;
        this.outputCallback  = outputCallback;
        this.findingCallback = findingCallback;
    }

    /** Subclass returns the full command as a String array */
    protected abstract String[] buildCommand();

    /** Subclass parses tool-specific output and returns findings */
    protected abstract List<Vulnerability> parseOutput(List<String> outputLines);

    /** Display name shown in GUI step indicator */
    public abstract String getToolName();

    /**
     * Runs the tool as a subprocess, streams output live, parses findings.
     * Called on a background thread — NEVER on JavaFX Application Thread.
     */
    public void runScan() {
        List<String> outputLines = new ArrayList<>();
        String[] cmd = buildCommand();

        outputCallback.accept("▶  Starting " + getToolName() + " on " + target + ":" + port);
        outputCallback.accept("   Command: " + String.join(" ", cmd));
        outputCallback.accept("─".repeat(60));

        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            currentProcess = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(currentProcess.getInputStream()))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    outputLines.add(line);
                    outputCallback.accept(line);   // stream live to GUI terminal
                }
            }

            currentProcess.waitFor();

        } catch (Exception e) {
            outputCallback.accept("⚠  " + getToolName() + " not found or error: " + e.getMessage());
            outputCallback.accept("   (Running in demo mode — showing simulated output)");
            outputLines = getSimulatedOutput();  // fallback for demo/dev
        }

        // Parse output and feed into report
        List<Vulnerability> findings = parseOutput(outputLines);
        for (Vulnerability v : findings) {
            report.addFinding(v);
            findingCallback.accept(v);   // live update to GUI findings panel
        }

        outputCallback.accept("─".repeat(60));
        outputCallback.accept("✔  " + getToolName() + " complete — " + findings.size() + " finding(s)");
        outputCallback.accept("");
    }

    /** Stop running scan */
    public void stop() {
        if (currentProcess != null && currentProcess.isAlive()) {
            currentProcess.destroy();
        }
    }

    /**
     * Subclass overrides to provide realistic simulated output
     * when tool is not installed (for development / demo purposes).
     */
    protected List<String> getSimulatedOutput() {
        return new ArrayList<>();
    }
}
