package com.webguard.ui;

import com.webguard.core.TargetValidator;
import com.webguard.models.Vulnerability;
import com.webguard.models.VulnerabilityReport;
import com.webguard.redteam.*;
import javafx.animation.*;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.*;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * RedTeamDashboard
 *
 * Full Red Team module GUI.
 *
 * Layout:
 *   LEFT  — live terminal output (all 4 tools streaming)
 *   RIGHT — vulnerability findings panel (fills as scan runs)
 *   TOP   — target input + scan controls + step indicator
 *   BOTTOM — summary report stats
 */
public class RedTeamDashboard {

    private final BorderPane root;
    private final Stage stage;

    // UI state
    private TextField targetField;
    private TextField portField;
    private Button    scanBtn;
    private Button    stopBtn;
    private TextArea  terminalArea;
    private VBox      findingsPanel;
    private Label     statusLabel;
    private HBox      stepIndicator;

    // Scan state
    private final VulnerabilityReport report = new VulnerabilityReport();
    private ExecutorService executor;
    private boolean scanning = false;

    // Step labels for the top progress indicator
    private Label[] stepLabels;

    public RedTeamDashboard(Stage stage) {
        this.stage = stage;
        this.root  = build();
    }

    public BorderPane getRoot() { return root; }

    // ── ROOT LAYOUT ───────────────────────────────────────────────────────

    private BorderPane build() {
        BorderPane bp = new BorderPane();
        bp.getStyleClass().add("red-root");

        bp.setTop(buildTopBar());
        bp.setCenter(buildMainContent());
        bp.setBottom(buildSummaryBar());

        return bp;
    }

    // ── TOP BAR: nav + target input + step indicator ──────────────────────

    private VBox buildTopBar() {
        VBox top = new VBox(0);
        top.getStyleClass().add("red-top");

        // Nav row
        HBox nav = new HBox(12);
        nav.setPadding(new Insets(14, 24, 14, 24));
        nav.setAlignment(Pos.CENTER_LEFT);
        nav.getStyleClass().add("nav-bar");

        Button backBtn = new Button("← Home");
        backBtn.getStyleClass().add("nav-back-btn");
        backBtn.setOnAction(e -> goHome());

        Label breadcrumb = new Label("WebGuard Pro  /  Red Team Module");
        breadcrumb.getStyleClass().add("breadcrumb");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label modeTag = new Label("⚔  RED TEAM");
        modeTag.getStyleClass().add("mode-tag-red");

        nav.getChildren().addAll(backBtn, breadcrumb, spacer, modeTag);

        // Control row: target + port + scan button
        HBox controls = new HBox(12);
        controls.setPadding(new Insets(12, 24, 12, 24));
        controls.setAlignment(Pos.CENTER_LEFT);
        controls.getStyleClass().add("controls-bar");

        Label targetLbl = new Label("Target:");
        targetLbl.getStyleClass().add("ctrl-label");

        targetField = new TextField("127.0.0.1");
        targetField.getStyleClass().add("target-field");
        targetField.setPrefWidth(200);
        targetField.setPromptText("localhost / 192.168.x.x");

        Label portLbl = new Label("Port:");
        portLbl.getStyleClass().add("ctrl-label");

        portField = new TextField("80");
        portField.getStyleClass().add("port-field");
        portField.setPrefWidth(70);

        scanBtn = new Button("▶  Run Full Scan");
        scanBtn.getStyleClass().add("scan-btn");
        scanBtn.setOnAction(e -> startScan());

        stopBtn = new Button("■  Stop");
        stopBtn.getStyleClass().add("stop-btn");
        stopBtn.setDisable(true);
        stopBtn.setOnAction(e -> stopScan());

        statusLabel = new Label("Ready — enter target and press Run Full Scan");
        statusLabel.getStyleClass().add("status-label");

        controls.getChildren().addAll(targetLbl, targetField, portLbl, portField,
                scanBtn, stopBtn, statusLabel);

        // Step indicator
        stepIndicator = buildStepIndicator();

        top.getChildren().addAll(nav, controls, stepIndicator);
        return top;
    }

    private HBox buildStepIndicator() {
        HBox row = new HBox(0);
        row.setPadding(new Insets(8, 24, 8, 24));
        row.setAlignment(Pos.CENTER_LEFT);
        row.getStyleClass().add("step-bar");

        String[] tools = {"nmap", "nikto", "sqlmap", "gobuster", "Report"};
        stepLabels = new Label[tools.length];

        for (int i = 0; i < tools.length; i++) {
            Label lbl = new Label("  " + tools[i] + "  ");
            lbl.getStyleClass().addAll("step-label", "step-idle");
            stepLabels[i] = lbl;
            row.getChildren().add(lbl);

            if (i < tools.length - 1) {
                Label arrow = new Label(" → ");
                arrow.getStyleClass().add("step-arrow");
                row.getChildren().add(arrow);
            }
        }
        return row;
    }

    // ── MAIN CONTENT: terminal (left) + findings (right) ──────────────────

    private SplitPane buildMainContent() {
        SplitPane split = new SplitPane();
        split.setDividerPositions(0.55);
        split.getStyleClass().add("main-split");

        // LEFT — terminal
        VBox terminalBox = new VBox(0);
        terminalBox.getStyleClass().add("terminal-box");

        HBox termHeader = new HBox();
        termHeader.getStyleClass().add("panel-header");
        Label termTitle = new Label("⬛  Live Tool Output");
        termTitle.getStyleClass().add("panel-title");

        Button clearBtn = new Button("Clear");
        clearBtn.getStyleClass().add("clear-btn");
        clearBtn.setOnAction(e -> terminalArea.clear());

        Region h1 = new Region(); HBox.setHgrow(h1, Priority.ALWAYS);
        termHeader.getChildren().addAll(termTitle, h1, clearBtn);
        termHeader.setPadding(new Insets(10, 14, 10, 14));

        terminalArea = new TextArea();
        terminalArea.getStyleClass().add("terminal");
        terminalArea.setEditable(false);
        terminalArea.setWrapText(false);
        VBox.setVgrow(terminalArea, Priority.ALWAYS);

        terminalBox.getChildren().addAll(termHeader, terminalArea);

        // RIGHT — findings
        VBox findingsBox = new VBox(0);
        findingsBox.getStyleClass().add("findings-box");

        HBox findHeader = new HBox();
        findHeader.getStyleClass().add("panel-header");
        Label findTitle = new Label("🔍  Vulnerabilities Found");
        findTitle.getStyleClass().add("panel-title");
        findHeader.setPadding(new Insets(10, 14, 10, 14));
        findHeader.getChildren().add(findTitle);

        findingsPanel = new VBox(8);
        findingsPanel.setPadding(new Insets(12));
        findingsPanel.getStyleClass().add("findings-list");

        Label placeholder = new Label("Scan not started.\nFindings will appear here as tools run.");
        placeholder.getStyleClass().add("placeholder-text");
        placeholder.setId("placeholder");
        findingsPanel.getChildren().add(placeholder);

        ScrollPane findScroll = new ScrollPane(findingsPanel);
        findScroll.setFitToWidth(true);
        findScroll.getStyleClass().add("find-scroll");
        VBox.setVgrow(findScroll, Priority.ALWAYS);

        findingsBox.getChildren().addAll(findHeader, findScroll);

        split.getItems().addAll(terminalBox, findingsBox);
        return split;
    }

    // ── SUMMARY BAR ───────────────────────────────────────────────────────

    private HBox buildSummaryBar() {
        HBox bar = new HBox(0);
        bar.getStyleClass().add("summary-bar");
        bar.setAlignment(Pos.CENTER);
        bar.setPadding(new Insets(10, 24, 10, 24));

        Label info = new Label("Run a scan to see vulnerability summary");
        info.getStyleClass().add("summary-placeholder");
        info.setId("summary-info");
        bar.getChildren().add(info);

        return bar;
    }

    // ── SCAN LOGIC ────────────────────────────────────────────────────────

    private void startScan() {
        String target = targetField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException ex) {
            showError("Invalid port number.");
            return;
        }

        if (!TargetValidator.isAllowed(target)) {
            showBlockedAlert(target);
            return;
        }

        // Reset UI
        report.clear();
        terminalArea.clear();
        findingsPanel.getChildren().clear();
        resetSteps();

        scanning = true;
        scanBtn.setDisable(true);
        stopBtn.setDisable(false);
        setStatus("🔴  Scanning " + target + ":" + port + " ...");

        executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> runAllTools(target, port));
    }

    private void runAllTools(String target, int port) {
        int finalPort = port;

        // Tool instances — polymorphism: all extend ToolLauncher
        List<ToolLauncher> tools = List.of(
                new NmapScanner   (target, finalPort, report, this::appendTerminal, this::addFinding),
                new NiktoScanner  (target, finalPort, report, this::appendTerminal, this::addFinding),
                new SqlmapScanner (target, finalPort, report, this::appendTerminal, this::addFinding),
                new GobusterScanner(target, finalPort, report, this::appendTerminal, this::addFinding)
        );

        for (int i = 0; i < tools.size(); i++) {
            if (!scanning) break;
            final int step = i;
            Platform.runLater(() -> activateStep(step));
            tools.get(i).runScan();
            Platform.runLater(() -> completeStep(step));
        }

        Platform.runLater(() -> {
            activateStep(4); // "Report" step
            finalizeScan();
        });
    }

    private void finalizeScan() {
        scanning = false;
        scanBtn.setDisable(false);
        stopBtn.setDisable(true);
        completeStep(4);
        setStatus("✔  Scan complete — " + report.getTotalCount() + " findings");
        updateSummaryBar();
        appendTerminal("═".repeat(60));
        appendTerminal("SCAN COMPLETE — " + report.getTotalCount() + " vulnerabilities found");
        appendTerminal("Critical: " + report.getCriticalCount() +
                "  High: " + report.getHighCount() +
                "  Medium: " + report.getMediumCount() +
                "  Low: " + report.getLowCount());
        appendTerminal("═".repeat(60));
    }

    private void stopScan() {
        scanning = false;
        if (executor != null) executor.shutdownNow();
        scanBtn.setDisable(false);
        stopBtn.setDisable(true);
        setStatus("⏹  Scan stopped by user");
        appendTerminal("\n[!] Scan stopped by user.");
    }

    // ── UI HELPERS ────────────────────────────────────────────────────────

    /** Called from background thread — safe via Platform.runLater */
    private void appendTerminal(String line) {
        Platform.runLater(() -> {
            terminalArea.appendText(line + "\n");
        });
    }

    /** Called when a new vulnerability is found — adds a card to the findings panel */
    private void addFinding(Vulnerability v) {
        Platform.runLater(() -> {
            // Remove placeholder if present
            findingsPanel.getChildren().removeIf(n -> "placeholder".equals(n.getId()));

            VBox card = buildFindingCard(v);
            card.setOpacity(0);
            findingsPanel.getChildren().add(card);

            FadeTransition ft = new FadeTransition(Duration.millis(400), card);
            ft.setFromValue(0); ft.setToValue(1);
            ft.play();
        });
    }

    private VBox buildFindingCard(Vulnerability v) {
        VBox card = new VBox(6);
        card.setPadding(new Insets(12, 14, 12, 14));
        card.getStyleClass().addAll("finding-card", "sev-" + v.getSeverity().name().toLowerCase());

        HBox header = new HBox(8);
        header.setAlignment(Pos.CENTER_LEFT);

        Label sevLabel = new Label(v.getSeverityLabel());
        sevLabel.getStyleClass().addAll("sev-badge", "sev-" + v.getSeverity().name().toLowerCase() + "-badge");

        Label scoreLabel = new Label(String.format("CVSS %.1f", v.getCvssScore()));
        scoreLabel.getStyleClass().add("cvss-score");

        Label toolLabel = new Label("[" + v.getTool() + "]");
        toolLabel.getStyleClass().add("tool-badge");

        header.getChildren().addAll(sevLabel, scoreLabel, toolLabel);

        Label title = new Label(v.getTitle());
        title.getStyleClass().add("finding-title");
        title.setWrapText(true);

        Label endpoint = new Label("📍 " + v.getEndpoint());
        endpoint.getStyleClass().add("finding-endpoint");

        Label fix = new Label("🔧 " + v.getFix());
        fix.getStyleClass().add("finding-fix");
        fix.setWrapText(true);

        card.getChildren().addAll(header, title, endpoint, fix);
        return card;
    }

    private void setStatus(String msg) {
        Platform.runLater(() -> statusLabel.setText(msg));
    }

    private void resetSteps() {
        for (Label lbl : stepLabels) {
            lbl.getStyleClass().removeAll("step-active", "step-done");
            if (!lbl.getStyleClass().contains("step-idle")) lbl.getStyleClass().add("step-idle");
        }
    }

    private void activateStep(int i) {
        stepLabels[i].getStyleClass().removeAll("step-idle", "step-done");
        stepLabels[i].getStyleClass().add("step-active");
    }

    private void completeStep(int i) {
        stepLabels[i].getStyleClass().removeAll("step-idle", "step-active");
        stepLabels[i].getStyleClass().add("step-done");
    }

    private void updateSummaryBar() {
        HBox bar = (HBox) root.getBottom();
        bar.getChildren().clear();
        bar.getChildren().addAll(
                summaryChip("CRITICAL", report.getCriticalCount(), "chip-critical"),
                summaryChip("HIGH",     report.getHighCount(),     "chip-high"),
                summaryChip("MEDIUM",   report.getMediumCount(),   "chip-medium"),
                summaryChip("LOW",      report.getLowCount(),      "chip-low"),
                summaryChip("TOTAL",    report.getTotalCount(),    "chip-total")
        );
    }

    private HBox summaryChip(String label, int count, String style) {
        HBox chip = new HBox(8);
        chip.setPadding(new Insets(6, 20, 6, 20));
        chip.setAlignment(Pos.CENTER);
        chip.getStyleClass().addAll("summary-chip", style);

        Label num = new Label(String.valueOf(count));
        num.getStyleClass().add("chip-number");

        Label lbl = new Label(label);
        lbl.getStyleClass().add("chip-label");

        chip.getChildren().addAll(num, lbl);
        return chip;
    }

    private void showBlockedAlert(String target) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("Target Blocked");
        alert.setHeaderText("⛔  Safety Lock Active");
        alert.setContentText(TargetValidator.getErrorMessage(target));
        alert.showAndWait();
    }

    private void showError(String msg) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error"); alert.setContentText(msg);
        alert.showAndWait();
    }

    private void goHome() {
        if (scanning) stopScan();
        HomeScreen home = new HomeScreen(stage);
        root.getScene().setRoot(home.getRoot());
    }
}
