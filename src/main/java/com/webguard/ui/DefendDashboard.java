package com.webguard.ui;
import com.webguard.blueteam.FirewallManager;
import java.util.List;

import com.webguard.blueteam.*;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

/**
 * DefendDashboard — DEFEND mode.
 * Three panels:
 *   1. FirewallManager — LinkedList of blocked IPs + manual block/unblock
 *   2. PatchAdvisor    — ArrayList of CVE patches + status tracker
 *   3. HardenChecker   — HashMap config audit + score gauge
 *
 * IncidentLogger records every analyst action for the audit trail.
 */
public class DefendDashboard extends BorderPane {

    private final FirewallManager  firewallManager;
    private final PatchAdvisor     patchAdvisor;
    private final HardenChecker    hardenChecker;
    private final IncidentLogger   incidentLogger;
    private final AlertQueue       alertQueue;

    // ── Firewall UI ───────────────────────────────────────────────────────────
    private ObservableList<String> blockListItems;
    private ListView<String>       blockListView;
    private TextField              ipInputField;

    // ── Patch UI ──────────────────────────────────────────────────────────────
    private TableView<PatchAdvisor.PatchItem> patchTable;
    private ObservableList<PatchAdvisor.PatchItem> patchData;

    // ── Harden UI ─────────────────────────────────────────────────────────────
    private ListView<String> hardenList;
    private ObservableList<String> hardenLines;
    private Label lblScore;

    // ── Shared terminal ───────────────────────────────────────────────────────
    private ListView<String> terminal;
    private ObservableList<String> termLines;

    private final String targetHost;

    public DefendDashboard(String targetHost,
                           AlertQueue alertQueue,
                           IncidentLogger incidentLogger) {
        this.targetHost     = targetHost;
        this.alertQueue     = alertQueue;
        this.incidentLogger = incidentLogger;

        firewallManager = new FirewallManager();
        patchAdvisor    = new PatchAdvisor();
        hardenChecker   = new HardenChecker(targetHost);

        wireLogs();
        buildUi();
    }

    // ── Logging wiring ────────────────────────────────────────────────────────

    private void wireLogs() {
        firewallManager.setLogCallback(this::appendTerminal);
        patchAdvisor.setLogCallback(this::appendTerminal);
        hardenChecker.setLogCallback(this::appendTerminal);

        firewallManager.setListCallback(list -> Platform.runLater(this::refreshBlockList));
    }

    // ── UI Construction ───────────────────────────────────────────────────────

    private void buildUi() {
        setStyle("-fx-background-color: #0a0e1a;");

        setTop(buildHeader());

        // Three-column defend panels
        HBox columns = new HBox(10);
        columns.setPadding(new Insets(10));
        columns.setStyle("-fx-background-color: #0a0e1a;");

        VBox firewallPanel = buildFirewallPanel();
        VBox patchPanel    = buildPatchPanel();
        VBox hardenPanel   = buildHardenPanel();

        HBox.setHgrow(firewallPanel, Priority.ALWAYS);
        HBox.setHgrow(patchPanel,    Priority.ALWAYS);
        HBox.setHgrow(hardenPanel,   Priority.ALWAYS);

        columns.getChildren().addAll(firewallPanel, patchPanel, hardenPanel);
        setCenter(columns);
        setBottom(buildTerminal());
    }

    private VBox buildHeader() {
        VBox h = new VBox(4);
        h.setPadding(new Insets(14, 16, 10, 16));
        h.setStyle("-fx-background-color: #0d1225; -fx-border-color: #1a3a6e; -fx-border-width: 0 0 1 0;");

        HBox row = new HBox(12);
        row.setAlignment(Pos.CENTER_LEFT);

        Label icon  = new Label("⚔");
        icon.setStyle("-fx-font-size: 20px;");

        Label title = new Label("DEFEND — Block · Patch · Harden");
        title.setStyle("-fx-text-fill: #ef9a9a; -fx-font-size: 15px; " +
                       "-fx-font-weight: bold; -fx-font-family: 'Courier New';");

        Label tgt = new Label("Target: " + targetHost);
        tgt.setStyle("-fx-text-fill: #607d8b; -fx-font-size: 11px; -fx-font-family: 'Courier New';");
        HBox.setMargin(tgt, new Insets(0, 0, 0, 20));

        row.getChildren().addAll(icon, title, tgt);
        h.getChildren().add(row);
        return h;
    }

    // ── Panel 1: Firewall (LinkedList) ────────────────────────────────────────

    private VBox buildFirewallPanel() {
        VBox panel = new VBox(8);
        panel.setPrefWidth(300);

        Label lbl = sectionLabel("🔥 Firewall Block List (LinkedList)", "#ef9a9a");

        // Manual IP block input
        HBox inputRow = new HBox(6);
        ipInputField  = new TextField();
        ipInputField.setPromptText("Enter IP to block...");
        ipInputField.setStyle("-fx-background-color: #0d1225; -fx-text-fill: #eceff1; " +
                              "-fx-border-color: #1a3a6e; -fx-font-family: 'Courier New'; " +
                              "-fx-font-size: 11px; -fx-prompt-text-fill: #455a64;");
        HBox.setHgrow(ipInputField, Priority.ALWAYS);

        Button btnBlock = actionButton("Block", "#b71c1c");
        btnBlock.setOnAction(e -> manualBlock());
        ipInputField.setOnAction(e -> manualBlock());

        inputRow.getChildren().addAll(ipInputField, btnBlock);

        // Block list
        blockListItems = FXCollections.observableArrayList();
        blockListView  = new ListView<>(blockListItems);
        blockListView.setPrefHeight(200);
        styleDarkList(blockListView, "#ef9a9a");
        VBox.setVgrow(blockListView, Priority.ALWAYS);

        // Action buttons
        HBox actions = new HBox(6);
        Button btnUnblock    = actionButton("Unblock Selected", "#37474f");
        Button btnClearAuto  = actionButton("Clear Auto-Blocks", "#263238");
        Button btnAutoBlock  = actionButton("Auto-Block Threats", "#b71c1c");

        btnUnblock.setOnAction(e -> {
            String sel = blockListView.getSelectionModel().getSelectedItem();
            if (sel != null) {
                String ip = sel.split("\\s+")[0];
                if (firewallManager.unblockIp(ip)) {
                    incidentLogger.logUnblock(ip);
                }
            }
        });
        btnClearAuto.setOnAction(e -> {
            int n = firewallManager.clearAutoBlocks();
            appendTerminal("[Firewall] Cleared " + n + " auto-blocks.");
        });
        btnAutoBlock.setOnAction(e -> autoBlockThreats());

        actions.getChildren().addAll(btnUnblock, btnClearAuto);

        // Stat
        Label lblStat = new Label("LinkedList operations: O(1) append · O(n) remove");
        lblStat.setStyle("-fx-text-fill: #37474f; -fx-font-size: 9px; -fx-font-family: 'Courier New';");

        panel.getChildren().addAll(lbl, inputRow, blockListView, actions, btnAutoBlock, lblStat);
        return panel;
    }

    // ── Panel 2: Patch Advisor (ArrayList) ───────────────────────────────────

    private VBox buildPatchPanel() {
        VBox panel = new VBox(8);
        panel.setPrefWidth(360);

        Label lbl = sectionLabel("🩹 Patch Advisor (ArrayList)", "#fff176");

        patchData  = FXCollections.observableArrayList(patchAdvisor.getSortedByCvss());
        patchTable = new TableView<>(patchData);
        patchTable.setPrefHeight(300);
        patchTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        styleTable(patchTable);
        VBox.setVgrow(patchTable, Priority.ALWAYS);

        // CVE ID
        TableColumn<PatchAdvisor.PatchItem, String> colCve = new TableColumn<>("CVE");
        colCve.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().cveId));

        // Score
        TableColumn<PatchAdvisor.PatchItem, String> colScore = new TableColumn<>("CVSS");
        colScore.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(
            String.format("%.1f", d.getValue().cvssScore)));
        colScore.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String v, boolean empty) {
                super.updateItem(v, empty);
                if (empty || v == null) { setText(null); return; }
                setText(v);
                double s = Double.parseDouble(v);
                setStyle(s >= 9 ? "-fx-text-fill: #ff5252; -fx-font-weight: bold;" :
                         s >= 7 ? "-fx-text-fill: #ffb74d;" :
                                  "-fx-text-fill: #fff176;");
            }
        });

        // Title
        TableColumn<PatchAdvisor.PatchItem, String> colTitle = new TableColumn<>("Vulnerability");
        colTitle.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().title));

        // Status
        TableColumn<PatchAdvisor.PatchItem, String> colStatus = new TableColumn<>("Status");
        colStatus.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(
            d.getValue().status.name()));
        colStatus.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String v, boolean empty) {
                super.updateItem(v, empty);
                if (empty || v == null) { setText(null); return; }
                setText(v);
                setStyle(switch (v) {
                    case "APPLIED"    -> "-fx-text-fill: #69f0ae;";
                    case "IN_PROGRESS"-> "-fx-text-fill: #ffb74d;";
                    case "SKIPPED"    -> "-fx-text-fill: #607d8b;";
                    default           -> "-fx-text-fill: #ef9a9a;";
                });
            }
        });

        patchTable.getColumns().addAll(colCve, colScore, colTitle, colStatus);

        // Patch action buttons
        HBox patchActions = new HBox(6);
        Button btnApply  = actionButton("✓ Apply",     "#1b5e20");
        Button btnSkip   = actionButton("Skip",         "#37474f");
        Button btnInProg = actionButton("In Progress",  "#1565c0");

        btnApply.setOnAction(e -> updateSelectedPatch(PatchAdvisor.PatchStatus.APPLIED));
        btnSkip.setOnAction(e  -> updateSelectedPatch(PatchAdvisor.PatchStatus.SKIPPED));
        btnInProg.setOnAction(e -> updateSelectedPatch(PatchAdvisor.PatchStatus.IN_PROGRESS));

        patchActions.getChildren().addAll(btnApply, btnInProg, btnSkip);

        Label lblStat = new Label("ArrayList: O(1) indexed access · O(n) status scan");
        lblStat.setStyle("-fx-text-fill: #37474f; -fx-font-size: 9px; -fx-font-family: 'Courier New';");

        panel.getChildren().addAll(lbl, patchTable, patchActions, lblStat);
        return panel;
    }

    // ── Panel 3: Harden Checker (HashMap) ────────────────────────────────────

    private VBox buildHardenPanel() {
        VBox panel = new VBox(8);
        panel.setPrefWidth(280);

        Label lbl = sectionLabel("🔒 Hardening Checker (HashMap)", "#b39ddb");

        // Score gauge
        HBox scoreRow = new HBox(10);
        scoreRow.setAlignment(Pos.CENTER_LEFT);
        lblScore = new Label("Score: —/100");
        lblScore.setStyle("-fx-text-fill: #b39ddb; -fx-font-size: 14px; " +
                          "-fx-font-weight: bold; -fx-font-family: 'Courier New';");

        Button btnRun = actionButton("▶ Run All Checks", "#4527a0");
        btnRun.setOnAction(e -> runHardenChecks());

        scoreRow.getChildren().addAll(lblScore, btnRun);

        hardenLines = FXCollections.observableArrayList();
        hardenList  = new ListView<>(hardenLines);
        VBox.setVgrow(hardenList, Priority.ALWAYS);
        hardenList.setPrefHeight(300);
        styleDarkList(hardenList, "#ce93d8");
        hardenList.setCellFactory(lv -> new ListCell<>() {
            @Override protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) { setText(null); setStyle(""); return; }
                setText(item);
                setStyle(item.startsWith("✓")
                    ? "-fx-text-fill: #69f0ae; -fx-font-family: 'Courier New'; -fx-font-size: 11px;"
                    : item.startsWith("✗")
                    ? "-fx-text-fill: #ef5350; -fx-font-family: 'Courier New'; -fx-font-size: 11px;"
                    : "-fx-text-fill: #ffb74d; -fx-font-family: 'Courier New'; -fx-font-size: 11px;");
            }
        });

        Label lblStat = new Label("HashMap: O(1) check lookup · O(n) category filter");
        lblStat.setStyle("-fx-text-fill: #37474f; -fx-font-size: 9px; -fx-font-family: 'Courier New';");

        panel.getChildren().addAll(lbl, scoreRow, hardenList, lblStat);
        return panel;
    }

    private VBox buildTerminal() {
        VBox tv = new VBox(4);
        tv.setPadding(new Insets(8, 10, 8, 10));
        tv.setPrefHeight(130);
        tv.setStyle("-fx-background-color: #050810; -fx-border-color: #1a3a6e; -fx-border-width: 1 0 0 0;");

        Label lbl = new Label("● DEFEND LOG");
        lbl.setStyle("-fx-text-fill: #ef9a9a; -fx-font-size: 10px; -fx-font-family: 'Courier New'; -fx-font-weight: bold;");

        termLines = FXCollections.observableArrayList();
        terminal  = new ListView<>(termLines);
        terminal.setStyle("-fx-background-color: #050810; -fx-font-family: 'Courier New'; " +
                          "-fx-font-size: 11px; -fx-text-fill: #b0bec5;");
        VBox.setVgrow(terminal, Priority.ALWAYS);

        tv.getChildren().addAll(lbl, terminal);
        return tv;
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    private void manualBlock() {
        String ip = ipInputField.getText().trim();
        if (ip.isEmpty()) return;
        if (firewallManager.blockIp(ip, "Manual block by analyst", "MANUAL")) {
            incidentLogger.logBlock(ip, "Manual block");
            ipInputField.clear();
        }
    }

    private void autoBlockThreats() {
        // Drain current alerts and auto-block HIGH/CRITICAL source IPs
        List<AlertQueue.Alert> alerts = alertQueue.drainAll();
        int blocked = 0;
        for (AlertQueue.Alert a : alerts) {
            if ((a.severity == AlertQueue.Severity.HIGH ||
                 a.severity == AlertQueue.Severity.CRITICAL)
                && !firewallManager.isBlocked(a.sourceIp)) {
                firewallManager.autoBlock(a.sourceIp, a.type + ": " + a.message);
                incidentLogger.logBlock(a.sourceIp, "Auto-block: " + a.type);
                blocked++;
            }
        }
        appendTerminal("[AutoBlock] Blocked " + blocked + " IPs from " + alerts.size() + " alerts.");
    }

    private void updateSelectedPatch(PatchAdvisor.PatchStatus status) {
        PatchAdvisor.PatchItem sel = patchTable.getSelectionModel().getSelectedItem();
        if (sel == null) {
            appendTerminal("[Patch] No patch selected.");
            return;
        }
        patchAdvisor.updateStatus(sel.cveId, status, "Updated by analyst");
        incidentLogger.logPatch(sel.cveId, status.name());
        patchData.setAll(patchAdvisor.getSortedByCvss());
        appendTerminal("[Patch] " + sel.cveId + " → " + status);
    }

    private void runHardenChecks() {
        appendTerminal("[Harden] Running checks...");
        hardenLines.clear();
        hardenChecker.setResultCallback(item -> Platform.runLater(() -> {
            String symbol = switch (item.result) {
                case PASS    -> "✓";
                case FAIL    -> "✗";
                case WARNING -> "⚠";
                default      -> "?";
            };
            hardenLines.add(symbol + " [" + item.id + "] " + item.title + " — " + item.detail);
        }));

        new Thread(() -> {
            hardenChecker.runAllChecks();
            Platform.runLater(() -> {
                int score = hardenChecker.getHardeningScore();
                lblScore.setText("Score: " + score + "/100");
                lblScore.setStyle("-fx-font-size: 14px; -fx-font-weight: bold; " +
                                  "-fx-font-family: 'Courier New'; -fx-text-fill: " +
                                  (score >= 70 ? "#69f0ae" : score >= 40 ? "#ffb74d" : "#ef5350") + ";");
                incidentLogger.logHarden(score, hardenChecker.totalChecks());
                appendTerminal("[Harden] Done. Score: " + score + "/100  |  Fails: " + hardenChecker.failCount());
            });
        }).start();
    }

    private void refreshBlockList() {
        blockListItems.clear();
        for (FirewallManager.BlockedEntry e : firewallManager.getBlockList()) {
            blockListItems.add(String.format("%-16s  [%s]  %s  (%s)",
                e.ip, e.blockedAt, e.reason, e.blockedBy));
        }
    }

    private void appendTerminal(String msg) {
        Platform.runLater(() -> {
            termLines.add(0, msg);
            if (termLines.size() > 150) termLines.remove(termLines.size() - 1);
        });
    }

    // ── Style helpers ─────────────────────────────────────────────────────────

    private Label sectionLabel(String text, String color) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: " + color + "; -fx-font-size: 11px; " +
                   "-fx-font-weight: bold; -fx-font-family: 'Courier New';");
        return l;
    }

    private Button actionButton(String text, String bg) {
        Button b = new Button(text);
        b.setStyle("-fx-background-color: " + bg + "; -fx-text-fill: #eceff1; " +
                   "-fx-font-size: 11px; -fx-font-family: 'Courier New'; " +
                   "-fx-cursor: hand; -fx-border-radius: 3; -fx-background-radius: 3;");
        return b;
    }

    private void styleDarkList(ListView<?> lv, String textColor) {
        lv.setStyle("-fx-background-color: #050810; -fx-border-color: #1a3a6e; " +
                    "-fx-font-family: 'Courier New'; -fx-font-size: 11px; -fx-text-fill: " + textColor + ";");
    }

    private void styleTable(TableView<?> tv) {
        tv.setStyle("-fx-background-color: #050810; -fx-border-color: #1a3a6e; " +
                    "-fx-font-family: 'Courier New'; -fx-font-size: 11px;");
    }
}
