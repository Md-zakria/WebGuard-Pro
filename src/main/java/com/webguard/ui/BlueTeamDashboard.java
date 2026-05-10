package com.webguard.ui;
import com.webguard.blueteam.*;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import java.util.*;
import java.util.concurrent.*;

/**
 * BlueTeamDashboard — MONITOR mode.
 * Shows live traffic table (TrafficMonitor), log feed (LogAnalyzer),
 * alert queue panel, and anomaly detector threat list.
 *
 * All data structures feed into this UI:
 *   HashMap  → IP traffic table
 *   Stack    → live log feed (newest on top)
 *   Queue    → alert pipeline panel
 *   MinHeap  → threat severity list
 */
public class BlueTeamDashboard extends BorderPane {

    // ── Core modules ─────────────────────────────────────────────────────────
    private final AlertQueue     alertQueue;
    private final TrafficMonitor trafficMonitor;
    private final LogAnalyzer    logAnalyzer;
    private final AnomalyDetector anomalyDetector;
    private final IncidentLogger  incidentLogger;

    // ── UI: Stats bar ─────────────────────────────────────────────────────────
    private Label lblTotalRequests, lblAlertCount, lblThreatScore, lblStackSize;

    // ── UI: Live traffic table (HashMap → TableView) ──────────────────────────
    private TableView<TrafficMonitor.TrafficRecord> trafficTable;
    private ObservableList<TrafficMonitor.TrafficRecord> trafficData;

    // ── UI: Log feed (Stack → ListView, newest first) ─────────────────────────
    private ListView<String> logFeed;
    private ObservableList<String> logLines;

    // ── UI: Alert queue panel ─────────────────────────────────────────────────
    private ListView<String> alertPanel;
    private ObservableList<String> alertLines;

    // ── UI: Threat list (MinHeap top entries) ─────────────────────────────────
    private ListView<String> threatList;
    private ObservableList<String> threatLines;

    private final String targetHost;

    // Background executor for alert processing — keeps FX thread free
    private ScheduledExecutorService alertProcessor;

    public BlueTeamDashboard(String targetHost) {
    this.targetHost = targetHost;

    alertQueue      = new AlertQueue();
    trafficMonitor  = new TrafficMonitor(targetHost, alertQueue, 30);
    logAnalyzer     = new LogAnalyzer(
        "E:\\XAMPP\\apache\\logs\\access.log", alertQueue, trafficMonitor);
    anomalyDetector = new AnomalyDetector(alertQueue);
    incidentLogger  = new IncidentLogger("D:\\Tools\\webguard_incidents.log");

    buildUi();
    wireCallbacks();

    javafx.animation.PauseTransition delay =
        new javafx.animation.PauseTransition(javafx.util.Duration.millis(500));
    delay.setOnFinished(e -> startAll());
    delay.play();
}


    // ── UI Construction ───────────────────────────────────────────────────────

    private void buildUi() {
        setStyle("-fx-background-color: #0a0e1a;");
        setPadding(new Insets(0));

        // Header
        setTop(buildHeader());

        // Main content — 3 columns
        HBox content = new HBox(10);
        content.setPadding(new Insets(10));
        content.setStyle("-fx-background-color: #0a0e1a;");

        VBox leftCol  = buildLeftColumn();
        VBox midCol   = buildMidColumn();
        VBox rightCol = buildRightColumn();

        HBox.setHgrow(leftCol,  Priority.ALWAYS);
        HBox.setHgrow(midCol,   Priority.ALWAYS);
        HBox.setHgrow(rightCol, Priority.ALWAYS);

        content.getChildren().addAll(leftCol, midCol, rightCol);
        setCenter(content);
        setBottom(buildStatsBar());
    }

    private VBox buildHeader() {
        VBox header = new VBox(4);
        header.setPadding(new Insets(14, 16, 10, 16));
        header.setStyle("-fx-background-color: #0d1225; -fx-border-color: #1a3a6e; -fx-border-width: 0 0 1 0;");

        HBox titleRow = new HBox(12);
        titleRow.setAlignment(Pos.CENTER_LEFT);

        Label icon  = new Label("🛡");
        icon.setStyle("-fx-font-size: 20px;");

        Label title = new Label("MONITOR — Live Traffic & Threat Detection");
        title.setStyle("-fx-text-fill: #4fc3f7; -fx-font-size: 15px; -fx-font-weight: bold; -fx-font-family: 'Courier New';");

        Label target = new Label("Target: " + targetHost);
        target.setStyle("-fx-text-fill: #607d8b; -fx-font-size: 11px; -fx-font-family: 'Courier New';");
        HBox.setMargin(target, new Insets(0, 0, 0, 20));

        titleRow.getChildren().addAll(icon, title, target);
        header.getChildren().add(titleRow);
        return header;
    }

    private VBox buildLeftColumn() {
        VBox col = new VBox(8);
        col.setPrefWidth(340);

        // Traffic table — driven by HashMap<IP, TrafficRecord>
        Label lbl = sectionLabel("IP Traffic Map (HashMap)", "#4fc3f7");

        trafficData  = FXCollections.observableArrayList();
        trafficTable = new TableView<>(trafficData);
        trafficTable.setStyle("-fx-background-color: #0d1225; -fx-border-color: #1a3a6e;");
        trafficTable.setPrefHeight(220);
        trafficTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

        TableColumn<TrafficMonitor.TrafficRecord, String> colIp = new TableColumn<>("IP Address");
        colIp.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().ip));

        TableColumn<TrafficMonitor.TrafficRecord, Integer> colHits = new TableColumn<>("Hits");
        colHits.setCellValueFactory(d -> new javafx.beans.property.SimpleObjectProperty<>(d.getValue().hitCount));

        TableColumn<TrafficMonitor.TrafficRecord, Integer> colErr = new TableColumn<>("Errors");
        colErr.setCellValueFactory(d -> new javafx.beans.property.SimpleObjectProperty<>(d.getValue().errorCount));

        TableColumn<TrafficMonitor.TrafficRecord, String> colStatus = new TableColumn<>("Status");
        colStatus.setCellValueFactory(d -> {
            boolean susp = d.getValue().isSuspicious(30);
            return new javafx.beans.property.SimpleStringProperty(susp ? "⚠ SUSPECT" : "✓ Normal");
        });
        colStatus.setCellFactory(col2 -> new TableCell<>() {
            @Override protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) { setText(null); return; }
                setText(item);
                setStyle(item.startsWith("⚠")
                    ? "-fx-text-fill: #ff5252; -fx-font-weight: bold;"
                    : "-fx-text-fill: #69f0ae;");
            }
        });

        styleTable(trafficTable);
        trafficTable.getColumns().addAll(colIp, colHits, colErr, colStatus);

        // Log feed — driven by Stack (newest first)
        Label lblLog = sectionLabel("Log Feed (Stack — newest first)", "#81c784");
        logLines = FXCollections.observableArrayList();
        logFeed  = new ListView<>(logLines);
        logFeed.setPrefHeight(260);
        styleDarkList(logFeed, "#69f0ae");
        VBox.setVgrow(logFeed, Priority.ALWAYS);

        col.getChildren().addAll(lbl, trafficTable, lblLog, logFeed);
        return col;
    }

    private VBox buildMidColumn() {
        VBox col = new VBox(8);
        col.setPrefWidth(320);

        // Alert queue — FIFO pipeline
        Label lblA = sectionLabel("Alert Queue (Queue — FIFO)", "#ffb74d");
        alertLines = FXCollections.observableArrayList();
        alertPanel = new ListView<>(alertLines);
        alertPanel.setPrefHeight(230);
        styleDarkList(alertPanel, "#ffb74d");
        VBox.setVgrow(alertPanel, Priority.ALWAYS);

        // Quick action buttons
        HBox actions = new HBox(8);
        Button btnClearLow = actionButton("Clear LOW", "#546e7a");
        Button btnAckAll   = actionButton("Ack All", "#1565c0");
        btnClearLow.setOnAction(e -> {
            int n = alertQueue.clearBySeverity(AlertQueue.Severity.LOW);
            appendLog("[Queue] Cleared " + n + " LOW alerts.");
        });
        btnAckAll.setOnAction(e -> {
            alertQueue.drainAll();
            alertLines.clear();
            appendLog("[Queue] All alerts acknowledged.");
        });
        actions.getChildren().addAll(btnClearLow, btnAckAll);

        // Threat list — driven by AnomalyDetector MinHeap
        Label lblT = sectionLabel("Threat Heap (MaxHeap — highest first)", "#ef5350");
        threatLines = FXCollections.observableArrayList();
        threatList  = new ListView<>(threatLines);
        threatList.setPrefHeight(230);
        styleDarkList(threatList, "#ef9a9a");
        VBox.setVgrow(threatList, Priority.ALWAYS);

        Button btnMitigate = actionButton("⚡ Mitigate Top Threat", "#b71c1c");
        btnMitigate.setMaxWidth(Double.MAX_VALUE);
        btnMitigate.setOnAction(e -> mitigateTopThreat());

        col.getChildren().addAll(lblA, alertPanel, actions, lblT, threatList, btnMitigate);
        return col;
    }

    private VBox buildRightColumn() {
        VBox col = new VBox(8);
        col.setPrefWidth(240);

        Label lbl = sectionLabel("Session Stats", "#b0bec5");

        // Stat cards
        col.getChildren().addAll(lbl,
            statCard("Total Requests",  "0",     "#4fc3f7", true),
            statCard("Pending Alerts",  "0",     "#ffb74d", false),
            statCard("Top Threat Score","0.0",   "#ef5350", false),
            statCard("Log Stack Depth", "0",     "#81c784", false)
        );

        // Endpoint heat map (top probed paths)
        Label lblE = sectionLabel("Hot Endpoints", "#ce93d8");
        ListView<String> endpointList = new ListView<>();
        endpointList.setPrefHeight(200);
        styleDarkList(endpointList, "#ce93d8");
        VBox.setVgrow(endpointList, Priority.ALWAYS);

        col.getChildren().addAll(lblE, endpointList);

        // Wire endpoint refresh
        javafx.animation.Timeline endpointTimer = new javafx.animation.Timeline(
            new javafx.animation.KeyFrame(javafx.util.Duration.seconds(3), ev -> {
                Map<String, Integer> hits = trafficMonitor.getEndpointHits();
                List<Map.Entry<String, Integer>> sorted = new ArrayList<>(hits.entrySet());
                sorted.sort((a, b) -> b.getValue() - a.getValue());
                ObservableList<String> items = FXCollections.observableArrayList();
                sorted.stream().limit(8).forEach(en ->
                    items.add(String.format("%-4d  %s", en.getValue(), en.getKey())));
                endpointList.setItems(items);
            })
        );
        endpointTimer.setCycleCount(javafx.animation.Animation.INDEFINITE);
        endpointTimer.play();

        return col;
    }

    private HBox buildStatsBar() {
        HBox bar = new HBox(24);
        bar.setPadding(new Insets(8, 16, 8, 16));
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.setStyle("-fx-background-color: #050810; -fx-border-color: #1a3a6e; -fx-border-width: 1 0 0 0;");

        lblTotalRequests = statLabel("Requests: 0");
        lblAlertCount    = statLabel("Alerts: 0");
        lblThreatScore   = statLabel("Top Threat: 0.0");
        lblStackSize     = statLabel("Stack: 0");

        Label liveTag = new Label("● LIVE");
        liveTag.setStyle("-fx-text-fill: #69f0ae; -fx-font-size: 10px; -fx-font-family: 'Courier New';");

        bar.getChildren().addAll(liveTag, lblTotalRequests, lblAlertCount, lblThreatScore, lblStackSize);
        return bar;
    }

    // ── Callbacks & polling ───────────────────────────────────────────────────

    private void wireCallbacks() {
        // TrafficMonitor → update table (HashMap data)
        trafficMonitor.setTableCallback(map -> Platform.runLater(() -> {
            List<TrafficMonitor.TrafficRecord> top = trafficMonitor.getTopIps(15);
            trafficData.setAll(top);
            lblTotalRequests.setText("Requests: " + trafficMonitor.getTotalRequests());
        }));

        // LogAnalyzer → prepend to log feed (Stack newest-first)
        logAnalyzer.setEntryCallback(entry -> Platform.runLater(() -> {
            String line = String.format("[%s] %-16s  %s %s [%d]",
                    entry.timestamp, entry.ip, entry.method, entry.path, entry.statusCode);
            logLines.add(0, line);   // prepend = stack top = newest
            if (logLines.size() > 200) logLines.remove(logLines.size() - 1);
            lblStackSize.setText("Stack: " + logAnalyzer.getStackSize());
        }));

        // AlertQueue processing — background thread so analysis + file I/O never touch the FX thread
        alertProcessor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "alert-processor");
            t.setDaemon(true);
            return t;
        });
        alertProcessor.scheduleAtFixedRate(this::processAlerts, 500, 500, TimeUnit.MILLISECONDS);

        // AnomalyDetector polling → update threat list
        javafx.animation.Timeline threatTimer = new javafx.animation.Timeline(
            new javafx.animation.KeyFrame(javafx.util.Duration.seconds(2), e -> refreshThreats())
        );
        threatTimer.setCycleCount(javafx.animation.Animation.INDEFINITE);
        threatTimer.play();
    }

    /**
     * Runs on the alertProcessor background thread — never on the FX thread.
     * Drains the alert queue, feeds each alert into the anomaly detector and
     * incident logger, then dispatches a single batched UI update via
     * Platform.runLater so the FX thread only renders, never blocks.
     */
    private void processAlerts() {
        try {
            List<String> newLines = new ArrayList<>();
            AlertQueue.Alert alert;
            int cap = 0;
            while ((alert = alertQueue.dequeue()) != null && ++cap <= 50) {
                anomalyDetector.analyze(alert);
                incidentLogger.logAlert(alert.sourceIp, alert.severity, alert.message);
                newLines.add(String.format("[%s] %-10s  %-16s  %s",
                        alert.timestamp, alert.severity, alert.sourceIp, alert.message));
            }
            if (!newLines.isEmpty()) {
                // Reverse so the most-recent alert ends up at index 0 (top of list)
                Collections.reverse(newLines);
                final List<String> lines = newLines;
                final int total = alertQueue.getTotalEnqueued();
                Platform.runLater(() -> {
                    alertLines.addAll(0, lines);
                    while (alertLines.size() > 100) alertLines.remove(alertLines.size() - 1);
                    lblAlertCount.setText("Alerts: " + total);
                });
            }
        } catch (Exception ignored) {}
    }

    private void refreshThreats() {
        List<AnomalyDetector.Threat> top = anomalyDetector.getTopThreats(10);
        threatLines.clear();
        for (AnomalyDetector.Threat t : top) {
            threatLines.add(String.format("[%.1f] %-20s ← %s", t.score, t.name, t.sourceIp));
        }
        if (!top.isEmpty()) {
            lblThreatScore.setText("Top Threat: " + String.format("%.1f", top.get(0).score));
        }
    }

    private void mitigateTopThreat() {
        AnomalyDetector.Threat t = anomalyDetector.pollTop();
        if (t != null) {
            incidentLogger.logMitigation(t.name, t.score);
            appendLog("[Mitigate] " + t.name + " ← " + t.sourceIp + " (score " + t.score + ")");
            refreshThreats();
        }
    }

private void startAll() {
    new Thread(() -> {
        trafficMonitor.startMonitoring();
        logAnalyzer.startAnalyzing();
    }, "blueteam-monitor-thread").start();

    incidentLogger.log(IncidentLogger.EventType.MONITOR_STARTED, "System",
        "Blue Team MONITOR mode started — target: " + targetHost);
    appendLog("[BlueTeamDashboard] Monitor mode active — " + targetHost);
}
    public void shutdown() {
        trafficMonitor.stopMonitoring();
        logAnalyzer.stopAnalyzing();
        if (alertProcessor != null) alertProcessor.shutdownNow();
        incidentLogger.log(IncidentLogger.EventType.MONITOR_STOPPED, "System", "Monitor stopped.");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void appendLog(String msg) {
        Platform.runLater(() -> {
            logLines.add(0, msg);
            if (logLines.size() > 200) logLines.remove(logLines.size() - 1);
        });
    }

    private Label sectionLabel(String text, String color) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: " + color + "; -fx-font-size: 11px; " +
                   "-fx-font-weight: bold; -fx-font-family: 'Courier New';");
        return l;
    }

    private Label statLabel(String text) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: #607d8b; -fx-font-size: 11px; -fx-font-family: 'Courier New';");
        return l;
    }

    private VBox statCard(String label, String value, String color, boolean storeRef) {
        VBox card = new VBox(2);
        card.setPadding(new Insets(8, 12, 8, 12));
        card.setStyle("-fx-background-color: #0d1225; -fx-border-color: " + color +
                      "55; -fx-border-width: 1; -fx-border-radius: 4; -fx-background-radius: 4;");

        Label valLbl = new Label(value);
        valLbl.setStyle("-fx-text-fill: " + color + "; -fx-font-size: 18px; " +
                        "-fx-font-weight: bold; -fx-font-family: 'Courier New';");
        Label nameLbl = new Label(label);
        nameLbl.setStyle("-fx-text-fill: #455a64; -fx-font-size: 10px;");

        card.getChildren().addAll(valLbl, nameLbl);

        // Store refs for live update
        if (storeRef) lblTotalRequests = valLbl;

        return card;
    }

    private Button actionButton(String text, String bg) {
        Button b = new Button(text);
        b.setStyle("-fx-background-color: " + bg + "; -fx-text-fill: #eceff1; " +
                   "-fx-font-size: 11px; -fx-font-family: 'Courier New'; " +
                   "-fx-cursor: hand; -fx-border-radius: 3; -fx-background-radius: 3;");
        return b;
    }

    private void styleDarkList(ListView<String> lv, String textColor) {
        lv.setStyle("-fx-background-color: #050810; -fx-border-color: #1a3a6e; " +
                    "-fx-font-family: 'Courier New'; -fx-font-size: 11px; -fx-text-fill: " + textColor + ";");
    }

    @SuppressWarnings("unchecked")
    private void styleTable(TableView<?> tv) {
        tv.setStyle("-fx-background-color: #050810; -fx-border-color: #1a3a6e; " +
                    "-fx-font-family: 'Courier New'; -fx-font-size: 11px;");
    }

    // ── Accessors for BlueTeamHub ─────────────────────────────────────────────
    public AlertQueue      getAlertQueue()     { return alertQueue; }
    public IncidentLogger  getIncidentLogger() { return incidentLogger; }
    public AnomalyDetector getAnomalyDetector(){ return anomalyDetector; }
    public FirewallManager createFirewallManager() {
        FirewallManager fm = new FirewallManager();
        fm.setLogCallback(msg -> appendLog(msg));
        return fm;
    }
}
