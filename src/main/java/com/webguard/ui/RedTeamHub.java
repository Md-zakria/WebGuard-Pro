package com.webguard.ui;

import javafx.animation.*;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.util.Duration;

/**
 * RedTeamHub
 *
 * Intermediate Red Team screen — shown after clicking Red Team on HomeScreen.
 * Two sub-mode cards:
 *   Scan    →  RedTeamDashboard (nmap, nikto, sqlmap, gobuster)
 *   Exploit →  ExploitDashboard (SQLi, XSS, Brute Force, Traversal + Attack Tree)
 *
 * CSC211 Data Structures — WebGuard Pro
 */
public class RedTeamHub {

    private final BorderPane root;
    private final Stage stage;

    public RedTeamHub(Stage stage) {
        this.stage = stage;
        this.root  = build();
    }

    public BorderPane getRoot() { return root; }

    private BorderPane build() {
        BorderPane bp = new BorderPane();
        bp.getStyleClass().add("home-root");
        bp.setTop(buildTopBar());
        bp.setCenter(buildSubCards());
        return bp;
    }

    // ── TOP BAR ───────────────────────────────────────────────────────────

    private HBox buildTopBar() {
        HBox bar = new HBox(12);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.setPadding(new Insets(14, 24, 14, 24));
        bar.getStyleClass().add("top-bar");

        Button backBtn = new Button("← Home");
        backBtn.getStyleClass().add("nav-btn");
        backBtn.setOnAction(e -> goHome());

        Label breadcrumb = new Label("WebGuard Pro / Red Team");
        breadcrumb.getStyleClass().add("breadcrumb");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label modeTag = new Label("⚔  RED TEAM");
        modeTag.getStyleClass().add("mode-tag-red");

        bar.getChildren().addAll(backBtn, breadcrumb, spacer, modeTag);
        return bar;
    }

    // ── HEADER ────────────────────────────────────────────────────────────

    // ── SUB-MODE CARDS ────────────────────────────────────────────────────

    private VBox buildSubCards() {
        // Title section
        VBox titleBox = new VBox(6);
        titleBox.setAlignment(Pos.CENTER);
        titleBox.setPadding(new Insets(36, 0, 10, 0));

        Label title = new Label("Red Team");
        title.getStyleClass().add("app-title");
        title.setStyle("-fx-font-size: 36px;");

        Label subtitle = new Label("Choose your attack mode");
        subtitle.getStyleClass().add("app-subtitle");

        titleBox.getChildren().addAll(title, subtitle);

        // Cards row
        HBox cards = new HBox(48);
        cards.setAlignment(Pos.CENTER);
        cards.setPadding(new Insets(32, 80, 32, 80));

        VBox scanCard = buildSubCard(
            "scan-card",
            "🔍",
            "SCAN",
            "Reconnaissance & Enumeration",
            "Automated vulnerability scanner that\nruns all four tools in sequence:\n\n" +
            "  nmap      — port & service discovery\n" +
            "  nikto     — web server vulnerabilities\n" +
            "  sqlmap    — SQL injection detection\n" +
            "  gobuster  — directory brute force\n\n" +
            "Findings ranked by CVSS severity\nusing MinHeap data structure.",
            "red-card",
            this::openScan
        );

        VBox exploitCard = buildSubCard(
            "exploit-hub-card",
            "⚡",
            "EXPLOIT",
            "Active Exploitation + Attack Tree",
            "Active exploitation against DVWA\nwith live N-ary Attack Tree visual:\n\n" +
            "  SQLi      — dump databases & credentials\n" +
            "  XSS       — inject & reflect payloads\n" +
            "  Brute     — HTTP login brute force\n" +
            "  Traversal — LFI + directory exposure\n\n" +
            "Click any tree node to inspect\nfull breached data.",
            "exploit-card",
            this::openExploit
        );

        animateCardIn(scanCard,    0);
        animateCardIn(exploitCard, 160);

        cards.getChildren().addAll(scanCard, exploitCard);

        VBox center = new VBox(0);
        center.getChildren().addAll(titleBox, cards);
        return center;
    }

    private VBox buildSubCard(String id, String emoji, String mode, String tagline,
                               String description, String styleClass, Runnable onLaunch) {
        VBox card = new VBox(16);
        card.setId(id);
        card.getStyleClass().addAll("mode-card", styleClass);
        card.setAlignment(Pos.TOP_LEFT);
        card.setPrefWidth(420);
        card.setPadding(new Insets(36, 36, 32, 36));

        Label icon = new Label(emoji);
        icon.getStyleClass().add("card-icon");

        Label modeLabel = new Label(mode);
        modeLabel.getStyleClass().add("card-mode");

        Label taglineLabel = new Label(tagline);
        taglineLabel.getStyleClass().add("card-tagline");

        Separator sep = new Separator();
        sep.getStyleClass().add("card-sep");

        Label desc = new Label(description);
        desc.getStyleClass().add("card-desc");
        desc.setWrapText(true);

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);

        Button launchBtn = new Button("Launch " + mode + "  →");
        launchBtn.getStyleClass().addAll("launch-btn", styleClass + "-btn");
        launchBtn.setMaxWidth(Double.MAX_VALUE);
        launchBtn.setOnAction(e -> onLaunch.run());

        card.setOnMouseEntered(e -> card.getStyleClass().add("mode-card-hover"));
        card.setOnMouseExited(e  -> card.getStyleClass().remove("mode-card-hover"));

        card.getChildren().addAll(icon, modeLabel, taglineLabel, sep, desc, spacer, launchBtn);
        return card;
    }

    private void animateCardIn(VBox card, int delayMs) {
        card.setOpacity(0);
        card.setTranslateY(30);
        PauseTransition pause = new PauseTransition(Duration.millis(delayMs + 200));
        pause.setOnFinished(e -> {
            FadeTransition fade   = new FadeTransition(Duration.millis(450), card);
            fade.setFromValue(0); fade.setToValue(1);
            TranslateTransition slide = new TranslateTransition(Duration.millis(450), card);
            slide.setFromY(30); slide.setToY(0);
            new ParallelTransition(fade, slide).play();
        });
        pause.play();
    }


    // ── NAVIGATION ────────────────────────────────────────────────────────

    private void goHome() {
        HomeScreen home = new HomeScreen(stage);
        root.getScene().setRoot(home.getRoot());
    }

    private void openScan() {
        RedTeamDashboard dashboard = new RedTeamDashboard(stage);
        root.getScene().setRoot(dashboard.getRoot());
    }

    private void openExploit() {
        ExploitDashboard dashboard = new ExploitDashboard(stage);
        root.getScene().setRoot(dashboard.getRoot());
    }
}
