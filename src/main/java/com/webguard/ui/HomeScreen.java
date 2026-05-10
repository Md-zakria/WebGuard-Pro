package com.webguard.ui;

import javafx.animation.*;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.shape.Rectangle;
import javafx.stage.Stage;
import javafx.util.Duration;

/**
 * HomeScreen
 *
 * Main entry screen — two mode cards only:
 *   Red Team  →  RedTeamHub (Scan + Exploit)
 *   Blue Team →  BlueTeamDashboard (Week 3)
 *
 * CSC211 Data Structures — WebGuard Pro
 */
public class HomeScreen {

    private final BorderPane root;
    private final Stage stage;
    private BlueTeamHub blueTeamHub;

    public HomeScreen(Stage stage) {
        this.stage = stage;
        this.root  = build();
    }

    public BorderPane getRoot() { return root; }

    private BorderPane build() {
        BorderPane bp = new BorderPane();
        bp.getStyleClass().add("home-root");
        bp.setTop(buildHeader());
        bp.setCenter(buildModeCards());
        bp.setBottom(buildFooter());
        return bp;
    }

    // ── HEADER ────────────────────────────────────────────────────────────

    private VBox buildHeader() {
        VBox header = new VBox(6);
        header.setAlignment(Pos.CENTER);
        header.setPadding(new Insets(56, 0, 24, 0));
        header.getStyleClass().add("header");

        Label tag = new Label("COMSATS UNIVERSITY ISLAMABAD  ·  CSC211 DATA STRUCTURES");
        tag.getStyleClass().add("header-tag");

        Label title = new Label("WebGuard Pro");
        title.getStyleClass().add("app-title");

        Rectangle underline = new Rectangle(0, 2);
        underline.getStyleClass().add("title-underline");
        Timeline tl = new Timeline(
            new KeyFrame(Duration.ZERO,       new KeyValue(underline.widthProperty(), 0)),
            new KeyFrame(Duration.millis(800), new KeyValue(underline.widthProperty(), 260, Interpolator.EASE_OUT))
        );
        tl.setDelay(Duration.millis(300));
        tl.play();

        Label subtitle = new Label("Automated Purple Team Security Lab Platform");
        subtitle.getStyleClass().add("app-subtitle");

        header.getChildren().addAll(tag, title, underline, subtitle);
        return header;
    }

    // ── MODE CARDS ────────────────────────────────────────────────────────

    private HBox buildModeCards() {
        HBox cards = new HBox(48);
        cards.setAlignment(Pos.CENTER);
        cards.setPadding(new Insets(40, 80, 40, 80));

        VBox redCard = buildModeCard(
            "red-card",
            "⚔",
            "RED TEAM",
            "Attack & Exploit",
            "Active offensive security against your\n" +
            "DVWA / XAMPP localhost lab.\n\n" +
            "Choose from two modes:\n" +
            "  Scan    — nmap → nikto → sqlmap → gobuster\n" +
            "  Exploit — SQLi, XSS, Brute Force, Traversal\n" +
            "            with live Attack Tree visualization",
            "🔒  localhost / 192.168.x.x only",
            "red-card",
            this::openRedTeam
        );

        VBox blueCard = buildModeCard(
            "blue-card",
            "🛡",
            "BLUE TEAM",
            "Monitor & Defend",
            "Real-time Apache access.log monitor.\n" +
            "Detects SQLi, XSS, brute force,\n" +
            "directory traversal, and scanner tools.\n\n" +
            "Auto-deploys IP blocks, rate limits,\n" +
            "and forensic timeline live as attacks arrive.",
            "📡  Any host you own",
            "blue-card",
            this::openBlueTeam
        );

        animateCardIn(redCard,   0);
        animateCardIn(blueCard, 180);

        cards.getChildren().addAll(redCard, blueCard);
        return cards;
    }

    private VBox buildModeCard(String id, String emoji, String mode, String tagline,
                                String description, String scope,
                                String styleClass, Runnable onLaunch) {
        VBox card = new VBox(16);
        card.setId(id);
        card.getStyleClass().addAll("mode-card", styleClass);
        card.setAlignment(Pos.TOP_LEFT);
        card.setPrefWidth(440);
        card.setPadding(new Insets(38, 38, 34, 38));

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

        Label scopeLabel = new Label(scope);
        scopeLabel.getStyleClass().add("scope-badge");

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);

        Button launchBtn = new Button("Launch " + mode + "  →");
        launchBtn.getStyleClass().addAll("launch-btn", styleClass + "-btn");
        launchBtn.setMaxWidth(Double.MAX_VALUE);
        launchBtn.setOnAction(e -> onLaunch.run());

        card.setOnMouseEntered(e -> card.getStyleClass().add("mode-card-hover"));
        card.setOnMouseExited(e  -> card.getStyleClass().remove("mode-card-hover"));

        card.getChildren().addAll(icon, modeLabel, taglineLabel, sep, desc, scopeLabel, spacer, launchBtn);
        return card;
    }

    private void animateCardIn(VBox card, int delayMs) {
        card.setOpacity(0);
        card.setTranslateY(30);
        PauseTransition pause = new PauseTransition(Duration.millis(delayMs + 400));
        pause.setOnFinished(e -> {
            FadeTransition fade   = new FadeTransition(Duration.millis(500), card);
            fade.setFromValue(0); fade.setToValue(1);
            TranslateTransition slide = new TranslateTransition(Duration.millis(500), card);
            slide.setFromY(30); slide.setToY(0);
            new ParallelTransition(fade, slide).play();
        });
        pause.play();
    }

    // ── FOOTER ────────────────────────────────────────────────────────────

    private VBox buildFooter() {
        HBox stats = new HBox(0);
        stats.setAlignment(Pos.CENTER);
        stats.getStyleClass().add("stats-bar");
        stats.getChildren().addAll(
            statItem("4",  "Integrated Tools"),
            statDivider(),
            statItem("8",  "Data Structures"),
            statDivider(),
            statItem("21", "OOP Classes"),
            statDivider(),
            statItem("6",  "Attack Types Detected")
        );

        return new VBox(0) {{ getChildren().add(stats); }};
    }

    private VBox statItem(String number, String label) {
        VBox item = new VBox(2);
        item.setAlignment(Pos.CENTER);
        item.setPadding(new Insets(14, 40, 14, 40));
        Label num = new Label(number);
        num.getStyleClass().add("stat-number");
        Label lbl = new Label(label);
        lbl.getStyleClass().add("stat-label");
        item.getChildren().addAll(num, lbl);
        return item;
    }

    private Label statDivider() {
        Label d = new Label("|");
        d.getStyleClass().add("stat-divider");
        d.setAlignment(Pos.CENTER);
        return d;
    }

    // ── NAVIGATION ────────────────────────────────────────────────────────

    private void openRedTeam() {
        RedTeamHub hub = new RedTeamHub(stage);
        root.getScene().setRoot(hub.getRoot());
    }


    private void openBlueTeam() {
        javafx.scene.Scene scene = root.getScene();
        BlueTeamHub hub = new BlueTeamHub(
            () -> scene.setRoot(root),
            "localhost:8080"
        );
        scene.setRoot(hub);
    }
}