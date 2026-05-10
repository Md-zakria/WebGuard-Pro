package com.webguard.ui;

import javafx.animation.*;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.util.Duration;

/**
 * BlueTeamHub — entry screen for the Blue Team module.
 * Mirrors RedTeamHub: CSS-class-based cards, top-bar nav, breadcrumb.
 * Back button: dashboard → card selection → HomeScreen.
 */
public class BlueTeamHub extends BorderPane {

    private final Runnable onBack;
    private final String   targetHost;

    private BlueTeamDashboard activeMonitor = null;
    private DefendDashboard   activeDefend  = null;

    // Reference used by handleBack() to detect whether a dashboard is active
    private VBox hubCenter;

    public BlueTeamHub(Runnable onBack, String targetHost) {
        this.onBack     = onBack;
        this.targetHost = targetHost;
        buildUi();
    }

    // ── Layout ────────────────────────────────────────────────────────────────

    private void buildUi() {
        getStyleClass().add("home-root");
        hubCenter = buildHubCenter();
        setCenter(hubCenter);
        setTop(buildTopBar());   // after hubCenter so handleBack() reference is valid
    }

    private HBox buildTopBar() {
        HBox bar = new HBox(12);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.setPadding(new Insets(14, 24, 14, 24));
        bar.getStyleClass().add("top-bar");

        Button backBtn = new Button("← Home");
        backBtn.getStyleClass().add("nav-btn");
        backBtn.setOnAction(e -> handleBack());

        Label breadcrumb = new Label("WebGuard Pro / Blue Team");
        breadcrumb.getStyleClass().add("breadcrumb");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label modeTag = new Label("🛡  BLUE TEAM");
        modeTag.getStyleClass().add("mode-tag-blue");

        bar.getChildren().addAll(backBtn, breadcrumb, spacer, modeTag);
        return bar;
    }

    private VBox buildHubCenter() {
        // Title section
        VBox titleBox = new VBox(6);
        titleBox.setAlignment(Pos.CENTER);
        titleBox.setPadding(new Insets(36, 0, 10, 0));

        Label title = new Label("Blue Team");
        title.getStyleClass().add("app-title");
        title.setStyle("-fx-font-size: 36px;");

        Label subtitle = new Label("Choose your defense mode");
        subtitle.getStyleClass().add("app-subtitle");

        titleBox.getChildren().addAll(title, subtitle);

        // Cards row
        HBox cards = new HBox(48);
        cards.setAlignment(Pos.CENTER);
        cards.setPadding(new Insets(32, 80, 32, 80));

        VBox monitorCard = buildModeCard(
            "monitor-hub-card",
            "🛡",
            "MONITOR",
            "Live Traffic & Threat Detection",
            "Passive real-time monitor feeding four\n" +
            "data structures simultaneously:\n\n" +
            "  HashMap  — IP frequency tracking\n" +
            "  Stack    — log feed (newest first)\n" +
            "  Queue    — FIFO alert pipeline\n" +
            "  MaxHeap  — threat severity ranking",
            "monitor-card",
            this::launchMonitor
        );

        VBox defendCard = buildModeCard(
            "defend-hub-card",
            "⚔",
            "DEFEND",
            "Block · Patch · Harden",
            "Active response: block IPs, apply\n" +
            "patches, run hardening checks.\n\n" +
            "  LinkedList — blocked IP chain\n" +
            "  ArrayList  — CVE patch index\n" +
            "  HashMap    — config audit map\n" +
            "  LinkedList — incident timeline",
            "defend-card",
            this::launchDefend
        );

        animateCardIn(monitorCard, 0);
        animateCardIn(defendCard,  160);

        cards.getChildren().addAll(monitorCard, defendCard);

        VBox center = new VBox(0);
        center.getChildren().addAll(titleBox, cards);
        return center;
    }

    private VBox buildModeCard(String id, String emoji, String mode, String tagline,
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

    // ── Navigation ────────────────────────────────────────────────────────────

    private void launchMonitor() {
        if (activeMonitor == null) {
            activeMonitor = new BlueTeamDashboard(targetHost);
        }
        setCenter(activeMonitor);
    }

    private void launchDefend() {
        if (activeMonitor == null) {
            // Monitor must run first — its alertQueue and incidentLogger are shared
            activeMonitor = new BlueTeamDashboard(targetHost);
        }
        if (activeDefend == null) {
            activeDefend = new DefendDashboard(
                targetHost,
                activeMonitor.getAlertQueue(),
                activeMonitor.getIncidentLogger()
            );
        }
        setCenter(activeDefend);
    }

    private void handleBack() {
        if (getCenter() != hubCenter) {
            // Inside a dashboard → return to card selection (dashboards stay alive)
            setCenter(hubCenter);
        } else {
            // At card selection → exit to HomeScreen
            shutdown();
            onBack.run();
        }
    }

    // ── Animation ─────────────────────────────────────────────────────────────

    private void animateCardIn(VBox card, int delayMs) {
        card.setOpacity(0);
        card.setTranslateY(30);
        PauseTransition pause = new PauseTransition(Duration.millis(delayMs + 200));
        pause.setOnFinished(e -> {
            FadeTransition fade  = new FadeTransition(Duration.millis(450), card);
            fade.setFromValue(0); fade.setToValue(1);
            TranslateTransition slide = new TranslateTransition(Duration.millis(450), card);
            slide.setFromY(30); slide.setToY(0);
            new ParallelTransition(fade, slide).play();
        });
        pause.play();
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    public void shutdown() {
        if (activeMonitor != null) {
            activeMonitor.shutdown();
            activeMonitor = null;
        }
        activeDefend = null;
    }
}
