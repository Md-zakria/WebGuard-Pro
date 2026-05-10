package com.webguard;

import com.webguard.ui.HomeScreen;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

/**
 * WebGuard Pro — Entry Point
 * Dual-mode cybersecurity lab platform for educational use.
 * COMSATS University Islamabad — CSC211 Data Structures
 */
public class MainApp extends Application {

    public static final String APP_TITLE = "WebGuard Pro";
    public static final int WINDOW_WIDTH  = 1200;
    public static final int WINDOW_HEIGHT = 750;

    @Override
    public void start(Stage primaryStage) {
        HomeScreen homeScreen = new HomeScreen(primaryStage);

        Scene scene = new Scene(homeScreen.getRoot(), WINDOW_WIDTH, WINDOW_HEIGHT);

        // Load global stylesheet
        String css = getClass().getResource("/css/theme.css").toExternalForm();
        scene.getStylesheets().add(css);

        primaryStage.setTitle(APP_TITLE);
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(1000);
        primaryStage.setMinHeight(650);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
