package com.webguard.core;

import javafx.scene.layout.Pane;
import javafx.stage.Stage;

/**
 * AppNavigator
 * Central navigation controller. Any screen can call AppNavigator to switch views.
 * Keeps the Stage reference so we never pass it everywhere.
 */
public class AppNavigator {

    private static Stage primaryStage;
    private static javafx.scene.Scene scene;

    public static void init(Stage stage, javafx.scene.Scene sc) {
        primaryStage = stage;
        scene = sc;
    }

    public static void navigateTo(Pane root) {
        scene.setRoot(root);
    }

    public static Stage getStage() {
        return primaryStage;
    }
}
