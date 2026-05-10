/*
 * ════════════════════════════════════════════════════════════════════
 * HomeScreen.java — Blue Team wiring patch
 * Find the buildBlueTeamCard() call (or the Blue Team card section)
 * and replace / add the following launch logic.
 * ════════════════════════════════════════════════════════════════════
 *
 * 1. Add a field at the top of HomeScreen:
 */
    private BlueTeamHub blueTeamHub;

/*
 * 2. Replace the Blue Team card's setOnMouseClicked / button action with:
 */
    private void launchBlueTeam() {
        if (blueTeamHub == null) {
            String host = targetField.getText().trim().isEmpty()
                ? "localhost:8080"
                : targetField.getText().trim();
            blueTeamHub = new BlueTeamHub(this::showHome, host);
        }
        rootPane.setCenter(blueTeamHub);   // swap center — same pattern as Red Team
    }

/*
 * 3. showHome() already exists — just make sure it nulls the hub
 *    if you want a fresh instance each visit:
 */
    private void showHome() {
        if (blueTeamHub != null) {
            blueTeamHub.shutdown();
            blueTeamHub = null;
        }
        rootPane.setCenter(homeContent);   // restore home cards
    }

/*
 * 4. In buildBlueTeamCard(), wire the button:
 *
 *    launchButton.setOnAction(e -> launchBlueTeam());
 *    card.setOnMouseClicked(e -> launchBlueTeam());
 *
 * ════════════════════════════════════════════════════════════════════
 * No other changes needed. BlueTeamHub handles all internal routing
 * between Monitor and Defend modes autonomously.
 * ════════════════════════════════════════════════════════════════════
 */
