package com.webguard.blueteam;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * AnomalyDetector — ranks detected threats by CVSS-style severity score.
 * Data Structure: PriorityQueue<Threat> (MinHeap by default; we invert
 * comparator to get MaxHeap so highest severity = top of heap).
 *
 * Why MinHeap/MaxHeap: O(log n) insert, O(1) peek-max, O(log n) remove-max.
 * Perfect for a live threat feed where we always want the worst threat first,
 * and new threats can arrive at any moment.
 *
 * Mirrors RedTeamDashboard's MinHeap for VulnerabilityReport — both teams
 * use heap-based severity ranking, demonstrating the data structure's
 * applicability on both offense and defense.
 */
public class AnomalyDetector {

    public static class Threat implements Comparable<Threat> {
        public final String  id;
        public final String  name;
        public final String  sourceIp;
        public final String  description;
        public final double  score;       // 0.0 – 10.0 (CVSS-style)
        public final String  category;   // INTRUSION, PROBE, BRUTE_FORCE, EXFIL, etc.
        public final String  timestamp;
        public boolean       mitigated;

        public Threat(String name, String sourceIp, String description,
                      double score, String category) {
            this.id          = "THR-" + System.currentTimeMillis() + "-" + (int)(Math.random()*1000);
            this.name        = name;
            this.sourceIp    = sourceIp;
            this.description = description;
            this.score       = Math.min(10.0, Math.max(0.0, score));
            this.category    = category;
            this.timestamp   = new java.text.SimpleDateFormat("HH:mm:ss")
                                   .format(new java.util.Date());
            this.mitigated   = false;
        }

        public AlertQueue.Severity toAlertSeverity() {
            if (score >= 9.0) return AlertQueue.Severity.CRITICAL;
            if (score >= 7.0) return AlertQueue.Severity.HIGH;
            if (score >= 4.0) return AlertQueue.Severity.MEDIUM;
            return AlertQueue.Severity.LOW;
        }

        /** Natural order = ascending score (MinHeap). */
        @Override public int compareTo(Threat other) {
            return Double.compare(this.score, other.score);
        }

        @Override public String toString() {
            return String.format("[%.1f] %s ← %s | %s", score, name, sourceIp, description);
        }
    }

    // MaxHeap: highest score = top (invert natural order)
    private final PriorityQueue<Threat> heap = new PriorityQueue<>(
        Comparator.comparingDouble((Threat t) -> t.score).reversed()
    );

    // All-time threat list for history panel
    private final List<Threat> history = new ArrayList<>();

    private final AlertQueue   alertQueue;
    private Consumer<Threat>   threatCallback;
    private Consumer<String>   logCallback;

    // Correlation: if same IP fires >3 different threat types → escalate
    private final Map<String, Set<String>> ipThreatTypes = new HashMap<>();

    // Track IPs that already generated an APT indicator — fires only once per IP
    private final Set<String> aptFired = new HashSet<>();

    public AnomalyDetector(AlertQueue alertQueue) {
        this.alertQueue = alertQueue;
    }

    public void setThreatCallback(Consumer<Threat> cb) { this.threatCallback = cb; }
    public void setLogCallback(Consumer<String>   cb)  { this.logCallback    = cb; }

    /**
     * Analyze an alert from the AlertQueue and produce a scored Threat.
     * Called by BlueTeamDashboard's polling loop.
     */
    public synchronized Threat analyze(AlertQueue.Alert alert) {
        double score = scoreAlert(alert);
        String category = categorize(alert.type);

        Threat threat = new Threat(alert.type, alert.sourceIp,
                                   alert.message, score, category);
        insertThreat(threat);
        return threat;
    }

    /** Manually insert a threat (used by DefendDashboard for manual entries). */
    public synchronized void insertThreat(Threat threat) {
        heap.offer(threat);          // O(log n) insert
        history.add(threat);

        // Correlation tracking
        ipThreatTypes.computeIfAbsent(threat.sourceIp, k -> new HashSet<>())
                     .add(threat.category);
        checkCorrelation(threat.sourceIp);

        log(String.format("[AnomalyDetector] +Threat  score=%.1f  %s  ← %s",
                threat.score, threat.name, threat.sourceIp));

        if (threatCallback != null) threatCallback.accept(threat);
    }

    /** Peek at the highest-severity threat. O(1). */
    public synchronized Threat peekTop() {
        return heap.peek();
    }

    /** Remove and return the highest-severity threat. O(log n). */
    public synchronized Threat pollTop() {
        Threat t = heap.poll();
        if (t != null) {
            t.mitigated = true;
            log("[AnomalyDetector] Mitigated: " + t.name + " (score " + t.score + ")");
        }
        return t;
    }

    /** Return top N threats by score (does NOT remove them). */
    public synchronized List<Threat> getTopThreats(int n) {
        // Dump heap to sorted list without destroying it
        List<Threat> sorted = new ArrayList<>(heap);
        sorted.sort(Comparator.comparingDouble((Threat t) -> t.score).reversed());
        return sorted.subList(0, Math.min(n, sorted.size()));
    }

    /** Mark a specific threat as mitigated and remove from heap. O(n). */
    public synchronized boolean mitigate(String threatId) {
        Iterator<Threat> it = heap.iterator();
        while (it.hasNext()) {
            Threat t = it.next();
            if (t.id.equals(threatId)) {
                it.remove();           // O(n) — acceptable for UI-driven action
                t.mitigated = true;
                log("[AnomalyDetector] Mitigated by user: " + t.name);
                return true;
            }
        }
        return false;
    }

    /** Correlation check — same IP with 3+ distinct threat types = APT indicator. Fires once per IP. */
    private void checkCorrelation(String ip) {
        if (aptFired.contains(ip)) return;
        Set<String> types = ipThreatTypes.get(ip);
        if (types != null && types.size() >= 3) {
            aptFired.add(ip);
            Threat apt = new Threat(
                "APT INDICATOR", ip,
                "IP involved in " + types.size() + " distinct attack types: " + types,
                9.5, "INTRUSION"
            );
            heap.offer(apt);
            history.add(apt);
            alertQueue.enqueue("APT INDICATOR", ip,
                "Correlated attack pattern — " + types.size() + " threat types",
                AlertQueue.Severity.CRITICAL);
            log("[!] CRITICAL: APT indicator for " + ip + " — types: " + types);
        }
    }

    private double scoreAlert(AlertQueue.Alert alert) {
        return switch (alert.type) {
            case "APT INDICATOR"    -> 9.5;
            case "BRUTE FORCE (cont.)"  -> 9.0;
            case "BRUTE FORCE"      -> 8.5;
            case "EXPLOIT PROBE"    -> 8.0;
            case "LOG ANOMALY"      -> 6.5;
            case "SENSITIVE PATH"   -> 5.5;
            default                 -> switch (alert.severity) {
                case CRITICAL -> 9.0;
                case HIGH     -> 7.5;
                case MEDIUM   -> 5.0;
                case LOW      -> 2.5;
            };
        };
    }

    private String categorize(String alertType) {
        if (alertType.contains("BRUTE"))   return "BRUTE_FORCE";
        if (alertType.contains("EXPLOIT")) return "PROBE";
        if (alertType.contains("LOG"))     return "INTRUSION";
        if (alertType.contains("SENSITIVE")) return "RECON";
        if (alertType.contains("APT"))     return "INTRUSION";
        return "UNKNOWN";
    }

    private void log(String msg) { if (logCallback != null) logCallback.accept(msg); }

    public synchronized int     heapSize()            { return heap.size(); }
    public synchronized List<Threat> getHistory()     { return Collections.unmodifiableList(history); }
    public synchronized boolean isEmpty()             { return heap.isEmpty(); }
    public synchronized double  getAverageScore() {
        return history.stream().mapToDouble(t -> t.score).average().orElse(0.0);
    }
}
