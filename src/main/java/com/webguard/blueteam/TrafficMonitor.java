package com.webguard.blueteam;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * TrafficMonitor — watches HTTP traffic to DVWA and counts requests per IP.
 * Data Structure: HashMap<String, Integer> — O(1) hit counting per IP.
 * Why HashMap: IP addresses are keys; we need instant lookup and update
 * without scanning a list each time a packet arrives.
 *
 * Also tracks: request rates, suspicious endpoints, HTTP status codes.
 */
public class TrafficMonitor {

    public static class TrafficRecord {
        public final String ip;
        public int hitCount;
        public int errorCount;       // 4xx/5xx responses
        public long firstSeen;
        public long lastSeen;
        public final List<String> endpoints = new ArrayList<>();

        public TrafficRecord(String ip) {
            this.ip        = ip;
            this.hitCount  = 1;
            this.firstSeen = System.currentTimeMillis();
            this.lastSeen  = this.firstSeen;
        }

        public double requestsPerSecond() {
            long elapsed = (lastSeen - firstSeen) / 1000;
            return elapsed > 0 ? (double) hitCount / elapsed : hitCount;
        }

        public boolean isSuspicious(int threshold) {
            return hitCount >= threshold || requestsPerSecond() > 10;
        }
    }

    // Core data structure: HashMap for O(1) IP lookup and count update
    private final Map<String, TrafficRecord> ipTable = new HashMap<>();

    // Endpoint hit map — tracks which DVWA paths are being probed
    private final Map<String, Integer> endpointHits = new HashMap<>();

    private final AlertQueue alertQueue;
    private final int        bruteForceThreshold;
    private final String     targetHost;

    private ScheduledExecutorService scheduler;
    private Consumer<String>         logCallback;
    private Consumer<Map<String, TrafficRecord>> tableCallback;

    private volatile boolean monitoring = false;

    // Simulated DVWA log entries for demo (mirrors real Apache log format)
    private static final String[] SIMULATED_IPS = {
        "127.0.0.1", "192.168.1.101", "192.168.1.102",
        "10.0.0.55",  "172.16.0.5"
    };
    private static final String[] SIMULATED_PATHS = {
        "/dvwa/login.php", "/dvwa/vulnerabilities/sqli/",
        "/dvwa/vulnerabilities/xss_r/", "/dvwa/vulnerabilities/brute/",
        "/dvwa/vulnerabilities/fi/", "/dvwa/setup.php",
        "/dvwa/phpinfo.php", "/.env", "/admin", "/wp-login.php"
    };
    private static final int[] SIMULATED_CODES = {200, 200, 200, 302, 401, 403, 404, 500};

    public TrafficMonitor(String targetHost, AlertQueue alertQueue, int bruteForceThreshold) {
        this.targetHost          = targetHost;
        this.alertQueue          = alertQueue;
        this.bruteForceThreshold = bruteForceThreshold;
    }

    public void setLogCallback(Consumer<String> cb)                              { this.logCallback   = cb; }
    public void setTableCallback(Consumer<Map<String, TrafficRecord>> cb)        { this.tableCallback = cb; }

    /** Start polling/simulating traffic every 800ms. */
    public void startMonitoring() {
        if (monitoring) return;
        monitoring = true;
        scheduler  = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::pollTraffic, 0, 800, TimeUnit.MILLISECONDS);
        log("[TrafficMonitor] Started — watching " + targetHost);
    }

    public void stopMonitoring() {
        monitoring = false;
        if (scheduler != null) scheduler.shutdownNow();
        log("[TrafficMonitor] Stopped.");
    }

    /** Simulate one batch of incoming requests (3–8 per tick). */
    private void pollTraffic() {
        int batch = 3 + (int)(Math.random() * 6);
        for (int i = 0; i < batch; i++) {
            String ip       = SIMULATED_IPS[(int)(Math.random() * SIMULATED_IPS.length)];
            String path     = SIMULATED_PATHS[(int)(Math.random() * SIMULATED_PATHS.length)];
            int    code     = SIMULATED_CODES[(int)(Math.random() * SIMULATED_CODES.length)];

            // Occasionally simulate a brute-force burst from one IP
            if (Math.random() < 0.05) {
                ip = "192.168.1.101";
                path = "/dvwa/vulnerabilities/brute/";
                code = 200;
            }

            recordHit(ip, path, code);
        }
        if (tableCallback != null) tableCallback.accept(Collections.unmodifiableMap(ipTable));
    }

    /**
     * Record one HTTP hit — the core HashMap operation.
     * getOrDefault + put = O(1) lookup + O(1) insert/update.
     */
    public synchronized void recordHit(String ip, String path, int statusCode) {
        // O(1) get or create
        TrafficRecord rec = ipTable.getOrDefault(ip, null);
        if (rec == null) {
            rec = new TrafficRecord(ip);
            ipTable.put(ip, rec);          // O(1) insert
        } else {
            rec.hitCount++;
            rec.lastSeen = System.currentTimeMillis();
        }

        if (statusCode >= 400) rec.errorCount++;
        if (!rec.endpoints.contains(path)) rec.endpoints.add(path);

        // Endpoint frequency map — O(1) update
        endpointHits.merge(path, 1, Integer::sum);

        String entry = String.format("%-16s  %s  [%d]", ip, path, statusCode);
        log(entry);

        // Anomaly checks
        checkBruteForce(rec);
        checkSensitivePath(ip, path, statusCode);
    }

    private void checkBruteForce(TrafficRecord rec) {
        if (rec.hitCount == bruteForceThreshold) {
            alertQueue.enqueue(
                "BRUTE FORCE", rec.ip,
                rec.hitCount + " requests detected — possible brute force",
                AlertQueue.Severity.HIGH
            );
            log("[!] ALERT: Brute force suspected from " + rec.ip);
        }
        if (rec.hitCount > bruteForceThreshold && rec.hitCount % 50 == 0) {
            alertQueue.enqueue(
                "BRUTE FORCE (cont.)", rec.ip,
                rec.hitCount + " total requests — attack ongoing",
                AlertQueue.Severity.CRITICAL
            );
        }
    }

    private void checkSensitivePath(String ip, String path, int code) {
        if (path.contains(".env") || path.contains("phpinfo") || path.contains("setup.php")) {
            alertQueue.enqueue(
                "SENSITIVE PATH", ip,
                "Probe of sensitive endpoint: " + path + " [" + code + "]",
                AlertQueue.Severity.MEDIUM
            );
            log("[!] ALERT: Sensitive path probed — " + path + " from " + ip);
        }
        if (path.contains("sqli") || path.contains("xss") || path.contains("fi/")) {
            alertQueue.enqueue(
                "EXPLOIT PROBE", ip,
                "DVWA exploit endpoint accessed: " + path,
                AlertQueue.Severity.HIGH
            );
        }
    }

    private void log(String msg) {
        if (logCallback != null) logCallback.accept(msg);
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    public synchronized Map<String, TrafficRecord> getIpTable()      { return Collections.unmodifiableMap(ipTable); }
    public synchronized Map<String, Integer>       getEndpointHits() { return Collections.unmodifiableMap(endpointHits); }
    public synchronized int getTotalRequests()  { return ipTable.values().stream().mapToInt(r -> r.hitCount).sum(); }

    /** Return top N IPs by hit count — used by the dashboard table. */
    public synchronized List<TrafficRecord> getTopIps(int n) {
        List<TrafficRecord> list = new ArrayList<>(ipTable.values());
        list.sort((a, b) -> b.hitCount - a.hitCount);
        return list.subList(0, Math.min(n, list.size()));
    }

    public boolean isMonitoring() { return monitoring; }
}
