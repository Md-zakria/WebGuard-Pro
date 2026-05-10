package com.webguard.blueteam;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.*;

/**
 * LogAnalyzer — reads and parses DVWA's Apache access log in real time.
 * Data Structure: Stack<LogEntry> — newest log line = top of stack.
 * Why Stack: we always care about the MOST RECENT requests first.
 * Popping from the top gives us the latest entry in O(1),
 * mirroring how a security analyst reads a live log feed.
 *
 * Log path: E:\XAMPP\apache\logs\access.log (Windows XAMPP default)
 * Falls back to simulation if the file is unavailable.
 */
public class LogAnalyzer {

    // Apache Combined Log Format pattern
    // 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    private static final Pattern LOG_PATTERN = Pattern.compile(
        "^(\\S+) \\S+ \\S+ \\[([^\\]]+)\\] \"(\\w+) (\\S+) \\S+\" (\\d{3}) (\\d+|-)"
    );

    public static class LogEntry {
        public final String ip;
        public final String timestamp;
        public final String method;
        public final String path;
        public final int    statusCode;
        public final int    bytes;
        public final String raw;

        public LogEntry(String ip, String timestamp, String method,
                        String path, int statusCode, int bytes, String raw) {
            this.ip         = ip;
            this.timestamp  = timestamp;
            this.method     = method;
            this.path       = path;
            this.statusCode = statusCode;
            this.bytes      = bytes;
            this.raw        = raw;
        }

        public boolean isError()     { return statusCode >= 400; }
        public boolean isSuspicious() {
            return path.contains("sqli") || path.contains("xss") ||
                   path.contains("brute") || path.contains(".env") ||
                   path.contains("phpinfo") || path.contains("../") ||
                   path.contains("setup.php");
        }
    }

    // Core data structure: Stack — LIFO, newest entry on top
    private final Deque<LogEntry> logStack = new ArrayDeque<>();
    private static final int MAX_STACK_SIZE = 500; // cap memory usage

    private final AlertQueue       alertQueue;
    private final TrafficMonitor   trafficMonitor;
    private final String           logFilePath;

    private long    lastFileSize   = 0;
    private int     totalParsed    = 0;
    private int     suspiciousCount = 0;

    private ScheduledExecutorService scheduler;
    private Consumer<String>         logCallback;
    private Consumer<LogEntry>       entryCallback;  // called per new entry for live UI

    // Simulation fallback entries (realistic Apache log format)
    private static final String[] SIM_ENTRIES = {
        "127.0.0.1 - admin [%s] \"POST /dvwa/login.php HTTP/1.1\" 302 -",
        "192.168.1.101 - - [%s] \"GET /dvwa/vulnerabilities/sqli/?id=1'+OR+'1'='1 HTTP/1.1\" 200 4821",
        "192.168.1.101 - - [%s] \"GET /dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script> HTTP/1.1\" 200 3102",
        "192.168.1.101 - - [%s] \"POST /dvwa/vulnerabilities/brute/ HTTP/1.1\" 200 1752",
        "10.0.0.55 - - [%s] \"GET /dvwa/vulnerabilities/fi/?page=../../etc/passwd HTTP/1.1\" 200 2048",
        "127.0.0.1 - - [%s] \"GET /dvwa/phpinfo.php HTTP/1.1\" 200 76321",
        "172.16.0.5 - - [%s] \"GET /.env HTTP/1.1\" 404 196",
        "192.168.1.102 - - [%s] \"GET /dvwa/index.php HTTP/1.1\" 200 2890",
        "127.0.0.1 - - [%s] \"GET /dvwa/setup.php HTTP/1.1\" 200 4410",
        "192.168.1.101 - - [%s] \"GET /dvwa/vulnerabilities/brute/?username=admin&password=1234 HTTP/1.1\" 200 1752"
    };

    public LogAnalyzer(String logFilePath, AlertQueue alertQueue, TrafficMonitor trafficMonitor) {
        this.logFilePath    = logFilePath;
        this.alertQueue     = alertQueue;
        this.trafficMonitor = trafficMonitor;
    }

    public void setLogCallback(Consumer<String> cb)      { this.logCallback   = cb; }
    public void setEntryCallback(Consumer<LogEntry> cb)  { this.entryCallback = cb; }

    /** Start tailing the log file every 1.5 seconds. */
    public void startAnalyzing() {
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::readNewLines, 0, 1500, TimeUnit.MILLISECONDS);
        log("[LogAnalyzer] Started — tailing: " + logFilePath);
    }

    public void stopAnalyzing() {
        if (scheduler != null) scheduler.shutdownNow();
        log("[LogAnalyzer] Stopped.");
    }

    private void readNewLines() {
        File f = new File(logFilePath);
        if (!f.exists() || !f.canRead()) {
            simulateEntry(); // fallback
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            long len = raf.length();
            if (len < lastFileSize) lastFileSize = 0; // log was rotated
            raf.seek(lastFileSize);
            String line;
            while ((line = raf.readLine()) != null) {
                parseLine(line);
            }
            lastFileSize = raf.getFilePointer();
        } catch (IOException e) {
            simulateEntry();
        }
    }

    private void parseLine(String raw) {
        Matcher m = LOG_PATTERN.matcher(raw);
        if (!m.find()) return;
        try {
            String ip        = m.group(1);
            String timestamp = m.group(2);
            String method    = m.group(3);
            String path      = m.group(4);
            int    code      = Integer.parseInt(m.group(5));
            int    bytes     = m.group(6).equals("-") ? 0 : Integer.parseInt(m.group(6));

            LogEntry entry = new LogEntry(ip, timestamp, method, path, code, bytes, raw);
            pushEntry(entry);

            // Feed into TrafficMonitor's HashMap
            if (trafficMonitor != null) trafficMonitor.recordHit(ip, path, code);

            if (entry.isSuspicious()) {
                suspiciousCount++;
                alertQueue.enqueue(
                    "LOG ANOMALY", ip,
                    method + " " + path + " [" + code + "]",
                    code >= 500 ? AlertQueue.Severity.HIGH : AlertQueue.Severity.MEDIUM
                );
            }
            if (entryCallback != null) entryCallback.accept(entry);
            log(String.format("[LOG] %-16s %s %s [%d]", ip, method, path, code));
        } catch (Exception ignored) {}
    }

    /** Push onto stack — cap at MAX_STACK_SIZE (remove bottom if full). */
    private synchronized void pushEntry(LogEntry entry) {
        logStack.push(entry);          // O(1) push to top
        totalParsed++;
        if (logStack.size() > MAX_STACK_SIZE) {
            // Remove oldest (bottom of stack = last element in deque)
            ((ArrayDeque<LogEntry>) logStack).removeLast();
        }
    }

    // ── Stack operations exposed to UI ──────────────────────────────────────

    /** Peek at the most recent entry without removing. O(1). */
    public synchronized LogEntry peekLatest() {
        return logStack.isEmpty() ? null : logStack.peek();
    }

    /** Pop the latest entry. O(1). */
    public synchronized LogEntry popLatest() {
        return logStack.isEmpty() ? null : logStack.pop();
    }

    /** Return a snapshot of the top N entries (newest first). */
    public synchronized List<LogEntry> getRecentEntries(int n) {
        List<LogEntry> result = new ArrayList<>();
        Iterator<LogEntry> it = logStack.iterator();
        int count = 0;
        while (it.hasNext() && count < n) {
            result.add(it.next());
            count++;
        }
        return result;
    }

    /** Filter entries by IP — O(n) scan of the stack. */
    public synchronized List<LogEntry> filterByIp(String ip) {
        List<LogEntry> result = new ArrayList<>();
        for (LogEntry e : logStack) {
            if (e.ip.equals(ip)) result.add(e);
        }
        return result;
    }

    /** Filter entries that are suspicious — for anomaly highlight panel. */
    public synchronized List<LogEntry> getSuspiciousEntries(int limit) {
        List<LogEntry> result = new ArrayList<>();
        for (LogEntry e : logStack) {
            if (e.isSuspicious()) result.add(e);
            if (result.size() >= limit) break;
        }
        return result;
    }

    // ── Simulation ──────────────────────────────────────────────────────────

    private int simIndex = 0;
    private void simulateEntry() {
        String ts  = new java.text.SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss Z").format(new java.util.Date());
        String raw = String.format(SIM_ENTRIES[simIndex % SIM_ENTRIES.length], ts);
        simIndex++;
        parseLine(raw);
    }

    private void log(String msg) { if (logCallback != null) logCallback.accept(msg); }

    public int  getTotalParsed()     { return totalParsed; }
    public int  getSuspiciousCount() { return suspiciousCount; }
    public int  getStackSize()       { return logStack.size(); }
}
