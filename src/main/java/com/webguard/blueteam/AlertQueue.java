package com.webguard.blueteam;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.Queue;
import java.util.ArrayList;
import java.util.List;

/**
 * AlertQueue — FIFO pipeline for security alerts.
 * Data Structure: Queue<Alert> (LinkedList implementation)
 * Why Queue: alerts must be processed in the order they arrive —
 * first anomaly detected = first alert handled (FIFO).
 */
public class AlertQueue {

    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    public static class Alert {
        public final String id;
        public final String type;
        public final String sourceIp;
        public final String message;
        public final Severity severity;
        public final String timestamp;
        public boolean acknowledged;

        public Alert(String type, String sourceIp, String message, Severity severity) {
            this.id        = "ALT-" + System.currentTimeMillis();
            this.type      = type;
            this.sourceIp  = sourceIp;
            this.message   = message;
            this.severity  = severity;
            this.timestamp = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("HH:mm:ss"));
            this.acknowledged = false;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s | %s | %s → %s",
                    timestamp, severity, type, sourceIp, message);
        }
    }

    // Core queue — FIFO order guaranteed
    private final Queue<Alert> queue = new LinkedList<>();

    // History of all alerts ever enqueued (for the UI log panel)
    private final List<Alert> history = new ArrayList<>();

    private int totalEnqueued = 0;
    private int totalProcessed = 0;

    /** Enqueue a new alert. */
    public synchronized void enqueue(Alert alert) {
        queue.offer(alert);
        history.add(alert);
        totalEnqueued++;
    }

    /** Convenience factory — enqueue directly from parts. */
    public synchronized void enqueue(String type, String sourceIp,
                                     String message, Severity severity) {
        enqueue(new Alert(type, sourceIp, message, severity));
    }

    /** Dequeue and return the next alert (FIFO), or null if empty. */
    public synchronized Alert dequeue() {
        Alert a = queue.poll();
        if (a != null) {
            a.acknowledged = true;
            totalProcessed++;
        }
        return a;
    }

    /** Peek at the front without removing. */
    public synchronized Alert peek() {
        return queue.peek();
    }

    /** Acknowledge (remove) alerts by severity — used by DefendDashboard "Clear Low" action. */
    public synchronized int clearBySeverity(Severity severity) {
        int removed = 0;
        Queue<Alert> temp = new LinkedList<>();
        while (!queue.isEmpty()) {
            Alert a = queue.poll();
            if (a.severity == severity) {
                a.acknowledged = true;
                totalProcessed++;
                removed++;
            } else {
                temp.offer(a);
            }
        }
        queue.addAll(temp);
        return removed;
    }

    public synchronized boolean isEmpty()      { return queue.isEmpty(); }
    public synchronized int    size()          { return queue.size(); }
    public synchronized List<Alert> getHistory() { return new ArrayList<>(history); }
    public int getTotalEnqueued()  { return totalEnqueued; }
    public int getTotalProcessed() { return totalProcessed; }

    /** Drain all pending alerts into a list (used for bulk UI refresh). */
    public synchronized List<Alert> drainAll() {
        List<Alert> drained = new ArrayList<>();
        Alert a;
        while ((a = queue.poll()) != null) {
            a.acknowledged = true;
            totalProcessed++;
            drained.add(a);
        }
        return drained;
    }
}
