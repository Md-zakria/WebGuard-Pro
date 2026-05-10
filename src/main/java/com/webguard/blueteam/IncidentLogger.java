package com.webguard.blueteam;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.function.Consumer;

/**
 * IncidentLogger — records all Blue Team defensive events in a timeline.
 * Data Structure: LinkedList<IncidentEvent>
 * Why LinkedList: a timeline is a sequential chain where we frequently
 * append to the tail (new events) and occasionally insert mid-chain
 * (correlate a response to an earlier incident). LinkedList O(1) for both.
 * Also supports efficient iteration from head (oldest) for report export.
 *
 * This is the audit trail for the project report — every block, patch,
 * alert acknowledgement, and hardening action gets logged here.
 */
public class IncidentLogger {

    public enum EventType {
        ALERT_RECEIVED, IP_BLOCKED, IP_UNBLOCKED,
        PATCH_APPLIED, HARDEN_CHECK_RUN, THREAT_MITIGATED,
        MONITOR_STARTED, MONITOR_STOPPED, MANUAL_NOTE
    }

    public static class IncidentEvent {
        public final String    id;
        public final EventType type;
        public final String    actor;       // IP, module name, or "ANALYST"
        public final String    description;
        public final String    timestamp;
        public final long      epochMs;
        public String          linkedEventId;  // chain to related event

        public IncidentEvent(EventType type, String actor, String description) {
            this.id          = "INC-" + System.currentTimeMillis();
            this.type        = type;
            this.actor       = actor;
            this.description = description;
            this.epochMs     = System.currentTimeMillis();
            this.timestamp   = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                                   .format(new Date(this.epochMs));
        }

        @Override public String toString() {
            return String.format("[%s] %-20s  %-16s  %s",
                    timestamp, type, actor, description);
        }
    }

    // Core data structure: LinkedList — O(1) append + O(1) iterator advance
    private final LinkedList<IncidentEvent> timeline = new LinkedList<>();

    private final String logFilePath;
    private Consumer<String>        logCallback;
    private Consumer<IncidentEvent> eventCallback;

    public IncidentLogger(String logFilePath) {
        this.logFilePath = logFilePath;
    }

    public void setLogCallback(Consumer<String>        cb) { this.logCallback  = cb; }
    public void setEventCallback(Consumer<IncidentEvent> cb) { this.eventCallback = cb; }

    /**
     * Log a new event — appended to the tail of the LinkedList. O(1).
     */
    public synchronized IncidentEvent log(EventType type, String actor, String description) {
        IncidentEvent event = new IncidentEvent(type, actor, description);
        timeline.addLast(event);     // O(1) LinkedList tail append
        writeToFile(event);
        if (logCallback != null)   logCallback.accept(event.toString());
        if (eventCallback != null) eventCallback.accept(event);
        return event;
    }

    /** Link two events (e.g., "IP blocked IN RESPONSE TO alert-123"). */
    public synchronized void linkEvents(String eventId, String linkedId) {
        for (IncidentEvent e : timeline) {
            if (e.id.equals(eventId)) {
                e.linkedEventId = linkedId;
                return;
            }
        }
    }

    // ── Convenience logging methods called by other Blue Team modules ────────

    public IncidentEvent logAlert(String sourceIp, AlertQueue.Severity severity, String message) {
        return log(EventType.ALERT_RECEIVED, sourceIp,
                   "[" + severity + "] " + message);
    }

    public IncidentEvent logBlock(String ip, String reason) {
        return log(EventType.IP_BLOCKED, ip, "Blocked: " + reason);
    }

    public IncidentEvent logUnblock(String ip) {
        return log(EventType.IP_UNBLOCKED, ip, "Unblocked by analyst");
    }

    public IncidentEvent logPatch(String cveId, String status) {
        return log(EventType.PATCH_APPLIED, "ANALYST", cveId + " → " + status);
    }

    public IncidentEvent logHarden(int score, int checks) {
        return log(EventType.HARDEN_CHECK_RUN, "HardenChecker",
                   checks + " checks run — score: " + score + "/100");
    }

    public IncidentEvent logMitigation(String threatName, double score) {
        return log(EventType.THREAT_MITIGATED, "ANALYST",
                   "Mitigated: " + threatName + " (score " + String.format("%.1f", score) + ")");
    }

    public IncidentEvent logNote(String note) {
        return log(EventType.MANUAL_NOTE, "ANALYST", note);
    }

    // ── Timeline queries ─────────────────────────────────────────────────────

    /** Return the N most recent events (tail of timeline). */
    public synchronized List<IncidentEvent> getRecent(int n) {
        List<IncidentEvent> result = new ArrayList<>();
        Iterator<IncidentEvent> it = timeline.descendingIterator();  // O(1) per step
        while (it.hasNext() && result.size() < n) {
            result.add(it.next());
        }
        return result;
    }

    /** Return all events of a given type. O(n) scan. */
    public synchronized List<IncidentEvent> filterByType(EventType type) {
        List<IncidentEvent> result = new ArrayList<>();
        for (IncidentEvent e : timeline) {    // O(n) forward iteration
            if (e.type == type) result.add(e);
        }
        return result;
    }

    /** Return events involving a specific IP/actor. O(n) scan. */
    public synchronized List<IncidentEvent> filterByActor(String actor) {
        List<IncidentEvent> result = new ArrayList<>();
        for (IncidentEvent e : timeline) {
            if (e.actor.equals(actor)) result.add(e);
        }
        return result;
    }

    /** Export full timeline as text for report. Iterates head→tail (oldest first). */
    public synchronized String exportTimeline() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== WebGuard Pro — Incident Timeline ===\n");
        sb.append(String.format("Generated: %s  |  Total events: %d\n\n",
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()), timeline.size()));
        for (IncidentEvent e : timeline) {     // head→tail = chronological
            sb.append(e.toString()).append("\n");
            if (e.linkedEventId != null) {
                sb.append("         └─ linked to: ").append(e.linkedEventId).append("\n");
            }
        }
        return sb.toString();
    }

    private void writeToFile(IncidentEvent event) {
        try (FileWriter fw = new FileWriter(logFilePath, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            bw.write(event.toString());
            bw.newLine();
        } catch (IOException ignored) { /* log file optional */ }
    }

    public synchronized int    size()     { return timeline.size(); }
    public synchronized boolean isEmpty() { return timeline.isEmpty(); }

    /** Head of list = oldest event. O(1). */
    public synchronized IncidentEvent getOldest() { return timeline.peekFirst(); }
    /** Tail of list = newest event. O(1). */
    public synchronized IncidentEvent getNewest() { return timeline.peekLast();  }
}
