package com.webguard.blueteam;

import java.util.*;
import java.util.function.Consumer;

/**
 * FirewallManager — maintains the list of blocked IP addresses.
 * Data Structure: LinkedList<BlockedEntry>
 * Why LinkedList: blocking/unblocking IPs = frequent insert/delete at
 * arbitrary positions. LinkedList gives O(1) add/remove once the node
 * is found, vs ArrayList's O(n) shift cost on removal.
 * Also used as a discovery-order chain — new blocks appended to the tail.
 *
 * In a real system this would write iptables/Windows Firewall rules.
 * Here it manages the block list and simulates rule application.
 */
public class FirewallManager {

    public static class BlockedEntry {
        public final String ip;
        public final String reason;
        public final String blockedAt;
        public final String blockedBy;  // "AUTO" or "MANUAL"
        public boolean      active;

        public BlockedEntry(String ip, String reason, String blockedBy) {
            this.ip        = ip;
            this.reason    = reason;
            this.blockedBy = blockedBy;
            this.blockedAt = new java.text.SimpleDateFormat("HH:mm:ss")
                                 .format(new java.util.Date());
            this.active    = true;
        }

        @Override public String toString() {
            return String.format("%-16s  [%s]  %s  (by %s)", ip, blockedAt, reason, blockedBy);
        }
    }

    // Core data structure: LinkedList — O(1) insert/delete, O(n) search
    private final LinkedList<BlockedEntry> blockList = new LinkedList<>();

    // HashMap for O(1) "is this IP blocked?" check — complements the LinkedList
    private final Map<String, BlockedEntry> blockIndex = new HashMap<>();

    private Consumer<String>       logCallback;
    private Consumer<List<BlockedEntry>> listCallback;

    public void setLogCallback(Consumer<String> cb)               { this.logCallback  = cb; }
    public void setListCallback(Consumer<List<BlockedEntry>> cb)  { this.listCallback = cb; }

    /**
     * Block an IP address.
     * LinkedList.addLast() = O(1) — append to tail, preserving insertion order.
     */
    public synchronized boolean blockIp(String ip, String reason, String blockedBy) {
        if (blockIndex.containsKey(ip)) {
            log("[FirewallManager] " + ip + " is already blocked.");
            return false;
        }
        BlockedEntry entry = new BlockedEntry(ip, reason, blockedBy);
        blockList.addLast(entry);      // O(1) linked list append
        blockIndex.put(ip, entry);     // O(1) index insert
        applyRule(ip, true);
        log("[FirewallManager] BLOCKED: " + entry);
        notifyListeners();
        return true;
    }

    /** Auto-block triggered by AnomalyDetector (called with "AUTO" flag). */
    public synchronized boolean autoBlock(String ip, String reason) {
        return blockIp(ip, reason, "AUTO");
    }

    /**
     * Unblock an IP.
     * LinkedList.remove(Object) = O(n) scan then O(1) pointer unlink.
     */
    public synchronized boolean unblockIp(String ip) {
        BlockedEntry entry = blockIndex.remove(ip);
        if (entry == null) {
            log("[FirewallManager] " + ip + " is not blocked.");
            return false;
        }
        entry.active = false;
        blockList.remove(entry);       // O(n) find + O(1) unlink
        applyRule(ip, false);
        log("[FirewallManager] UNBLOCKED: " + ip);
        notifyListeners();
        return true;
    }

    /** O(1) lookup via index — the HashMap makes this fast. */
    public synchronized boolean isBlocked(String ip) {
        return blockIndex.containsKey(ip);
    }

    /** Retrieve a specific entry. O(1) via index. */
    public synchronized BlockedEntry getEntry(String ip) {
        return blockIndex.get(ip);
    }

    /** Return full block list snapshot (for UI table). */
    public synchronized List<BlockedEntry> getBlockList() {
        return new ArrayList<>(blockList);
    }

    /** Remove all AUTO-blocked entries (manual blocks remain). */
    public synchronized int clearAutoBlocks() {
        int removed = 0;
        Iterator<BlockedEntry> it = blockList.iterator();
        while (it.hasNext()) {
            BlockedEntry e = it.next();
            if ("AUTO".equals(e.blockedBy)) {
                it.remove();               // O(1) via iterator
                blockIndex.remove(e.ip);
                applyRule(e.ip, false);
                removed++;
            }
        }
        log("[FirewallManager] Cleared " + removed + " auto-blocks.");
        notifyListeners();
        return removed;
    }

    /** Simulate writing an iptables / netsh rule. */
    private void applyRule(String ip, boolean block) {
        String action = block ? "DROP" : "ACCEPT";
        // Real command would be: iptables -I INPUT -s <ip> -j DROP
        // Windows: netsh advfirewall firewall add rule name="WebGuard-<ip>" ...
        log(String.format("[FirewallManager] [SIM] iptables -I INPUT -s %s -j %s", ip, action));
    }

    private void notifyListeners() {
        if (listCallback != null) listCallback.accept(getBlockList());
    }

    private void log(String msg) { if (logCallback != null) logCallback.accept(msg); }

    public synchronized int  size()      { return blockList.size(); }
    public synchronized boolean isEmpty() { return blockList.isEmpty(); }
}
