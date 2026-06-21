/**
 * Tracks per-sender activity over a rolling time window.
 * Used to detect multi-TX attack sequences (probe → exploit pattern).
 */

export interface SenderHistory {
  /** Number of TXs seen from this sender in the tracking window. */
  txCount: number;
  /** Number of alerts triggered by this sender in the tracking window. */
  alertCount: number;
  /** Window duration in minutes. */
  windowMinutes: number;
  /** Last 10 alert rule IDs triggered by this sender (oldest first). */
  recentAlertRuleIds: string[];
}

interface SenderEntry {
  txCount: number;
  alertCount: number;
  firstSeenMs: number;
  lastSeenMs: number;
  alertRuleIds: string[];
}

export class SenderTracker {
  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly data = new Map<string, SenderEntry>();

  constructor(windowMinutes = 60, maxEntries = 5_000) {
    this.windowMs = windowMinutes * 60_000;
    this.maxEntries = maxEntries;
  }

  /**
   * Record a transaction from sender. Call AFTER running detectors so that
   * `getSenderHistory()` returns only prior-TX history.
   */
  recordTx(sender: string, timestampMs: number, alertRuleIds: string[] = []): void {
    // Periodically purge stale entries (every ~100 calls)
    if (this.data.size > this.maxEntries || Math.random() < 0.01) {
      this.purgeExpired(timestampMs);
    }

    const existing = this.data.get(sender) ?? {
      txCount: 0,
      alertCount: 0,
      firstSeenMs: timestampMs,
      lastSeenMs: timestampMs,
      alertRuleIds: [],
    };

    existing.txCount += 1;
    existing.lastSeenMs = timestampMs;

    if (alertRuleIds.length > 0) {
      existing.alertCount += alertRuleIds.length;
      existing.alertRuleIds.push(...alertRuleIds);
      // Keep last 20 rule IDs to cap memory
      if (existing.alertRuleIds.length > 20) {
        existing.alertRuleIds = existing.alertRuleIds.slice(-20);
      }
    }

    this.data.set(sender, existing);
  }

  /**
   * Get the activity history for a sender from BEFORE the current TX.
   * Returns null if the sender has not been seen in the current window.
   */
  getSenderHistory(sender: string, nowMs?: number): SenderHistory | null {
    const entry = this.data.get(sender);
    if (!entry) return null;

    const cutoff = (nowMs ?? Date.now()) - this.windowMs;
    if (entry.lastSeenMs < cutoff) return null;

    return {
      txCount: entry.txCount,
      alertCount: entry.alertCount,
      windowMinutes: this.windowMs / 60_000,
      recentAlertRuleIds: entry.alertRuleIds.slice(-10),
    };
  }

  /** Remove entries whose last-seen timestamp is older than the window. */
  purgeExpired(nowMs = Date.now()): void {
    const cutoff = nowMs - this.windowMs;
    for (const [sender, entry] of this.data.entries()) {
      if (entry.lastSeenMs < cutoff) {
        this.data.delete(sender);
      }
    }
  }

  /** Total unique senders tracked (for metrics). */
  get senderCount(): number {
    return this.data.size;
  }
}
