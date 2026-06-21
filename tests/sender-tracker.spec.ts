import { describe, expect, it } from 'vitest';

import { SenderTracker } from '../src/detection/sender-tracker.js';

const SENDER_A = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SENDER_B = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const NOW = Date.now();
const MIN = 60_000;

describe('SenderTracker', () => {
  it('returns null for unseen sender', () => {
    const tracker = new SenderTracker(60);
    expect(tracker.getSenderHistory(SENDER_A, NOW)).toBeNull();
  });

  it('records tx and returns history with correct counts', () => {
    const tracker = new SenderTracker(60);
    tracker.recordTx(SENDER_A, NOW, ['rule:foo', 'rule:bar']);
    const history = tracker.getSenderHistory(SENDER_A, NOW + 1);
    expect(history).not.toBeNull();
    expect(history!.txCount).toBe(1);
    expect(history!.alertCount).toBe(2);
    expect(history!.recentAlertRuleIds).toEqual(['rule:foo', 'rule:bar']);
  });

  it('accumulates across multiple TXs', () => {
    const tracker = new SenderTracker(60);
    tracker.recordTx(SENDER_A, NOW, ['rule:a']);
    tracker.recordTx(SENDER_A, NOW + 1_000, ['rule:b', 'rule:c']);
    tracker.recordTx(SENDER_A, NOW + 2_000, []);
    const history = tracker.getSenderHistory(SENDER_A, NOW + 3_000);
    expect(history!.txCount).toBe(3);
    expect(history!.alertCount).toBe(3);
    expect(history!.recentAlertRuleIds).toContain('rule:a');
    expect(history!.recentAlertRuleIds).toContain('rule:c');
  });

  it('does not mix up senders', () => {
    const tracker = new SenderTracker(60);
    tracker.recordTx(SENDER_A, NOW, ['rule:a']);
    tracker.recordTx(SENDER_B, NOW, []);
    expect(tracker.getSenderHistory(SENDER_A, NOW + 1)!.alertCount).toBe(1);
    expect(tracker.getSenderHistory(SENDER_B, NOW + 1)!.alertCount).toBe(0);
  });

  it('returns null for sender outside the time window', () => {
    const tracker = new SenderTracker(60); // 60-minute window
    tracker.recordTx(SENDER_A, NOW - 61 * MIN, ['rule:old']);
    // Purge and check
    tracker.purgeExpired(NOW);
    expect(tracker.getSenderHistory(SENDER_A, NOW)).toBeNull();
  });

  it('getSenderHistory returns null when last seen is outside window even without purge', () => {
    const tracker = new SenderTracker(60);
    tracker.recordTx(SENDER_A, NOW - 61 * MIN, ['rule:old']);
    // No purge called — but getSenderHistory still respects window
    expect(tracker.getSenderHistory(SENDER_A, NOW)).toBeNull();
  });

  it('keeps only last 20 alert rule IDs (memory cap)', () => {
    const tracker = new SenderTracker(60);
    for (let i = 0; i < 25; i++) {
      tracker.recordTx(SENDER_A, NOW + i * 1_000, [`rule:${i}`]);
    }
    const history = tracker.getSenderHistory(SENDER_A, NOW + 26_000);
    expect(history!.recentAlertRuleIds.length).toBeLessThanOrEqual(10); // getSenderHistory returns last 10
    expect(history!.alertCount).toBe(25); // but total count is preserved
  });
});
