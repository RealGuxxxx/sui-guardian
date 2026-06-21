import type { RuntimeState } from './types.js';

export const DEMO_STATE: RuntimeState = {
  lastCheckpoint: 289578632,
  packageVersions: {
    "0xcaf6ba059d539a97646d47f0b9ddf843e138d215e2a12ca1f4585d386f7aec3a": {
      "packageAddress": "0xcaf6ba059d539a97646d47f0b9ddf843e138d215e2a12ca1f4585d386f7aec3a",
      "version": 2,
      "digest": "CLnGztoLq1de8pQiYRpbhxxRjNM1oUUJwLnamFBMRiKE",
      "sender": "0x37f187e1e54e9c9b8c78b6c46a7281f644ebc62e75493623edcaa6d1dfcf64d2",
      "updatedAt": "2026-04-24T06:11:10.844Z"
    }
  },
  trackedObjectSnapshots: {},
  priceReferenceProfiles: {},
  objectBaselineProfiles: {},
  flowHistory: {},
  recentTransactionDigests: [],
  recentAlerts: [
    {
      "id": "alert-1",
      "createdAt": "2026-06-21T12:00:00.000Z",
      "projectId": "deepbook-v3",
      "projectName": "DeepBook V3 Main Pool",
      "ruleId": "package-upgrade:unauthorized-upgrade",
      "ruleName": "Unauthorized Contract Upgrade",
      "severity": "critical",
      "summary": "Unauthorized package upgrade attempt detected on package 0xdee9...3425 by untrusted sender.",
      "details": {
        "package": "0xdee97f7c6590b1e10472d6e3c02e1b10a24177d468117a2a5ec8e2b7e51c3425",
        "sender": "0x4a92...11b2",
        "allowedSenders": ["0x37f1...64d2"],
        "checkpoint": 289578100,
        "digest": "8xNWXKZfYJ2raAoj1o5hVVk4LxVJn88qBzVCPwMU9Nd"
      },
      "fingerprint": "unauthorized-upgrade-fingerprint",
      "status": "open",
      "firstSeenAt": "2026-06-21T12:00:00.000Z",
      "lastSeenAt": "2026-06-21T12:00:00.000Z",
      "updatedAt": "2026-06-21T12:00:00.000Z",
      "occurrences": 1,
      "note": "Awaiting admin confirmation to verify if the address was added to the emergency whitelist."
    },
    {
      "id": "alert-2",
      "createdAt": "2026-06-21T11:45:00.000Z",
      "projectId": "interest-protocol",
      "projectName": "Interest Lending Pool",
      "ruleId": "outflow-spike:vault-drain",
      "ruleName": "Abnormal Vault Asset Outflow",
      "severity": "high",
      "summary": "Asset outflow of 75,000 SUI exceeded hourly safety threshold (50,000 SUI) on Vault 0x8a92...e3b1.",
      "details": {
        "vault": "0x8a9284cf6ba059d539a97646d47f0b9ddf843e138d215e2a12ca1f4585d386f7aec3b",
        "outflowAmount": "75000",
        "hourlyThreshold": "50000",
        "token": "SUI",
        "receiver": "0xbf18...25a9",
        "digest": "5y96f841-2431-424a-bf18-25a962659b6a"
      },
      "fingerprint": "vault-drain-fingerprint",
      "status": "open",
      "firstSeenAt": "2026-06-21T11:45:00.000Z",
      "lastSeenAt": "2026-06-21T11:55:00.000Z",
      "updatedAt": "2026-06-21T11:55:00.000Z",
      "occurrences": 3,
      "note": "Triggered automated cooling-down phase for the vault. Alert routed to operations team."
    },
    {
      "id": "alert-3",
      "createdAt": "2026-06-21T10:30:00.000Z",
      "projectId": "deepbook-v3",
      "projectName": "DeepBook V3 Main Pool",
      "ruleId": "failure-spike:failure-burst",
      "ruleName": "High Transaction Failure Rate",
      "severity": "medium",
      "summary": "Package 0xcaf6...c3a triggered 45 failed transactions in a 60-second window (threshold: 30).",
      "details": {
        "package": "0xcaf6ba059d539a97646d47f0b9ddf843e138d215e2a12ca1f4585d386f7aec3a",
        "windowSeconds": 60,
        "failedTxCount": 45,
        "latestError": "Error in Move execution: Abort code 5 in module big_vector::leaf_remove",
        "latestDigest": "4e2a40da-f425-4aff-bffc-4579bb456af8"
      },
      "fingerprint": "failure-burst-fingerprint",
      "status": "acknowledged",
      "firstSeenAt": "2026-06-21T10:30:00.000Z",
      "lastSeenAt": "2026-06-21T10:35:00.000Z",
      "updatedAt": "2026-06-21T10:40:00.000Z",
      "occurrences": 12,
      "note": "Dev team notified. Looks like an oracle synchronization issue during high volatility."
    },
    {
      "id": "alert-4",
      "createdAt": "2026-06-21T09:15:00.000Z",
      "projectId": "interest-protocol",
      "projectName": "Interest Lending Pool",
      "ruleId": "function-guard:parameter-change",
      "ruleName": "Config Parameter Modification",
      "severity": "low",
      "summary": "Global protocol fee modified from 30 bps to 35 bps by admin account 0x37f1...64d2.",
      "details": {
        "function": "protocol_config::set_fee",
        "sender": "0x37f187e1e54e9c9b8c78b6c46a7281f644ebc62e75493623edcaa6d1dfcf64d2",
        "oldValue": "30",
        "newValue": "35",
        "checkpoint": 289574500
      },
      "fingerprint": "fee-modification-fingerprint",
      "status": "resolved",
      "firstSeenAt": "2026-06-21T09:15:00.000Z",
      "lastSeenAt": "2026-06-21T09:15:00.000Z",
      "updatedAt": "2026-06-21T09:30:00.000Z",
      "occurrences": 1,
      "note": "Scheduled governance proposal executed successfully."
    }
  ],
  scanHistory: [
    {
      "id": "scan-1",
      "startedAt": "2026-06-21T12:28:00.000Z",
      "finishedAt": "2026-06-21T12:28:01.200Z",
      "latestCheckpoint": 289578632,
      "checkpointsProcessed": 24,
      "transactionsProcessed": 142,
      "alertsTriggered": 0,
      "durationMs": 1200,
      "success": true
    },
    {
      "id": "scan-2",
      "startedAt": "2026-06-21T12:27:00.000Z",
      "finishedAt": "2026-06-21T12:27:00.950Z",
      "latestCheckpoint": 289578608,
      "checkpointsProcessed": 18,
      "transactionsProcessed": 98,
      "alertsTriggered": 0,
      "durationMs": 950,
      "success": true
    },
    {
      "id": "scan-3",
      "startedAt": "2026-06-21T12:26:00.000Z",
      "finishedAt": "2026-06-21T12:26:01.150Z",
      "latestCheckpoint": 289578590,
      "checkpointsProcessed": 20,
      "transactionsProcessed": 115,
      "alertsTriggered": 0,
      "durationMs": 1150,
      "success": true
    },
    {
      "id": "scan-4",
      "startedAt": "2026-06-21T12:25:00.000Z",
      "finishedAt": "2026-06-21T12:25:00.800Z",
      "latestCheckpoint": 289578570,
      "checkpointsProcessed": 15,
      "transactionsProcessed": 76,
      "alertsTriggered": 0,
      "durationMs": 800,
      "success": true
    }
  ],
  updatedAt: "2026-06-21T12:28:01.200Z"
};
