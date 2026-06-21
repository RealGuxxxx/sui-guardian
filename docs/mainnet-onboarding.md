# Mainnet Onboarding Runbook

This is the production path for turning the demo into a real project monitor.

## 1. Create A Project Config

Start from the template:

```bash
cp config/projects.example.yml config/mainnet.my-protocol.yml
```

This repository also includes a concrete read-only example:

```bash
npm run mainnet:deepbook:scan
```

See `config/mainnet.deepbook.yml` and `docs/deepbook-mainnet-config.md`.

Replace every placeholder address with audited project data:

- `projects[*].packages[*].address`: current mainnet package IDs.
- `allowedUpgradeSenders`: multisig, governance, or deployer addresses allowed to publish upgrades.
- `deprecatedAddresses`: old package IDs that should no longer receive user traffic.
- `protectedAddresses`: treasuries, vault-owning objects, custody addresses, and other high-value owners.
- `functionGuards`: admin-only functions such as pause, unpause, upgrade, emergency withdraw, price update, fee change, and role changes.
- `trackedObjects`: admin, vault, oracle, pool, market, config, and risk-parameter objects.
- `objectBaselines`: invariants for permission fields, price fields, and inventory fields.

Do not use the testnet range package as production evidence. It is only for reproducible judging and regression tests.

## 2. Run Read-Only Mainnet Scanning

```bash
API_KEY=replace-with-dashboard-token \
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/replace/me \
npm start -- --config config/mainnet.my-protocol.yml
```

Then open:

- Dashboard: `http://127.0.0.1:3000/`
- Health: `http://127.0.0.1:3000/api/health`
- Readiness: `http://127.0.0.1:3000/api/readiness`

The app is read-only against Sui RPC. It does not sign transactions or mutate on-chain state.

## 3. Validate Signal Quality

Before submitting a production claim, capture:

- At least one successful mainnet scan.
- A readiness result with no required failures.
- Config summary showing real packages, protected addresses, function guards, object baselines, and webhook enabled.
- One alert lifecycle action: open to acknowledged or resolved.
- A webhook delivery sample in Slack, Discord, or the local webhook sink.

For local webhook proof:

```bash
npm run webhook:sink
```

In another terminal:

```bash
ALERT_WEBHOOK_URL=http://127.0.0.1:8787/webhook npm run demo:overflow
```

Received webhook events are written to `.data/webhook-events.jsonl`.

## 4. AI Rule Promotion

Use AI-generated rules as a staged deployment, not as immediate production truth:

1. Generate rules from Move source and deployment manifest.
2. Start with `aiRules.shadow.enabled: true` and `aiRules.shadow.notify: false`.
3. Promote to `traffic_failure`, then `objects_prices`, then `full` after reviewing false positives.
4. Keep generated rules in version control or export them for audit before production use.

## 5. Demo Claim Boundary

For Overflow judging, the strongest claim is:

> Sui Guardian already scans live Sui chain data, detects reproducible exploit patterns on testnet, and has a concrete read-only mainnet onboarding path for real DeFi teams.

Avoid claiming that a third-party mainnet protocol is protected until its exact package IDs, treasury addresses, admin allowlists, and webhook target have been verified by that team.
