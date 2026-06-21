# Judge Quickstart

## Two-Minute Flow

```bash
npm install
npm run build
npm run demo:overflow
```

Open the printed dashboard URL and show:

1. `Overflow 提交就绪度`
2. scan history with checkpoint progress
3. monitored package and protected assets
4. staged exploit alerts
5. one alert detail with severity, risk score, evidence, and remediation
6. acknowledge or resolve the alert
7. `runbooks/latest-defi-range.json` for package ID, object IDs, tx digests, and expected-rule coverage

## Notification Proof

Optional terminal A:

```bash
npm run webhook:sink
```

Terminal B:

```bash
ALERT_WEBHOOK_URL=http://127.0.0.1:8787/webhook npm run demo:overflow
```

This records delivered alerts to `.data/webhook-events.jsonl`, proving the response loop is not dashboard-only.

## Mainnet Proof

```bash
npm run mainnet:deepbook:scan
npm run build
npm run mainnet:deepbook
```

Open `http://127.0.0.1:3020/` and show that the active network is `mainnet`, the project is `DeepBook V3 Mainnet Read-Only`, and the latest scan processed live mainnet checkpoints.

The latest captured mainnet evidence is stored in `runbooks/latest-mainnet-deepbook.json`.

## What To Say

Sui Guardian is a real-time incident monitor for Sui DeFi teams. It watches packages, guarded functions, protected vaults, oracle and admin objects, behavior anomalies, price deviation, and fund-flow patterns, then turns detections into actionable incidents with remediation and webhook routing.

The testnet range is used because it is reproducible for judges. The production path is the read-only mainnet config flow in `docs/mainnet-onboarding.md`.

The included DeepBook config is the best mainnet proof path because it uses public Sui documentation and read-only GraphQL scanning.

## Current Evidence

The latest successful DeFi range report is at:

```text
runbooks/latest-defi-range.json
```

It includes:

- testnet package ID
- published object IDs
- attack transaction digests
- monitor checkpoint state
- detected alert count
- expected rule coverage
