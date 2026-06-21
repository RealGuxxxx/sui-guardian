# Overflow Demo Runbook

This is the recommended judging demo for Sui Guardian. It uses a real Sui testnet deployment, not static fixture data.

## What It Shows

- A vulnerable Sui DeFi protocol is published to testnet.
- The protocol exposes four realistic risk surfaces: emergency withdraw, admin takeover, admin drain, and oracle manipulation.
- Sui Guardian generates a project-specific monitoring config for the deployed package and shared objects.
- The monitor detects unauthorized function calls, failed exploit probes, object field changes, vault balance drops, and incident timelines.
- The dashboard exposes an Overflow readiness score and operator response workflow.

## Prerequisites

- `sui` CLI installed.
- Active Sui environment is `testnet`.
- At least two Sui addresses in the local keystore.
- Admin address has enough testnet SUI to publish and seed the range.
- Dependencies installed with `npm install`.

Check the Sui environment:

```bash
sui client active-env
sui client active-address
sui client addresses
```

## Run The Demo

```bash
npm run demo:overflow
```

The script will:

- publish `contracts/defi-range`;
- seed SUI into the lending pool, admin vault, and price bank;
- generate `config/generated-defi-range.yml`;
- build and start Sui Guardian on a free local port;
- run the staged attacker flow;
- wait for expected alerts;
- write `runbooks/latest-defi-range.json`.

By default the monitor remains running so the dashboard can be opened during a live demo. To stop it automatically:

```bash
npm run demo:overflow -- --stop-monitor-at-end
```

## Demo Talk Track

1. Open the printed dashboard URL.
2. Show the Overflow readiness panel and explain that the monitor is running against a live testnet deployment.
3. Show the config summary: package, function guards, tracked objects, object baselines, and price model.
4. Show the incident list: unauthorized oracle update, admin takeover, admin withdraw, emergency withdraw, and failed probe burst.
5. Open the behavior timeline and point out cross-rule correlation.
6. Acknowledge or resolve one alert to prove the response loop.
7. Open `runbooks/latest-defi-range.json` to show package ID, object IDs, transaction digests, and observed alerts.

## Expected Winning Narrative

Sui Guardian is not a generic chain monitor. It understands Sui-specific attack surfaces:

- package upgrade authority;
- shared object state;
- Move entry functions;
- object field baselines;
- PTB and multi-transaction attack behavior;
- protocol-specific rule generation.

For Overflow, pitch it as a DeFi & Payments safety layer with an Agentic Web extension: AI helps projects turn Move source and deployment metadata into live monitoring rules.

## Troubleshooting

- If the script says the active env is not testnet, run `sui client switch --env testnet`.
- If the attacker has no gas, the script tries to fund it from the admin address.
- If the monitor takes time to alert, wait for GraphQL indexing. The monitor uses checkpoint overlap to handle short indexing delays.
- If publish fails because the active address has no gas, request testnet SUI for the admin address and rerun.
