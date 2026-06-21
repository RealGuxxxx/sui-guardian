# DeepBook Mainnet Read-Only Config

## Why DeepBook

DeepBook V3 is the best first real mainnet integration for this project because it is Sui-native, DeFi-critical, publicly documented, and deployed on mainnet with stable object IDs. It lets the submission show live-chain monitoring without implying control over a third-party protocol.

## Source Of Truth

Primary source:

- Sui DeepBookV3 contract information: `https://docs.sui.io/onchain-finance/deepbookv3/contract-information`

The config uses:

- Current DeepBook V3 Version 6 package ID.
- Registry ID.
- DEEP treasury object.
- DEEP/SUI, SUI/USDC, and DEEP/USDC pool IDs.
- Official DEEP, SUI, and USDC coin types.

I also verified the package and selected objects against Sui mainnet GraphQL before committing the config.

The pools are tracked as market objects, not configured as protected outflow addresses. That keeps normal high-frequency order activity from being treated as an incident context.

This config also disables generic attack heuristics for DeepBook's mainnet sample. DeepBook has legitimate high-volume PTBs, batch fee settlement, flashloan flows, and repeated order operations; the mainnet sample should prove read-only integration without paging on ordinary market activity. The reproducible testnet range keeps the full attack-detector demo enabled.

## Run It

One-shot scan:

```bash
npm run mainnet:deepbook:scan
```

Dashboard:

```bash
npm run build
npm run mainnet:deepbook
```

Open:

```text
http://127.0.0.1:3020/
```

Latest captured evidence:

```text
runbooks/latest-mainnet-deepbook.json
```

Optional webhook proof:

```bash
npm run webhook:sink
ALERT_WEBHOOK_URL=http://127.0.0.1:8787/webhook npm run mainnet:deepbook
```

## What This Proves

This proves Sui Guardian can ingest a real mainnet protocol configuration and scan live Sui mainnet checkpoints in read-only mode.

It does not prove that DeepBook is officially using this monitor. The production claim should remain:

> Sui Guardian can be configured against real Sui mainnet deployments using public package, object, and treasury metadata.

## Production Caveats

Before production paging, confirm these with the protocol team:

- Admin and governance sender allowlists.
- Expected upgrade senders.
- Normal pool outflow ranges for high-volume trading days.
- Maintenance windows for upgrades and parameter changes.
- Which previous package versions should be treated as compatible versus deprecated.
