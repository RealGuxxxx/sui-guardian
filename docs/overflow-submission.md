# Sui Overflow 2026 Submission Notes

## Track Positioning

Primary track: DeFi & Payments.

Secondary angle: Agentic Web, through AI-assisted rule generation from Move source code and live chain context.

Sui Guardian is a real-time security monitor for Sui DeFi teams. It watches protocol packages, treasuries, vaults, oracle objects, admin functions, suspicious callers, and known exploit patterns, then turns raw rule hits into incident workflows that an operator can acknowledge, resolve, and route to webhook channels.

## Handbook Alignment

Source: <https://mystenlabs.notion.site/overflow-2026-handbook>

The handbook frames Overflow around meaningful products, real-world applications, and long-term ecosystem growth. This project should therefore be submitted as a working product for protocol teams, not as a standalone detection script.

Relevant 2026 dates from the handbook:
- May 7: official launch.
- May 7 to June 21: building period.
- June 21: submission deadline.
- July 8: shortlisted teams announcement.
- July 20 to July 21: Demo Day.
- August 27: winners announcement.

Prize distribution note: the handbook states that 50% is paid on winner announcement and 50% after successful mainnet deployment, unless the winning team has already deployed to mainnet by the announcement.

## Demo Script

Recommended judging flow:

```bash
npm run demo:overflow
```

Then:

1. Open the printed dashboard URL.
2. Show the Overflow readiness panel.
3. Show scan history, checkpoint progress, monitored packages, object baselines, and price model.
4. Show the staged attack alerts: oracle manipulation, admin takeover, admin drain, emergency withdraw, and failed probe burst.
5. Show one alert including severity, evidence, risk score, and remediation.
6. Acknowledge or resolve the alert to demonstrate the response loop.
7. Open `runbooks/latest-defi-range.json` to show package ID, object IDs, transaction digests, and alert evidence.
8. Open the AI analysis panel, upload or paste Move code, and show generated monitoring rules.
9. Apply generated rules to create a dynamic monitored project.

Optional notification proof:

```bash
npm run webhook:sink
ALERT_WEBHOOK_URL=http://127.0.0.1:8787/webhook npm run demo:overflow
```

This writes delivered webhook payloads to `.data/webhook-events.jsonl`.

## Submission Checklist

- Register and submit through the official Overflow flow.
- Include this repository and a short product demo video.
- Use `README.md` as the quick-start document.
- Use `docs/architecture.md` to explain system design and production path.
- Use `docs/judge-quickstart.md` for the shortest judge-facing flow.
- Use `docs/mainnet-onboarding.md` to explain the read-only mainnet onboarding path.
- Use `docs/deepbook-mainnet-config.md` and `config/mainnet.deepbook.yml` as the real mainnet read-only integration evidence.
- Use `runbooks/latest-mainnet-deepbook.json` as the latest captured DeepBook mainnet scan evidence.
- Use `config/projects.example.yml` to show the mainnet-ready configuration surface.
- Use `runbooks/overflow-demo.md` as the live judging runbook.
- Run `npm run typecheck` and `npm run test` before final submission.
- Capture at least one successful scan in the dashboard before recording the final demo.

## Current Product Claims

- Real Sui GraphQL checkpoint scanning with checkpoint overlap and scan history.
- Configurable package upgrade, protected address, function guard, traffic spike, failure spike, object baseline, price deviation, and fund-flow detectors.
- Incident aggregation with status lifecycle and remediation metadata.
- Slack, Discord, and generic webhook dispatch.
- AI-assisted rule generation and hot-loaded generated rules.
- Overflow readiness API at `GET /api/readiness`.

## Claim Boundary

The testnet DeFi range is reproducible judging evidence. Production claims should be framed as read-only mainnet readiness until a real protocol config has verified package IDs, protected addresses, admin allowlists, and webhook routing.
