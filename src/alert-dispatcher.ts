import type { Alert, IncidentAlert } from './types.js';
import { errorMessage, summarizeAlert } from './utils.js';
import { formatUsd } from './utils/usd-estimator.js';

const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = [1000, 3000, 8000] as const;

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff3b82',
  high: '#ff6b6b',
  medium: '#f7b955',
  low: '#5fa8ff',
  info: '#97a7c3',
};

/** Severity emoji for Discord/Slack messages */
const SEVERITY_EMOJI: Record<string, string> = {
  critical: '🚨',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

export class AlertDispatcher {
  constructor(
    private readonly consoleEnabled: boolean,
    private readonly webhookUrl?: string,
  ) {}

  async dispatch(alert: Alert): Promise<void> {
    if (this.consoleEnabled) {
      console.log(summarizeAlert(alert));
      console.log(JSON.stringify(alert.details, null, 2));
    }

    if (!this.webhookUrl) {
      return;
    }

    await this.deliverWithRetry(alert);
  }

  private async deliverWithRetry(alert: Alert): Promise<void> {
    const idempotencyKey = `${alert.projectId}:${alert.ruleId}:${alert.createdAt}`;

    // Detect webhook platform by URL and build platform-specific payload
    const webhookUrl = this.webhookUrl!;
    let payload: string;
    let contentType = 'application/json';

    if (webhookUrl.includes('hooks.slack.com') || webhookUrl.includes('slack.com/api/')) {
      payload = JSON.stringify(buildSlackPayload(alert, idempotencyKey));
    } else if (webhookUrl.includes('discord.com/api/webhooks') || webhookUrl.includes('discordapp.com/api/webhooks')) {
      payload = JSON.stringify(buildDiscordPayload(alert, idempotencyKey));
    } else {
      // Generic JSON webhook (original format)
      payload = JSON.stringify({
        text: summarizeAlert(alert),
        alert,
        idempotencyKey,
      });
    }

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const response = await fetch(webhookUrl, {
          method: 'POST',
          headers: {
            'content-type': contentType,
            'x-sui-guardian-idempotency-key': idempotencyKey,
          },
          body: payload,
        });

        if (response.ok) {
          return;
        }

        if (response.status >= 400 && response.status < 500) {
          console.error(`Webhook rejected alert (${response.status}) — not retrying: ${alert.ruleId}`);
          return;
        }

        console.warn(`Webhook delivery attempt ${attempt + 1}/${MAX_RETRIES} failed with ${response.status}, will retry`);
      } catch (error) {
        console.warn(`Webhook delivery attempt ${attempt + 1}/${MAX_RETRIES} errored: ${errorMessage(error)}`);
      }

      if (attempt < MAX_RETRIES - 1) {
        await sleep(RETRY_BACKOFF_MS[attempt] ?? 1000);
      }
    }

    console.error(`Webhook delivery permanently failed after ${MAX_RETRIES} attempts for alert: ${alert.ruleId} (id: ${alert.id})`);
  }
}

// ── Slack Block Kit payload ───────────────────────────────────────────────────

function buildSlackPayload(alert: Alert, idempotencyKey: string): object {
  const emoji = SEVERITY_EMOJI[alert.severity] ?? '⚠️';
  const color = SEVERITY_COLORS[alert.severity] ?? '#97a7c3';
  const details = alert.details as Record<string, unknown>;
  const sender = details['sender'] as string | undefined;
  const riskScore = details['riskScore'] as number | undefined;
  const estimatedUsd = details['estimatedUsd'] as number | undefined;
  const remediation = details['remediation'] as { immediateActions?: string[] } | undefined;
  const chainHints = details['chainHints'] as { stage?: string } | undefined;

  const contextParts: string[] = [];
  if (sender) contextParts.push(`*发送者:* \`${sender.slice(0, 12)}…\``);
  if (riskScore !== undefined) contextParts.push(`*风险分:* ${riskScore}/100`);
  if (estimatedUsd !== undefined) contextParts.push(`*估算损失:* ${formatUsd(estimatedUsd)}`);
  if (chainHints?.stage) contextParts.push(`*攻击阶段:* ${chainHints.stage}`);

  const topActions = (remediation?.immediateActions ?? []).slice(0, 3);

  const blocks: object[] = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `${emoji} ${alert.severity.toUpperCase()} — ${alert.projectName}` },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*${alert.ruleName}*\n${alert.summary}` },
    },
  ];

  if (contextParts.length > 0) {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: contextParts.join('  |  ') },
    });
  }

  if (topActions.length > 0) {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: `*应急响应:*\n${topActions.map((a, i) => `${i + 1}. ${a}`).join('\n')}` },
    });
  }

  blocks.push({
    type: 'context',
    elements: [
      { type: 'mrkdwn', text: `规则: \`${alert.ruleId}\`  |  告警 ID: \`${alert.id.slice(0, 8)}\`` },
    ],
  });

  return {
    attachments: [
      {
        color,
        blocks,
        footer: 'Sui Guardian',
        ts: Math.floor(new Date(alert.createdAt).getTime() / 1000).toString(),
      },
    ],
    metadata: { idempotencyKey },
  };
}

// ── Discord Embed payload ─────────────────────────────────────────────────────

function buildDiscordPayload(alert: Alert, idempotencyKey: string): object {
  const emoji = SEVERITY_EMOJI[alert.severity] ?? '⚠️';
  const colorHex = (SEVERITY_COLORS[alert.severity] ?? '#97a7c3').replace('#', '');
  const colorInt = parseInt(colorHex, 16);
  const details = alert.details as Record<string, unknown>;
  const sender = details['sender'] as string | undefined;
  const riskScore = details['riskScore'] as number | undefined;
  const estimatedUsd = details['estimatedUsd'] as number | undefined;
  const remediation = details['remediation'] as { threat?: string; immediateActions?: string[] } | undefined;
  const chainHints = details['chainHints'] as { stage?: string } | undefined;

  const fields: object[] = [];

  if (sender) {
    fields.push({ name: '发送者', value: `\`${sender.slice(0, 16)}…\``, inline: true });
  }
  if (riskScore !== undefined) {
    fields.push({ name: '风险评分', value: `${riskScore}/100`, inline: true });
  }
  if (estimatedUsd !== undefined) {
    fields.push({ name: '估算损失', value: formatUsd(estimatedUsd), inline: true });
  }
  if (chainHints?.stage) {
    fields.push({ name: '攻击阶段', value: chainHints.stage, inline: true });
  }

  const topActions = (remediation?.immediateActions ?? []).slice(0, 3);
  if (topActions.length > 0) {
    fields.push({
      name: '应急响应步骤',
      value: topActions.map((a, i) => `**${i + 1}.** ${a}`).join('\n'),
      inline: false,
    });
  }

  return {
    embeds: [
      {
        title: `${emoji} ${alert.severity.toUpperCase()} — ${alert.projectName}`,
        description: `**${alert.ruleName}**\n${alert.summary}`,
        color: colorInt,
        fields,
        footer: {
          text: `Sui Guardian  •  ${alert.ruleId}  •  ID: ${alert.id.slice(0, 8)}`,
        },
        timestamp: alert.createdAt,
      },
    ],
    // idempotency key in content for receivers that parse it
    username: 'Sui Guardian',
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
