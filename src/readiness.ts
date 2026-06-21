import type { AppConfig, RuntimeState, SubmissionReadiness, SubmissionReadinessCheck } from './types.js';
import { nowIso } from './utils.js';

const HANDBOOK_URL = 'https://mystenlabs.notion.site/overflow-2026-handbook';

export function buildSubmissionReadiness(config: AppConfig, state: RuntimeState): SubmissionReadiness {
  const projectCount = config.projects.length;
  const packageCount = sumProjects(config, (project) => project.packages.length);
  const protectedAddressCount = sumProjects(config, (project) => project.protectedAddresses.length);
  const functionGuardCount = sumProjects(config, (project) => project.functionGuards.length);
  const trafficRuleCount = sumProjects(config, (project) => project.trafficSpikes.length);
  const failureRuleCount = sumProjects(config, (project) => project.failureSpikes.length);
  const objectRuleCount = sumProjects(config, (project) => project.trackedObjects.length + project.objectBaselines.length + project.priceModels.length);
  const deprecatedPackageCount = sumProjects(config, (project) =>
    project.packages.reduce((sum, pkg) => sum + (pkg.deprecatedAddresses?.length ?? 0), 0),
  );
  const successfulScans = state.scanHistory.filter((scan) => scan.success);
  const lastSuccessfulScan = successfulScans[0];
  const mainnetConfigured = isMainnetConfigured(config);
  const aiRules = config.aiRules;

  const checks: SubmissionReadinessCheck[] = [
    {
      id: 'track-fit',
      label: 'Track fit',
      status: 'pass',
      required: true,
      evidence: 'Sui Guardian is positioned for DeFi & Payments, with AI-generated monitoring rules as an Agentic Web extension.',
      action: 'Keep the submission focused on DeFi protocol loss prevention and incident response.',
    },
    {
      id: 'real-project-config',
      label: 'Real project configuration',
      status: projectCount > 0 ? 'pass' : 'fail',
      required: true,
      evidence: projectCount > 0 ? `${projectCount} monitored project(s) configured.` : 'No monitored project is configured in the active config.',
      action: 'Add at least one real Sui protocol package, protected address, and admin sender to the active config.',
    },
    {
      id: 'core-detection-coverage',
      label: 'Core detection coverage',
      status: coverageStatus(packageCount, protectedAddressCount, functionGuardCount, trafficRuleCount + failureRuleCount + objectRuleCount),
      required: true,
      evidence: `${packageCount} package(s), ${protectedAddressCount} protected address(es), ${functionGuardCount} function guard(s), ${trafficRuleCount + failureRuleCount + objectRuleCount} behavior/object rule(s).`,
      action: 'Cover package upgrades, treasury/vault outflows, privileged functions, and burst/failure/object anomalies.',
    },
    {
      id: 'mainnet-path',
      label: 'Mainnet deployment path',
      status: mainnetConfigured ? 'pass' : 'warn',
      required: true,
      evidence: mainnetConfigured
        ? `Configured for ${config.network.name} via ${config.network.graphqlEndpoint}.`
        : `Current network is ${config.network.name}; endpoint is ${config.network.graphqlEndpoint}.`,
      action: 'Run the final demo against Sui mainnet, or clearly mark testnet-only evidence in the submission.',
    },
    {
      id: 'live-chain-evidence',
      label: 'Live chain evidence',
      status: lastSuccessfulScan && state.lastCheckpoint > 0 ? 'pass' : projectCount > 0 ? 'warn' : 'fail',
      required: true,
      evidence: lastSuccessfulScan
        ? `Last successful scan processed checkpoint ${lastSuccessfulScan.latestCheckpoint} with ${lastSuccessfulScan.transactionsProcessed} transaction(s).`
        : 'No successful scan has been recorded yet.',
      action: 'Run a successful scan before recording the submission demo.',
    },
    {
      id: 'incident-response-loop',
      label: 'Incident response loop',
      status: 'pass',
      required: true,
      evidence: 'Dashboard and API support incident aggregation, open/acknowledged/resolved states, scan history, and remediation notes.',
      action: 'In the demo, show one alert being acknowledged or resolved to prove the operator workflow.',
    },
    {
      id: 'notification-channel',
      label: 'Notification channel',
      status: config.alerts.webhookUrl ? 'pass' : 'warn',
      required: false,
      evidence: config.alerts.webhookUrl ? 'Webhook dispatch is configured.' : 'Webhook dispatch is not configured.',
      action: 'Configure Slack, Discord, or a generic incident webhook for the live demo.',
    },
    {
      id: 'ai-rule-generation',
      label: 'AI rule generation',
      status: aiRules?.enabled || aiRules?.generator.enabled ? 'pass' : 'warn',
      required: false,
      evidence: aiRules?.enabled
        ? `AI rules hot reload is enabled from ${aiRules.generatedDir}.`
        : 'AI rule generation exists, but hot reload is disabled in the active config.',
      action: 'Use the AI analysis panel or generated rules flow in the demo if pitching the Agentic Web angle.',
    },
    {
      id: 'known-exploit-hardening',
      label: 'Known exploit hardening',
      status: deprecatedPackageCount > 0 ? 'pass' : 'warn',
      required: false,
      evidence: deprecatedPackageCount > 0
        ? `${deprecatedPackageCount} deprecated package address(es) are watched.`
        : 'No deprecated package addresses are configured.',
      action: 'Add deprecated package addresses for protocols with retired vulnerable versions.',
    },
  ];

  const score = computeScore(checks);
  const requiredFailures = checks.filter((check) => check.required && check.status === 'fail');
  const status = requiredFailures.length > 0 ? 'blocked' : score >= 80 ? 'ready' : 'needs-work';

  return {
    generatedAt: nowIso(),
    targetTrack: 'DeFi & Payments',
    secondaryTrack: 'Agentic Web',
    handbookUrl: HANDBOOK_URL,
    score,
    status,
    summary: readinessSummary(status, score, requiredFailures.length),
    checks,
    criticalGaps: checks
      .filter((check) => check.status === 'fail' || (check.required && check.status === 'warn'))
      .map((check) => check.action),
    submissionAssets: [
      {
        label: 'README',
        path: 'README.md',
        purpose: 'Project positioning, local run commands, API overview, and demo flow.',
      },
      {
        label: 'Overflow submission guide',
        path: 'docs/overflow-submission.md',
        purpose: 'Hackathon track fit, judging narrative, demo script, and final checklist.',
      },
      {
        label: 'Architecture',
        path: 'docs/architecture.md',
        purpose: 'System design, data flow, rule engine, and production roadmap.',
      },
      {
        label: 'Production config template',
        path: 'config/projects.example.yml',
        purpose: 'Mainnet-ready project configuration template.',
      },
    ],
  };
}

function sumProjects(config: AppConfig, count: (project: AppConfig['projects'][number]) => number): number {
  return config.projects.reduce((sum, project) => sum + count(project), 0);
}

function isMainnetConfigured(config: AppConfig): boolean {
  return config.network.name.toLowerCase().includes('mainnet') ||
    config.network.graphqlEndpoint.toLowerCase().includes('mainnet');
}

function coverageStatus(
  packageCount: number,
  protectedAddressCount: number,
  functionGuardCount: number,
  advancedRuleCount: number,
): SubmissionReadinessCheck['status'] {
  if (packageCount > 0 && protectedAddressCount > 0 && functionGuardCount > 0 && advancedRuleCount > 0) {
    return 'pass';
  }
  if (packageCount > 0 && (protectedAddressCount > 0 || functionGuardCount > 0 || advancedRuleCount > 0)) {
    return 'warn';
  }
  return 'fail';
}

function computeScore(checks: SubmissionReadinessCheck[]): number {
  const totalWeight = checks.reduce((sum, check) => sum + (check.required ? 2 : 1), 0);
  const actual = checks.reduce((sum, check) => {
    const weight = check.required ? 2 : 1;
    if (check.status === 'pass') return sum + weight;
    if (check.status === 'warn') return sum + weight * 0.5;
    return sum;
  }, 0);
  return Math.round((actual / totalWeight) * 100);
}

function readinessSummary(status: SubmissionReadiness['status'], score: number, requiredFailureCount: number): string {
  if (status === 'ready') {
    return `Submission-ready baseline reached (${score}/100). Focus the demo on real-time DeFi monitoring and response.`;
  }
  if (status === 'blocked') {
    return `Blocked by ${requiredFailureCount} required item(s) (${score}/100). Configure real monitoring targets before submission.`;
  }
  return `Needs a final pass before submission (${score}/100). Address required warnings and capture live chain evidence.`;
}
