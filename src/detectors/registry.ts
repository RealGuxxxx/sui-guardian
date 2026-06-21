import { detectUnknownCoordinatedAttack } from './anomaly/unknown-attack-detector.js';
import { detectClmmExtremeTickAttacks } from './known/clmm-extreme-tick-attack-detector.js';
import { detectUpgradeCapMisuseAttacks } from './known/upgrade-cap-misuse-detector.js';
import { detectSpoofTokenPoolInjectionAttacks } from './known/spoof-token-pool-injection-detector.js';
import { detectBridgeBurstDrainAttacks } from './known/bridge-burst-drain-detector.js';
import { detectPtbBreadthAttacks } from './known/ptb-breadth-attack-detector.js';
import { detectRugPullAttacks } from './known/rug-pull-detector.js';
import { detectMultiHopLaunderingAttacks } from './known/multi-hop-laundering-detector.js';
import { detectApprovalProbeThenReuseAttacks } from './known/approval-probe-then-reuse-detector.js';
import { detectApprovalDrainAttacks } from './known/approval-drain-detector.js';
import { detectAttackerProfitRealizationAttacks } from './known/attacker-profit-realization-detector.js';
import { detectArbitraryExternalCallAttacks } from './known/arbitrary-external-call-detector.js';
import { detectBridgeDrainAfterClaimAttacks } from './known/bridge-drain-after-claim-detector.js';
import { detectBridgeMessageValidationAttacks } from './known/bridge-message-validation-detector.js';
import { detectBridgeProofProbeThenReplayAttacks } from './known/bridge-proof-probe-then-replay-detector.js';
import { detectBridgeProofReplayDrainAttacks } from './known/bridge-proof-replay-drain-detector.js';
import { detectBridgeRouterDrainChainAttacks } from './known/bridge-router-drain-chain-detector.js';
import { detectCollateralParameterFlipAttacks } from './known/collateral-parameter-flip-detector.js';
import { detectCrossMarketManipulationAttacks } from './known/cross-market-manipulation-detector.js';
import { detectDrainAfterTakeoverAttacks } from './known/drain-after-takeover-detector.js';
import { detectExecutionAbuseAttacks } from './known/execution-abuse-detector.js';
import { detectFeeRecipientHijackAttacks } from './known/fee-recipient-hijack-detector.js';
import { detectGovernanceDelayCollapseAttacks } from './known/governance-delay-collapse-detector.js';
import { detectFlashLoanSequenceAttacks } from './known/flash-loan-sequence-detector.js';
import { detectGovernanceProposalHijackAttacks } from './known/governance-proposal-hijack-detector.js';
import { detectGovernanceFlashLoanVoteAttacks } from './known/governance-flash-loan-vote-detector.js';
import { detectGovernanceQuorumCollapseAttacks } from './known/governance-quorum-collapse-detector.js';
import { detectGovernanceExecutionAfterVoteSurgeAttacks } from './known/governance-execution-after-vote-surge-detector.js';
import { detectGovernanceEmergencyBrakeDisableAttacks } from './known/governance-emergency-brake-disable-detector.js';
import { detectGovernanceParameterPoisoningAttacks } from './known/governance-parameter-poisoning-detector.js';
import { detectGovernanceTimelockBypassAttacks } from './known/governance-timelock-bypass-detector.js';
import { detectGovernanceVetoDisableAttacks } from './known/governance-veto-disable-detector.js';
import { detectGovernanceVoteConcentrationAttacks } from './known/governance-vote-concentration-detector.js';
import { detectFlashLoanRepayMismatchAttacks } from './known/flash-loan-repay-mismatch-detector.js';
import { detectLiquidationManipulationAttacks } from './known/liquidation-manipulation-detector.js';
import { detectLiquidityCapReleaseThenDrainAttacks } from './known/liquidity-cap-release-then-drain-detector.js';
import { detectMaintenanceWindowBypassAttacks } from './known/maintenance-window-bypass-detector.js';
import { detectMultiAssetDrainAttacks } from './known/multi-asset-drain-detector.js';
import { detectOracleStalenessExploitationAttacks } from './known/oracle-staleness-exploitation-detector.js';
import { detectOracleAdminRotationThenBorrowAttacks } from './known/oracle-admin-rotation-then-borrow-detector.js';
import { detectOracleAnchorHeartbeatCollapseAttacks } from './known/oracle-anchor-heartbeat-collapse-detector.js';
import { detectOracleAnchorDeviationThresholdCollapseAttacks } from './known/oracle-anchor-deviation-threshold-collapse-detector.js';
import { detectOracleAnchorDecimalsMismatchAttacks } from './known/oracle-anchor-decimals-mismatch-detector.js';
import { detectOracleAnchorOverrideThenBorrowAttacks } from './known/oracle-anchor-override-then-borrow-detector.js';
import { detectOracleAnchorRoundResetAttacks } from './known/oracle-anchor-round-reset-detector.js';
import { detectOracleAnchorStalenessBypassAttacks } from './known/oracle-anchor-staleness-bypass-detector.js';
import { detectOracleFallbackFreezeThenLiquidateAttacks } from './known/oracle-fallback-freeze-then-liquidate-detector.js';
import { detectOracleFallbackDecimalsMismatchAttacks } from './known/oracle-fallback-decimals-mismatch-detector.js';
import { detectOracleFallbackSourceOverrideAttacks } from './known/oracle-fallback-source-override-detector.js';
import { detectOracleAnswerDecimalsFlipAttacks } from './known/oracle-answer-decimals-flip-detector.js';
import { detectOracleHeartbeatDisableThenBorrowAttacks } from './known/oracle-heartbeat-disable-then-borrow-detector.js';
import { detectOracleHeartbeatThresholdCollapseAttacks } from './known/oracle-heartbeat-threshold-collapse-detector.js';
import { detectOracleMinUpdateIntervalBypassAttacks } from './known/oracle-min-update-interval-bypass-detector.js';
import { detectOracleObservationDelayBypassAttacks } from './known/oracle-observation-delay-bypass-detector.js';
import { detectOracleObservationCardinalityDropAttacks } from './known/oracle-observation-cardinality-drop-detector.js';
import { detectOraclePrimarySourceDisableAttacks } from './known/oracle-primary-source-disable-detector.js';
import { detectOracleRoundIdResetAttacks } from './known/oracle-round-id-reset-detector.js';
import { detectOracleSequencerGracePeriodCollapseAttacks } from './known/oracle-sequencer-grace-period-collapse-detector.js';
import { detectOracleSequencerGateDisableAttacks } from './known/oracle-sequencer-gate-disable-detector.js';
import { detectOracleSequencerHeartbeatCollapseAttacks } from './known/oracle-sequencer-heartbeat-collapse-detector.js';
import { detectOracleSequencerRoundResetAttacks } from './known/oracle-sequencer-round-reset-detector.js';
import { detectOracleSequencerStatusInversionAttacks } from './known/oracle-sequencer-status-inversion-detector.js';
import { detectOracleSequencerUptimeFeedOverrideAttacks } from './known/oracle-sequencer-uptime-feed-override-detector.js';
import { detectOracleUpdaterQuorumCollapseAttacks } from './known/oracle-updater-quorum-collapse-detector.js';
import { detectOraclePoisoningAttacks } from './known/oracle-poisoning-detector.js';
import { detectOracleDeviationThresholdCollapseAttacks } from './known/oracle-deviation-threshold-collapse-detector.js';
import { detectOraclePriceBandDisableAttacks } from './known/oracle-price-band-disable-detector.js';
import { detectOracleRecencyBypassThenLiquidateAttacks } from './known/oracle-recency-bypass-then-liquidate-detector.js';
import { detectOracleTwapWindowCollapseAttacks } from './known/oracle-twap-window-collapse-detector.js';
import { detectOracleSignerSetRotationAttacks } from './known/oracle-signer-set-rotation-detector.js';
import { detectPermissionAttacks } from './known/permission-detector.js';
import { detectPrivilegedConfigFlipAttacks } from './known/privileged-config-flip-detector.js';
import { detectLiquidityDrainAttacks } from './known/liquidity-drain-detector.js';
import { detectPriceManipulationAttacks } from './known/price-manipulation-detector.js';
import { detectPrivilegedRoleExpansionAttacks } from './known/privileged-role-expansion-detector.js';
import { detectReentryLikeRepeatExtractionAttacks } from './known/reentry-like-repeat-extraction-detector.js';
import { detectRiskLimitBypassAttacks } from './known/risk-limit-bypass-detector.js';
import { detectRouterApprovalReuseAttacks } from './known/router-approval-reuse-detector.js';
import { detectRouterFeeSkimChainAttacks } from './known/router-fee-skim-chain-detector.js';
import { detectRouterRecipientFlipAttacks } from './known/router-recipient-flip-detector.js';
import { detectSequencedProbeThenExploitAttacks } from './known/sequenced-probe-then-exploit-detector.js';
import { detectSlippageAbuseAttacks } from './known/slippage-abuse-detector.js';
import { detectSuspiciousRouterHopAttacks } from './known/suspicious-router-hop-detector.js';
import { detectTimelockConfigDisableAttacks } from './known/timelock-config-disable-detector.js';
import { detectTreasurySkimSequenceAttacks } from './known/treasury-skim-sequence-detector.js';
import { detectRepeatAttacker } from './known/repeat-attacker-detector.js';
import { detectPerpetualsFeeParameterAbuseAttacks } from './known/perpetuals-fee-parameter-abuse-detector.js';
import { detectMultiVaultRapidDrainAttacks } from './known/multi-vault-rapid-drain-detector.js';
import { detectSandwichAttacks } from './known/sandwich-attack-detector.js';
import { detectKioskPolicyBypassAttacks } from './known/kiosk-policy-bypass-detector.js';
import { detectCoinMetadataSpoofingAttacks } from './known/coin-metadata-spoofing-detector.js';
import { detectDeepBookManipulationAttacks } from './known/deepbook-manipulation-detector.js';
import { detectDynamicFieldAbuseAttacks } from './known/dynamic-field-abuse-detector.js';
import { detectClockManipulationAttacks } from './known/clock-manipulation-detector.js';
import type { AttackDetectorContext, AttackFinding } from './types.js';

export function runAttackDetectors(ctx: AttackDetectorContext): AttackFinding[] {
  const findings = [
    ...detectApprovalProbeThenReuseAttacks(ctx),
    ...detectApprovalDrainAttacks(ctx),
    ...detectPermissionAttacks(ctx),
    ...detectPrivilegedConfigFlipAttacks(ctx),
    ...detectPrivilegedRoleExpansionAttacks(ctx),
    ...detectGovernanceProposalHijackAttacks(ctx),
    ...detectGovernanceFlashLoanVoteAttacks(ctx),
    ...detectGovernanceExecutionAfterVoteSurgeAttacks(ctx),
    ...detectGovernanceEmergencyBrakeDisableAttacks(ctx),
    ...detectGovernanceParameterPoisoningAttacks(ctx),
    ...detectGovernanceDelayCollapseAttacks(ctx),
    ...detectGovernanceQuorumCollapseAttacks(ctx),
    ...detectGovernanceTimelockBypassAttacks(ctx),
    ...detectGovernanceVetoDisableAttacks(ctx),
    ...detectTimelockConfigDisableAttacks(ctx),
    ...detectGovernanceVoteConcentrationAttacks(ctx),
    ...detectMaintenanceWindowBypassAttacks(ctx),
    ...detectOracleAdminRotationThenBorrowAttacks(ctx),
    ...detectOracleAnswerDecimalsFlipAttacks(ctx),
    ...detectOracleAnchorHeartbeatCollapseAttacks(ctx),
    ...detectOracleAnchorDeviationThresholdCollapseAttacks(ctx),
    ...detectOracleAnchorDecimalsMismatchAttacks(ctx),
    ...detectOracleAnchorOverrideThenBorrowAttacks(ctx),
    ...detectOracleAnchorRoundResetAttacks(ctx),
    ...detectOracleAnchorStalenessBypassAttacks(ctx),
    ...detectOracleFallbackDecimalsMismatchAttacks(ctx),
    ...detectOracleFallbackFreezeThenLiquidateAttacks(ctx),
    ...detectOracleFallbackSourceOverrideAttacks(ctx),
    ...detectOraclePoisoningAttacks(ctx),
    ...detectOraclePrimarySourceDisableAttacks(ctx),
    ...detectOracleRoundIdResetAttacks(ctx),
    ...detectOracleSequencerGracePeriodCollapseAttacks(ctx),
    ...detectOracleSequencerGateDisableAttacks(ctx),
    ...detectOracleSequencerHeartbeatCollapseAttacks(ctx),
    ...detectOracleSequencerRoundResetAttacks(ctx),
    ...detectOracleSequencerStatusInversionAttacks(ctx),
    ...detectOracleSequencerUptimeFeedOverrideAttacks(ctx),
    ...detectOracleSignerSetRotationAttacks(ctx),
    ...detectOracleUpdaterQuorumCollapseAttacks(ctx),
    ...detectOracleHeartbeatDisableThenBorrowAttacks(ctx),
    ...detectOracleHeartbeatThresholdCollapseAttacks(ctx),
    ...detectOracleMinUpdateIntervalBypassAttacks(ctx),
    ...detectOracleObservationDelayBypassAttacks(ctx),
    ...detectOracleObservationCardinalityDropAttacks(ctx),
    ...detectOracleTwapWindowCollapseAttacks(ctx),
    ...detectOracleStalenessExploitationAttacks(ctx),
    ...detectOracleDeviationThresholdCollapseAttacks(ctx),
    ...detectOraclePriceBandDisableAttacks(ctx),
    ...detectOracleRecencyBypassThenLiquidateAttacks(ctx),
    ...detectPriceManipulationAttacks(ctx),
    ...detectCollateralParameterFlipAttacks(ctx),
    ...detectRiskLimitBypassAttacks(ctx),
    ...detectCrossMarketManipulationAttacks(ctx),
    ...detectSlippageAbuseAttacks(ctx),
    ...detectSandwichAttacks(ctx),
    ...detectKioskPolicyBypassAttacks(ctx),
    ...detectCoinMetadataSpoofingAttacks(ctx),
    ...detectDeepBookManipulationAttacks(ctx),
    ...detectLiquidationManipulationAttacks(ctx),
    ...detectLiquidityCapReleaseThenDrainAttacks(ctx),
    ...detectLiquidityDrainAttacks(ctx),
    ...detectFeeRecipientHijackAttacks(ctx),
    ...detectMultiAssetDrainAttacks(ctx),
    ...detectAttackerProfitRealizationAttacks(ctx),
    ...detectFlashLoanRepayMismatchAttacks(ctx),
    ...detectBridgeDrainAfterClaimAttacks(ctx),
    ...detectBridgeProofProbeThenReplayAttacks(ctx),
    ...detectBridgeProofReplayDrainAttacks(ctx),
    ...detectBridgeRouterDrainChainAttacks(ctx),
    ...detectDrainAfterTakeoverAttacks(ctx),
    ...detectBridgeMessageValidationAttacks(ctx),
    ...detectArbitraryExternalCallAttacks(ctx),
    ...detectExecutionAbuseAttacks(ctx),
    ...detectReentryLikeRepeatExtractionAttacks(ctx),
    ...detectRouterApprovalReuseAttacks(ctx),
    ...detectRouterFeeSkimChainAttacks(ctx),
    ...detectRouterRecipientFlipAttacks(ctx),
    ...detectSequencedProbeThenExploitAttacks(ctx),
    ...detectSuspiciousRouterHopAttacks(ctx),
    ...detectTreasurySkimSequenceAttacks(ctx),
    ...detectFlashLoanSequenceAttacks(ctx),
    ...detectRugPullAttacks(ctx),
    ...detectMultiHopLaunderingAttacks(ctx),
    ...detectClmmExtremeTickAttacks(ctx),
    ...detectPtbBreadthAttacks(ctx),
    ...detectUpgradeCapMisuseAttacks(ctx),
    ...detectSpoofTokenPoolInjectionAttacks(ctx),
    ...detectBridgeBurstDrainAttacks(ctx),
    ...detectPerpetualsFeeParameterAbuseAttacks(ctx),
    ...detectMultiVaultRapidDrainAttacks(ctx),
    ...detectDynamicFieldAbuseAttacks(ctx),
    ...detectClockManipulationAttacks(ctx),
    ...detectRepeatAttacker(ctx),
    ...detectUnknownCoordinatedAttack(ctx),
  ];

  if (findings.length === 0) {
    return [
      {
        attackType: 'no-actionable-attack',
        category: 'unknown',
        summary: 'No actionable attack pattern detected',
        evidence: {
          evidenceSummary: ctx.derived.evidenceSummary ?? [],
        },
        riskHints: {
          severityFloor: 'info',
        },
      },
    ];
  }

  return findings;
}
