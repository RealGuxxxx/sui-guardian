import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * DeepBook Order Book Manipulation Detector
 *
 * DeepBook is Sui's native central limit order book (CLOB) DEX.
 * v2/v3 are the primary versions used by aggregators (e.g., Aftermath router).
 *
 * Attack patterns:
 *
 * 1. **Wash Trading / Spoofing** — Mass order placement + rapid cancellation
 *    to create false price discovery signals and manipulate aggregator quotes.
 *    Signal: 5+ `place_limit_order` calls in one PTB.
 *
 * 2. **Quote Stuffing** — Flooding the book with tiny orders to exhaust
 *    on-chain compute for legitimate traders (griefing / DoS).
 *    Signal: 8+ order operations (place or cancel) in single PTB.
 *
 * 3. **Layering** — Place large orders on one side, trigger fills, cancel
 *    before your own orders can be matched. Creates artificial price pressure.
 *    Signal: large place_limit_order pureInputs (quantity) immediately followed
 *    by cancel_order in the same PTB.
 *
 * 4. **Flash Order Arbitrage Drain** — Use a flash loan + market order to
 *    drain DeepBook liquidity and profit from mis-priced orders.
 *    Signal: flash-like funding + market order in same PTB.
 */

const PLACE_ORDER_PATTERNS = [
  'place_limit_order',
  'place_market_order',
  'place_order',
  'inject_liquidity',
  'add_order',
];

const CANCEL_ORDER_PATTERNS = [
  'cancel_order',
  'cancel_all_orders',
  'withdraw_order',
  'remove_order',
];

const DEEPBOOK_MODULE_PATTERNS = [
  'deepbook',
  'clob',
  'order_book',
  'orderbook',
];

function isDeepBookCall(mod: string, fn: string): boolean {
  const modLower = mod.toLowerCase();
  return DEEPBOOK_MODULE_PATTERNS.some((p) => modLower.includes(p));
}

function isPlaceOrderCall(mod: string, fn: string): boolean {
  return isDeepBookCall(mod, fn) &&
    PLACE_ORDER_PATTERNS.some((p) => fn.toLowerCase().includes(p));
}

function isCancelOrderCall(mod: string, fn: string): boolean {
  return isDeepBookCall(mod, fn) &&
    CANCEL_ORDER_PATTERNS.some((p) => fn.toLowerCase().includes(p));
}

// Thresholds
const WASH_TRADE_THRESHOLD = 5;   // 5+ place orders → wash trading
const QUOTE_STUFF_THRESHOLD = 8;  // 8+ total order ops → quote stuffing

export function detectDeepBookManipulationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx, derived } = ctx;

  const placeOrderCalls = tx.calls.filter((c) => isPlaceOrderCall(c.module, c.function));
  const cancelOrderCalls = tx.calls.filter((c) => isCancelOrderCall(c.module, c.function));
  const totalOrderOps = placeOrderCalls.length + cancelOrderCalls.length;

  if (totalOrderOps === 0) return [];

  const isWashTrading = placeOrderCalls.length >= WASH_TRADE_THRESHOLD;
  const isQuoteStuffing = totalOrderOps >= QUOTE_STUFF_THRESHOLD;

  // Layering: has both place AND cancel in same PTB (suspicious unless very low counts)
  const isLayering =
    placeOrderCalls.length >= 2 && cancelOrderCalls.length >= 1 &&
    placeOrderCalls.length + cancelOrderCalls.length >= 5;

  // Flash order drain: flash-like funding + market order
  const hasMarketOrder = placeOrderCalls.some((c) => c.function.toLowerCase().includes('market'));
  const isFlashOrderDrain = derived.flashLikeFundingDetected === true && hasMarketOrder;

  if (!isWashTrading && !isQuoteStuffing && !isLayering && !isFlashOrderDrain) return [];

  const patternNames: string[] = [];
  if (isWashTrading) patternNames.push(`wash-trading (${placeOrderCalls.length} orders)`);
  if (isQuoteStuffing) patternNames.push(`quote-stuffing (${totalOrderOps} ops)`);
  if (isLayering) patternNames.push('layering');
  if (isFlashOrderDrain) patternNames.push('flash-order-drain');

  const highestRisk = isFlashOrderDrain || isQuoteStuffing;
  const scoreDelta = isFlashOrderDrain ? 40 : isQuoteStuffing ? 35 : isWashTrading ? 30 : 25;

  return [
    {
      attackType: 'deepbook-manipulation',
      category: 'price-manipulation',
      summary: `检测到 DeepBook 订单操控：${patternNames.join('、')}，${placeOrderCalls.length} 次下单 + ${cancelOrderCalls.length} 次撤单在同一 PTB 内`,
      evidence: {
        sender: tx.sender,
        placeOrderCount: placeOrderCalls.length,
        cancelOrderCount: cancelOrderCalls.length,
        totalOrderOps,
        isWashTrading,
        isQuoteStuffing,
        isLayering,
        isFlashOrderDrain,
        hasFlashFunding: derived.flashLikeFundingDetected,
        placeOrderFunctions: [...new Set(placeOrderCalls.map((c) => `${c.module}::${c.function}`))],
        patterns: patternNames,
      },
      riskHints: {
        scoreDelta,
        severityFloor: highestRisk ? 'high' : 'medium',
      },
      chainHints: {
        stage: isFlashOrderDrain ? 'extraction' : 'manipulation',
      },
    },
  ];
}
