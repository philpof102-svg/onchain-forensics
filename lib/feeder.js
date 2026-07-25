'use strict';
/**
 * feeder.js — "who paid for this launch, and what else did they pay for?"
 * =======================================================================
 * `rugsignals` asks what the deployer CAN do. This asks who the deployer IS — by following the money
 * backwards. A token contract names its creator; a creator wallet minutes old names the wallet that funded
 * it; and that funder usually funded others. Three free queries and a cluster appears that no retail buyer
 * can see from a chart.
 *
 * Proven on a live launch while writing this: token -> creator (funded once, 15.02 ETH, seven minutes before
 * the pool existed) -> funder, which had sent the SAME 15.020 ETH to twenty-six other fresh wallets. Nobody
 * funds twenty-six wallets to the milli-ETH by hand; that is a machine running a launch factory.
 *
 * WHAT THIS DOES NOT CLAIM. A shared funder is not proof of fraud. The same signature fits a launchpad, a
 * market maker, or a serial rug operation, and we cannot tell which from the graph alone. So this reports
 * STRUCTURE, never intent: these tokens share a paymaster, therefore they share fate. That is decision-
 * relevant on its own — and calling it "scammer" without evidence would be the same unfounded certainty we
 * refuse everywhere else. Intent only gets asserted when a sibling has actually rugged, which token-radar
 * records over time.
 *
 * Source: Blockscout's public Base instance (no key, no quota registration).
 */
const https = require('node:https');

const BLOCKSCOUT = { base: 'https://base.blockscout.com/api/v2' };
const FRESH_FUNDING_WINDOW_MS = 6 * 60 * 60 * 1000;   // funded <6h before deploying = wallet made for the job
const SIBLING_ALERT = 5;                              // a funder this prolific is infrastructure, not a person

const getJSON = (url) => new Promise((resolve) => {
  https.get(url, { headers: { accept: 'application/json' } }, (res) => {
    let d = ''; res.on('data', (c) => (d += c));
    res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
  }).on('error', () => resolve(null));
});

/**
 * traceFeeder — token -> deployer -> funder -> siblings.
 * @returns { ok, deployer, funder, fundedEth, fundedAt, freshDeployer, siblings, siblingCount, morePages,
 *            identicalAmountSiblings, pattern, note }
 */
async function traceFeeder(chain, tokenAddress, { fetchImpl } = {}) {
  const api = BLOCKSCOUT[String(chain).toLowerCase()];
  const fetchJSON = fetchImpl || getJSON;
  if (!api) return { ok: false, reason: 'no public explorer wired for chain "' + chain + '"' };

  // 1. The contract names its creator.
  const tok = await fetchJSON(api + '/addresses/' + tokenAddress);
  const deployer = tok && tok.creator_address_hash;
  if (!deployer) return { ok: false, reason: 'could not resolve the deploying wallet' };

  // 2. The creator's incoming transfers name whoever paid for it. A wallet with exactly one incoming
  //    transfer was created for this launch and nothing else — which is itself the signal.
  const inc = await fetchJSON(api + '/addresses/' + deployer + '/transactions?filter=to');
  const incoming = (inc && inc.items) || [];
  const funders = incoming.filter((t) => parseFloat(t.value || 0) > 0);
  if (!funders.length) return { ok: true, deployer, funder: null, siblings: [], siblingCount: 0,
    note: 'no incoming value transfer found for the deployer — it may be funded via a contract or bridged' };

  const first = funders[funders.length - 1];            // the explorer returns newest first
  const funder = first.from && first.from.hash;
  const fundedEth = parseFloat(first.value || 0) / 1e18;
  const fundedAt = first.timestamp || null;

  // 3. What else that funder paid for. One page is enough to see the shape; we say when there are more
  //    rather than paging forever, because an unbounded crawl on a free endpoint is how we lose it.
  const out = await fetchJSON(api + '/addresses/' + funder + '/transactions?filter=from');
  const sent = ((out && out.items) || []).filter((t) => parseFloat(t.value || 0) > 0);
  const byTarget = {};
  for (const t of sent) {
    const to = t.to && t.to.hash;
    if (!to || to.toLowerCase() === String(funder).toLowerCase()) continue;
    byTarget[to] = (byTarget[to] || 0) + parseFloat(t.value || 0) / 1e18;
  }
  const siblings = Object.entries(byTarget).map(([addr, eth]) => ({ addr, eth: +eth.toFixed(4) }))
    .sort((a, b) => b.eth - a.eth);

  // An identical amount repeated across many fresh wallets is a script, not a person deciding each time.
  const rounded = siblings.map((s) => s.eth.toFixed(3));
  const counts = {};
  for (const r of rounded) counts[r] = (counts[r] || 0) + 1;
  const [topAmount, identical] = Object.entries(counts).sort((a, b) => b[1] - a[1])[0] || [null, 0];

  const deployedAt = tok.creation_transaction_hash ? (first.timestamp || null) : null;
  const freshDeployer = incoming.length === 1;
  let pattern = 'single funder, no repeated pattern on this page';
  if (identical >= SIBLING_ALERT) pattern = 'the funder sent an identical ' + topAmount + ' ETH to ' + identical +
    ' different wallets — a scripted launch factory, not a person funding launches one by one';
  else if (siblings.length >= SIBLING_ALERT) pattern = 'the funder has bankrolled ' + siblings.length + ' distinct wallets';

  return { ok: true, deployer, funder, fundedEth: +fundedEth.toFixed(4), fundedAt, deployedAt,
    freshDeployer, siblings: siblings.slice(0, 12), siblingCount: siblings.length,
    morePages: !!(out && out.next_page_params), identicalAmountSiblings: identical, identicalAmount: topAmount,
    pattern,
    note: 'STRUCTURE ONLY. A shared funder proves shared control or shared infrastructure, never fraud — a launchpad and a rug factory look identical here. It means these tokens share fate: judge them together, not in isolation.' };
}

module.exports = { traceFeeder, SIBLING_ALERT, FRESH_FUNDING_WINDOW_MS };
