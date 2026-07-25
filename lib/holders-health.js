'use strict';
/**
 * holders-health.js — MEME vet layer 2: on-chain holder distribution health
 * ========================================================================
 * Checks if a meme token has healthy holder distribution (not a rug/pump scheme).
 * Uses Base RPC eth_getLogs to analyze Transfer events and compute:
 *   - Top 10 holders concentration (% of supply)
 *   - Holder count (unique addresses that received tokens)
 *   - Rug risk score (0-100, lower = healthier)
 *
 * Pure + dependency-free: injectable fetch for testing.
 * Complements canonical verification (layer 1) and deployer trust (layer 3).
 */


// Common meme token ABIs (minimal ERC-20)
const ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const DEFAULT_RPC = 'https://mainnet.base.org';
const DEFAULT_BLOCK_RANGE = 10000; // ~33k blocks ≈ 4.5 days on Base

/**
 * Fetch transfer events for a token contract
 */
async function fetchTransfers(tokenAddress, { fromBlock, toBlock, rpcUrl = DEFAULT_RPC, fetchImpl } = {}) {
  const f = fetchImpl || fetch;
  const rpc = async (method, params) => {
    const r = await f(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(10000)
    });
    if (!r.ok) throw new Error(`rpc ${method} HTTP ${r.status}`);
    const j = await r.json();
    if (j.error) throw new Error(`rpc ${method}: ${j.error.message || JSON.stringify(j.error)}`);
    return j.result;
  };

  const toAddr = (topic) => '0x' + String(topic).slice(26);

  const logs = await rpc('eth_getLogs', [{
    address: tokenAddress,
    fromBlock: typeof fromBlock === 'bigint' ? '0x' + fromBlock.toString(16) : fromBlock,
    toBlock: typeof toBlock === 'bigint' ? '0x' + toBlock.toString(16) : toBlock,
    topics: [ERC20_TRANSFER_TOPIC]
  }]);

  return (logs || []).map(log => ({
    from: toAddr(log.topics[1]),
    to: toAddr(log.topics[2]),
    value: BigInt(log.data),
    blockNumber: Number(log.blockNumber)
  }));
}

/**
 * Compute holder health metrics from transfer events
 */
function computeHealthMetrics(transfers) {
  const balances = new Map(); // address -> balance (BigInt)
  const holders = new Set(); // unique addresses that ever received

  // Track balances (simplified: just count transfers in/out)
  for (const tx of transfers) {
    const from = tx.from.toLowerCase();
    const to = tx.to.toLowerCase();

    // Skip zero address (mint/burn)
    if (from !== '0x0000000000000000000000000000000000000000') {
      const bal = balances.get(from) || 0n;
      balances.set(from, bal - tx.value);
    }

    if (to !== '0x0000000000000000000000000000000000000000') {
      const bal = balances.get(to) || 0n;
      balances.set(to, bal + tx.value);
      holders.add(to);
    }
  }

  // Get top 10 holders by balance
  const sorted = Array.from(balances.entries())
    .filter(([, bal]) => bal > 0n)
    .sort((a, b) => Number(b[1] - a[1]))
    .slice(0, 10);

  const totalSupply = sorted.reduce((sum, [, bal]) => sum + bal, 0n);

  // Compute concentration (% held by top 10)
  const top10Concentration = totalSupply > 0n
    ? Number(sorted.reduce((sum, [, bal]) => sum + bal, 0n) * 100n / totalSupply)
    : 0;

  // Rug risk score (0-100): higher concentration = higher risk
  let rugScore = 0;
  if (top10Concentration > 80) rugScore += 50; // Very concentrated
  if (top10Concentration > 60) rugScore += 30;
  if (holders.size < 100) rugScore += 20; // Very few holders

  return {
    top10Concentration,
    holderCount: holders.size,
    rugScore: Math.min(rugScore, 100),
    top10Holders: sorted.map(([addr, bal]) => ({
      address: addr,
      balance: bal.toString(),
      percent: totalSupply > 0n ? Number(bal * 100n / totalSupply) : 0
    }))
  };
}

/**
 * Check if a token has healthy holder distribution
 * @param {string} tokenAddress - Token contract address
 * @param {object} options - RPC and block range options
 * @returns {Promise<object>} Health report { healthy, score, metrics, error }
 */
async function checkHoldersHealth(tokenAddress, options = {}) {
  try {
    const rpcUrl = options.rpcUrl || DEFAULT_RPC;
    const f = options.fetchImpl || fetch;

    // Get current block
    const headResp = await f(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }),
      signal: AbortSignal.timeout(8000)
    });
    if (!headResp.ok) throw new Error(`Failed to get block number: HTTP ${headResp.status}`);
    const headJson = await headResp.json();
    if (headJson.error) throw new Error(`eth_blockNumber: ${headJson.error.message}`);
    const head = parseInt(headJson.result, 16);

    const fromBlock = '0x' + Math.max(0, head - DEFAULT_BLOCK_RANGE).toString(16);
    const toBlock = '0x' + head.toString(16);

    const transfers = await fetchTransfers(tokenAddress, { fromBlock, toBlock, rpcUrl, fetchImpl: f });
    const metrics = computeHealthMetrics(transfers);

    const healthy = metrics.rugScore < 50 && metrics.holderCount > 50;

    return {
      healthy,
      score: metrics.rugScore,
      metrics,
      error: null
    };
  } catch (err) {
    return {
      healthy: false,
      score: 100,
      metrics: null,
      error: err.message
    };
  }
}

module.exports = {
  checkHoldersHealth,
  fetchTransfers,
  computeHealthMetrics
};
