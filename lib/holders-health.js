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
/* Le commentaire disait « ~33k blocks ≈ 4.5 days on Base » a cote de la valeur 10000 — deux chiffres qui
 * ne parlent pas du meme objet. A ~2 s par bloc sur Base, 10000 blocs valent ~5,5 h, pas 4,5 jours. La
 * fenetre observee est donc bien plus courte que ce que le fichier annoncait: aucun changement de
 * comportement ici, mais la phrase servait a interpreter le verdict. */
const DEFAULT_BLOCK_RANGE = 10000; // ~10k blocs ≈ 5,5 h sur Base (~2 s/bloc)

/* Un mot ABI: exactement 32 octets. `topics[1]`/`topics[2]`/`data` d'un Transfer standard en sont un. */
const WORD = /^0x[0-9a-fA-F]{64}$/;

/**
 * Lire une quantite hexadecimale d'une reponse RPC.
 *
 * ⚠️ MESURE DU 2026-07-29. `parseInt(undefined, 16)` rend NaN, et NaN a traverse tout le module sans
 * jamais rien casser: `Math.max(0, NaN - 10000).toString(16)` donne la chaine 'NaN', donc la plage
 * demandee au noeud etait `fromBlock: '0xNaN', toBlock: '0xNaN'`. Un noeud qui repond `[]` a ca — ou un
 * proxy qui repond 200 sans `result` — produisait le verdict EXACTEMENT identique a celui d'un jeton
 * calme reellement lu: `{healthy:false, score:20, holderCount:0, error:null}`. Un `error: null` est une
 * AFFIRMATION: il dit que la lecture a eu lieu. Une absence n'est pas un zero.
 */
function hexQuantity(v, what) {
  if (typeof v !== 'string' || !/^0x[0-9a-fA-F]+$/.test(v)) {
    throw new Error(what + ': expected a hex quantity, got ' + (v === undefined ? 'no result field' : JSON.stringify(v)));
  }
  const n = Number.parseInt(v, 16);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(what + ': hex quantity out of range (' + v + ')');
  return n;
}

/**
 * Fetch transfer events for a token contract
 *
 * Rend un tableau de transferts, porteur d'une propriete `unreadable`: le NOMBRE de logs qu'on n'a pas
 * su lire. Un log illisible n'est pas un transfert qui n'a pas eu lieu — le jeter en silence ferait
 * d'une absence une mesure. Le compter permet a l'appelant de refuser de conclure. (Propriete posee sur
 * le tableau plutot que changement de type de retour: `.length`/`.map` et l'export restent intacts.)
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

  /* `(logs || [])` faisait d'un `result` absent une liste vide, donc « aucun transfert »: la reponse
   * mutilee d'un noeud devenait un fait sur le jeton. Un resultat qui n'est pas une liste est une panne. */
  if (!Array.isArray(logs)) {
    throw new Error('eth_getLogs: expected an array of logs, got ' + (logs === undefined ? 'no result field' : JSON.stringify(logs)));
  }

  /* ⚠️ MESURE DU 2026-07-29. `toAddr` faisait `'0x' + String(topic).slice(26)`: sur un `topics[1]`
   * ABSENT ca rendait la chaine '0x' — une adresse fantome, comptee comme un porteur. Et `BigInt(data)`
   * sur les 96 octets d'un Transfer NON indexe rendait un entier de 231 chiffres, sans rien jeter. Le
   * verdict publie annoncait alors `holderCount: 1, error: null` pour un log dont on n'avait lu aucun
   * champ. On valide donc la FORME avant de lire la valeur. */
  const readable = [];
  let unreadable = 0;
  for (const log of logs) {
    const topics = log && log.topics;
    if (!Array.isArray(topics) || !WORD.test(topics[1]) || !WORD.test(topics[2]) || !WORD.test(log.data)) {
      unreadable++;
      continue;
    }
    readable.push({
      from: toAddr(topics[1]),
      to: toAddr(topics[2]),
      value: BigInt(log.data),
      blockNumber: Number(log.blockNumber)
    });
  }
  readable.unreadable = unreadable;
  return readable;
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
  /* ⚠️ LA CONCENTRATION VALAIT 100 POUR TOUTE DISTRIBUTION — defaut REEL, mesure ici le 2026-07-27:
   * une baleine -> 100, deux cents porteurs a parts EGALES -> 100 aussi. `totalSupply` etait la somme
   * des DIX PREMIERS soldes, puis on divisait cette meme somme par elle-meme.
   *
   * Comme rugScore ajoute 50 au-dessus de 80 et 30 au-dessus de 60, il valait au moins 80 partout, donc
   * `healthy` etait TOUJOURS faux. Ca echouait dans le bon sens — et n'observait rien. Un signal a
   * variance nulle n'est pas une mesure, c'est une affirmation.
   *
   * Le denominateur est desormais la somme de TOUS les soldes positifs observes. Meme correction que
   * dans biii le meme jour; les deux depots portent une copie de ce module. */
  const positifs = Array.from(balances.entries()).filter(([, bal]) => bal > 0n);
  const totalSupply = positifs.reduce((sum, [, bal]) => sum + bal, 0n);

  const sorted = positifs
    /* Comparer les BigInt entre eux: `Number(b - a)` sur des soldes a 18 decimales convertit une
     * difference qui peut depasser MAX_SAFE_INTEGER. Le signe survit, mais l'intention est plus claire. */
    .sort((a, b) => (b[1] > a[1] ? 1 : b[1] < a[1] ? -1 : 0))
    .slice(0, 10);

  const top10Sum = sorted.reduce((sum, [, bal]) => sum + bal, 0n);
  const top10Concentration = totalSupply > 0n ? Number(top10Sum * 100n / totalSupply) : 0;

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
    /* `parseInt(headJson.result, 16)` acceptait l'absence de `result` et rendait NaN — voir hexQuantity. */
    const head = hexQuantity(headJson.result, 'eth_blockNumber');

    const fromBlock = '0x' + Math.max(0, head - DEFAULT_BLOCK_RANGE).toString(16);
    const toBlock = '0x' + head.toString(16);

    const transfers = await fetchTransfers(tokenAddress, { fromBlock, toBlock, rpcUrl, fetchImpl: f });
    const unreadableLogs = transfers.unreadable || 0;
    const metrics = computeHealthMetrics(transfers);

    /* Une distribution calculee sur une liste dont une partie n'a pas ete lue n'est pas une distribution
     * saine: c'est une distribution partiellement inconnue. On publie le chiffre — il reste informatif —
     * mais `healthy` ne peut pas etre affirme par-dessus un trou. Le compte voyage avec le verdict pour
     * que l'appelant voie la BORNE et pas seulement le score. */
    const healthy = unreadableLogs === 0 && metrics.rugScore < 50 && metrics.holderCount > 50;

    return {
      healthy,
      score: metrics.rugScore,
      metrics,
      unreadableLogs,
      error: null
    };
  } catch (err) {
    return {
      healthy: false,
      score: 100,
      metrics: null,
      unreadableLogs: null,
      error: err.message
    };
  }
}

module.exports = {
  checkHoldersHealth,
  fetchTransfers,
  computeHealthMetrics
};
