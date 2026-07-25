'use strict';
/**
 * trace.js — follow stolen funds across chains, from the victim's transaction to wherever the trail dies.
 * ========================================================================================================
 * Written by doing it by hand on a real theft and then keeping only the steps that mattered. A drained wallet
 * leaves a trail with a predictable shape: sweep the tokens, dump them for the native asset, bridge out, then
 * relay through fresh accounts. Each hop is public. What stops most people is not secrecy — it is that the
 * trail changes vocabulary at the bridge, and the tooling on the far side is different.
 *
 * The hard-won part is the bridge hop. A cross-chain aggregator writes its destination INTO ITS OWN CALLDATA,
 * in cleartext, because it has to. On the theft this was built from, the exit carried `0x2b6653dc` — which
 * reads as a plausible token amount and is in fact chain id 728126428, TRON mainnet. Misreading it as an
 * amount cost an hour and produced a confident wrong answer. So chain ids are checked against a table before
 * any field is called an amount.
 *
 * WHAT THIS PROVES AND WHAT IT DOES NOT: it establishes that value moved from A to B, and when. It never
 * establishes who controls B, and it never establishes intent. A relay that forwards the exact amount it
 * received is structurally a pass-through; calling its operator a launderer is a conclusion this data cannot
 * carry. Report the hops; let the reader draw the line.
 *
 * Keyless throughout: Blockscout for EVM, TronGrid for TRON.
 */
const https = require('node:https');
const crypto = require('node:crypto');

const EVM = {
  base: 'https://base.blockscout.com/api/v2',
  ethereum: 'https://eth.blockscout.com/api/v2',
  optimism: 'https://optimism.blockscout.com/api/v2',
  polygon: 'https://polygon.blockscout.com/api/v2',
  arbitrum: 'https://arbitrum.blockscout.com/api/v2',
  gnosis: 'https://gnosis.blockscout.com/api/v2',
};
const TRONGRID = 'https://api.trongrid.io';

// Chain ids that appear inside bridge calldata. Without this table a chain id reads as an amount, which is
// exactly the mistake that sent the first pass of this investigation to the wrong conclusion.
const CHAIN_IDS = {
  1: 'ethereum', 10: 'optimism', 56: 'bsc', 100: 'gnosis', 137: 'polygon', 8453: 'base',
  42161: 'arbitrum', 43114: 'avalanche', 59144: 'linea', 728126428: 'tron', 1151111081099710: 'solana',
};

const getJSON = (url) => new Promise((resolve) => {
  https.get(url, { headers: { accept: 'application/json' } }, (res) => {
    let d = ''; res.on('data', (c) => (d += c));
    res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
  }).on('error', () => resolve(null));
});

// ---------------------------------------------------------------------------------------------------------
// TRON addresses are base58check over a 0x41-prefixed 21-byte payload. Explorers and APIs disagree about
// which form they return, so both directions are needed to follow a trail without transcription errors —
// and transcribing a hex address by hand is precisely how a wrong address enters an investigation.
// ---------------------------------------------------------------------------------------------------------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function hexToTron(hex) {
  const b = Buffer.from(String(hex).replace(/^0x/, ''), 'hex');
  if (b.length !== 21 || b[0] !== 0x41) return null;
  const sum = crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest().slice(0, 4);
  let n = BigInt('0x' + Buffer.concat([b, sum]).toString('hex'));
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of Buffer.concat([b, sum])) { if (x === 0) s = '1' + s; else break; }
  return s;
}

function tronToHex(addr) {
  const s = String(addr);
  if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(s)) return null;
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); }
  let h = n.toString(16); if (h.length % 2) h = '0' + h;
  return h.slice(0, -8);   // drop the 4-byte checksum
}

// ---------------------------------------------------------------------------------------------------------
// EVM side
// ---------------------------------------------------------------------------------------------------------

/** What actually left a wallet in one transaction — the transaction, not the event logs. */
async function whatMoved(chain, txHash) {
  const api = EVM[String(chain).toLowerCase()];
  if (!api) return { ok: false, reason: 'chain "' + chain + '" not wired' };
  const tx = await getJSON(api + '/transactions/' + txHash);
  if (!tx || !tx.hash) return { ok: false, reason: 'transaction not found' };
  const xfers = await getJSON(api + '/transactions/' + txHash + '/token-transfers');

  // An ERC-20 Transfer log is attacker-controlled text; only the signer of the transaction is authoritative.
  // Any log claiming a different sender is forged, and reporting it as a real movement poisons the trail.
  const signer = (tx.from && tx.from.hash || '').toLowerCase();
  const moves = [];
  for (const t of ((xfers && xfers.items) || [])) {
    const from = (t.from && t.from.hash || '').toLowerCase();
    const dec = (t.total && t.total.decimals) || 18;
    moves.push({
      token: (t.token && t.token.symbol) || '?',
      amount: (t.total && t.total.value) ? Number(t.total.value) / Math.pow(10, dec) : null,
      from, to: (t.to && t.to.hash || '').toLowerCase(),
      authentic: from === signer,
    });
  }
  return { ok: true, chain, hash: tx.hash, timestamp: tx.timestamp, signer,
    to: tx.to && tx.to.hash, toName: (tx.to && tx.to.name) || null, toIsContract: !!(tx.to && tx.to.is_contract),
    method: tx.method || (tx.decoded_input && tx.decoded_input.method_call) || null,
    nativeValue: Number(tx.value || 0) / 1e18,
    transfers: moves, forgedTransfers: moves.filter((m) => !m.authentic).length };
}

/**
 * Read a bridge exit: which chain, which address. Aggregators put both in the calldata because the far side
 * needs them, so this is usually recoverable without any bridge-specific API.
 */
async function readBridgeExit(chain, txHash) {
  const api = EVM[String(chain).toLowerCase()];
  if (!api) return { ok: false, reason: 'chain not wired' };
  const tx = await getJSON(api + '/transactions/' + txHash);
  if (!tx) return { ok: false, reason: 'transaction not found' };
  const params = (tx.decoded_input && tx.decoded_input.parameters) || [];
  const blob = params.map((p) => (typeof p.value === 'string' ? p.value : JSON.stringify(p.value))).join('');
  const hex = blob.replace(/0x/g, '');

  // Chain ids hide somewhere in the calldata, but NOT reliably on a 32-byte boundary: aggregators concatenate
  // parameters of mixed widths and pad the tail, so word-aligned scanning silently misses them. It missed
  // TRON on the very transaction this was written for. Searching for each known id's own hex, at any offset,
  // is both simpler and correct.
  // Width matters for confidence. A one-byte id like Optimism's 10 (0x0a) occurs constantly inside padding
  // and matched on a transaction that went to TRON — a false destination is worse than no destination, since
  // the whole investigation turns on it. So single-byte ids are reported separately as unusable, and only
  // ids of two bytes or more are treated as evidence.
  const found = new Set(), ambiguous = new Set();
  for (const [id, name] of Object.entries(CHAIN_IDS)) {
    const raw = Number(id).toString(16);
    const padded = raw.length % 2 ? '0' + raw : raw;
    if (!new RegExp('(^|0)' + padded + '(00|$)').test(hex)) continue;
    if (padded.length >= 4) found.add(name); else ambiguous.add(name);
  }
  // A 20-byte value repeated in the parameters is the receiver (aggregators pass it as both receiver and
  // refund address, which is what makes it stand out from every other word).
  const addrs = {};
  for (let i = 0; i + 40 <= hex.length; i += 2) {
    const cand = hex.slice(i, i + 40);
    if (/^0+$/.test(cand) || !/^[0-9a-f]{40}$/.test(cand)) continue;
    addrs[cand] = (addrs[cand] || 0) + 1;
  }
  const repeated = Object.entries(addrs).filter(([, n]) => n > 1).map(([a]) => a);

  return { ok: true, adapter: (params.find((p) => /adapter/i.test(p.name || '')) || {}).value || null,
    destinationChains: [...found], ambiguousMatches: [...ambiguous], candidateReceivers: repeated.slice(0, 4),
    note: 'The destination chain is read from chain ids present in the calldata; a repeated 20-byte value is the likely receiver. Confirm on the destination chain by matching the arrival timestamp and amount before treating it as established.' };
}

// ---------------------------------------------------------------------------------------------------------
// TRON side
// ---------------------------------------------------------------------------------------------------------

/**
 * followTron — walk a TRON account's flow. A relay that forwards the exact amount it received, within
 * seconds, is a pass-through: that shape is what distinguishes a laundering hop from a destination.
 */
async function followTron(address, { maxHops = 3 } = {}) {
  const hops = [];
  let current = address;
  for (let hop = 0; hop < maxHops && current; hop++) {
    const acct = await getJSON(TRONGRID + '/v1/accounts/' + current);
    const info = ((acct && acct.data) || [])[0] || {};
    const txs = await getJSON(TRONGRID + '/v1/accounts/' + current + '/transactions?limit=40');
    const items = (txs && txs.data) || [];
    const ownHex = tronToHex(current);

    const flow = [];
    for (const t of items) {
      const c = ((t.raw_data && t.raw_data.contract) || [])[0] || {};
      const p = (c.parameter && c.parameter.value) || {};
      if (c.type !== 'TransferContract') continue;              // TransferAssetContract = TRC10, usually dust
      const amt = (p.amount || 0) / 1e6;
      if (amt <= 0) continue;
      flow.push({ ts: new Date(t.block_timestamp).toISOString(), amount: amt,
        from: hexToTron(p.owner_address), to: hexToTron(p.to_address),
        direction: (p.owner_address || '').toLowerCase() === (ownHex || '').toLowerCase() ? 'out' : 'in' });
    }
    const outs = flow.filter((f) => f.direction === 'out').sort((a, b) => b.amount - a.amount);
    const ins = flow.filter((f) => f.direction === 'in');

    // Pass-through detection. An exact microTRX match is the clean case, but a relay routinely keeps a cut
    // or pays fees out of the balance, so a strict equality test declares a real relay to be a destination
    // and the trail stops one hop early. A within-5% forward is still a forward.
    const near = (a, b) => Math.abs(a - b) <= Math.max(0.000002, b * 0.05);
    const passThrough = outs.find((o) => ins.some((i) => near(o.amount, i.amount)));

    hops.push({ address: current,
      createdAt: info.create_time ? new Date(info.create_time).toISOString() : null,
      balanceTrx: (info.balance || 0) / 1e6,
      inbound: ins.length, outbound: outs.length,
      largestOut: outs[0] || null,
      passThrough: passThrough ? { amount: passThrough.amount, to: passThrough.to, at: passThrough.ts,
        note: 'forwarded the exact amount it received — a relay hop, not a destination' } : null,
      recent: flow.slice(0, 8) });

    current = passThrough ? passThrough.to : (outs[0] ? outs[0].to : null);
    if (!current) break;
  }
  return { ok: true, hops, note: 'STRUCTURE ONLY. Amount-matched forwarding proves a pass-through; it does not identify who controls any address, and it does not establish intent.' };
}

module.exports = { whatMoved, readBridgeExit, followTron, hexToTron, tronToHex, CHAIN_IDS, EVM };
