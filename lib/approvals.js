'use strict';
/**
 * approvals.js — which doors into this wallet are still open?
 * ===========================================================
 * An ERC-20 approval is a standing permission to move your tokens without asking again. It is the most common
 * drain vector that does not require the key: you approved a contract once, months ago, for an unlimited
 * amount, and forgot. Wallets do not surface these, so almost nobody knows what they have granted.
 *
 * THE TRAP THIS MODULE EXISTS TO AVOID, and it caught us three separate ways this week in other forms: an
 * `Approval` EVENT IS NOT THE CURRENT STATE. The log is a history of permissions granted, and a later
 * approval of zero revokes an earlier one silently — the revocation is just another event in the same list.
 * A tool that reads the log and reports "you have 20 live approvals" is wrong, and wrong in the direction
 * that makes someone panic and then ignore it next time.
 *
 * So the log is used only to find CANDIDATE (token, spender) pairs, and every pair is then confirmed by
 * calling `allowance(owner, spender)` on the chain right now. What gets reported is state, never history.
 *
 * Read-only and keyless. It cannot revoke anything — revoking is a transaction, and that belongs to the
 * wallet holder. This tells you what to revoke and where; it never asks for a key or a signature.
 */
const https = require('node:https');

const RPC = { base: 'https://mainnet.base.org', ethereum: 'https://ethereum-rpc.publicnode.com' };
const EXPLORER = { base: 'https://base.blockscout.com', ethereum: 'https://eth.blockscout.com' };
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const ALLOWANCE_SEL = '0xdd62ed3e';   // allowance(address,address)

// Anything above this is effectively unlimited: no wallet holds 10^30 of a token, so the grant is a blank
// cheque rather than a budget. Treating it as a number would bury the point.
const EFFECTIVELY_UNLIMITED = 10n ** 30n;

const pad = (addr) => String(addr).toLowerCase().replace(/^0x/, '').padStart(64, '0');

function post(url, body) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const u = new URL(url);
    const req = https.request({ hostname: u.hostname, path: u.pathname || '/', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } }, (res) => {
      let d = ''; res.on('data', (c) => (d += c));
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.end(data);
  });
}

const getJSON = (url) => new Promise((resolve) => {
  https.get(url, { headers: { accept: 'application/json' } }, (res) => {
    let d = ''; res.on('data', (c) => (d += c));
    res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
  }).on('error', () => resolve(null));
});

/**
 * The live allowance, straight from the chain. This is the only number worth reporting.
 *
 * Retries, because the first version of this fired forty calls with no pause and 31 of them came back empty
 * — and since an empty answer was being read as a zero allowance, the tool cheerfully reported forty closed
 * doors while having verified nine. Throughput was the whole bug; a short backoff turns a fabricated all-clear
 * into a real one.
 */
async function liveAllowance(chain, token, owner, spender, { attempts = 3 } = {}) {
  const rpc = RPC[String(chain).toLowerCase()];
  if (!rpc) return null;
  for (let i = 0; i < attempts; i++) {
    const res = await post(rpc, { jsonrpc: '2.0', id: 1, method: 'eth_call',
      params: [{ to: token, data: ALLOWANCE_SEL + pad(owner) + pad(spender) }, 'latest'] });
    if (res && typeof res.result === 'string' && res.result !== '0x') {
      try { return BigInt(res.result); } catch { return null; }
    }
    // A revert (a token without allowance(), or a non-token address) is a definitive answer, not congestion.
    if (res && res.error && !/limit|rate|busy|timeout/i.test(String(res.error.message || ''))) return null;
    await new Promise((r) => setTimeout(r, 400 * (i + 1)));
  }
  return null;
}

/**
 * checkApprovals — every door still open into this wallet.
 * @returns { ok, owner, chain, scanned, live[], revoked, unlimited, note }
 *   live[]: { token, tokenName, spender, spenderName, spenderVerified, allowance, unlimited, decimals }
 */
async function checkApprovals(chain, owner, { fromBlock = 0, maxPairs = 40 } = {}) {
  const exp = EXPLORER[String(chain).toLowerCase()];
  if (!exp) return { ok: false, reason: 'chain "' + chain + '" not wired' };

  // 1. The log gives candidates only.
  const url = exp + '/api?module=logs&action=getLogs&fromBlock=' + fromBlock + '&toBlock=latest' +
    '&topic0=' + APPROVAL_TOPIC + '&topic1=0x' + pad(owner) + '&topic0_1_opr=and';
  const res = await getJSON(url);
  const logs = (res && Array.isArray(res.result)) ? res.result : [];

  // Collapse to unique (token, spender) pairs — the newest event per pair is irrelevant, because we are
  // about to ask the chain for the current value anyway.
  const pairs = new Map();
  for (const l of logs) {
    const token = String(l.address || '').toLowerCase();
    const spender = '0x' + String(l.topics && l.topics[2] || '').slice(26).toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(spender) || !token) continue;
    pairs.set(token + '|' + spender, { token, spender });
  }
  const candidates = [...pairs.values()].slice(0, maxPairs);

  // 2. Confirm each against current state, and only then describe it.
  // Three outcomes, never two. A confirmed zero and a call that did not answer look identical in code and
  // mean opposite things to a reader: the first is "this door is shut", the second is "I could not see the
  // door". Collapsing them makes an RPC outage report a clean wallet, which is the same fail-open mistake
  // this codebase keeps finding in other people's scanners — and it was in the first draft of this file.
  const live = [];
  let revoked = 0;
  const unchecked = [];
  for (const c of candidates) {
    const a = await liveAllowance(chain, c.token, owner, c.spender);
    await new Promise((r) => setTimeout(r, 120));   // pace the whole sweep, not just the retries
    if (a === null) { unchecked.push(c); continue; }
    if (a === 0n) { revoked++; continue; }

    const [tok, spd] = await Promise.all([
      getJSON(exp + '/api/v2/tokens/' + c.token),
      getJSON(exp + '/api/v2/addresses/' + c.spender),
    ]);
    const dec = tok && tok.decimals ? Number(tok.decimals) : 18;
    const unlimited = a >= EFFECTIVELY_UNLIMITED;
    live.push({
      token: c.token, tokenName: (tok && (tok.symbol || tok.name)) || 'unknown',
      spender: c.spender,
      spenderName: (spd && spd.name) || null,
      spenderVerified: !!(spd && spd.is_verified),
      spenderIsContract: !!(spd && spd.is_contract),
      spenderFlaggedScam: !!(spd && spd.is_scam),
      allowance: unlimited ? 'unlimited' : (Number(a) / Math.pow(10, dec)).toString(),
      unlimited,
    });
  }

  // Worst first: unlimited outranks large, and an unnamed unverified spender outranks a known router.
  live.sort((x, y) => (Number(y.unlimited) - Number(x.unlimited)) ||
    (Number(x.spenderVerified) - Number(y.spenderVerified)));

  const unlimited = live.filter((l) => l.unlimited).length;
  return { ok: true, owner, chain, scanned: candidates.length, live, revoked, unlimited,
    unchecked: unchecked.length, uncheckedPairs: unchecked,
    complete: unchecked.length === 0,
    note: (unchecked.length
      ? '⚠️ INCOMPLETE: ' + unchecked.length + ' pair(s) could not be read from the chain, so this is NOT a clean bill of health — an unanswered call is not a closed door. Re-run before drawing any conclusion. '
      : '') +
      'STATE, not history. Every entry was confirmed by calling allowance() on the chain just now; the ' +
      revoked + ' pair(s) that appear in the approval log but return zero are already revoked and are not listed. ' +
      'An unlimited allowance to an unverified contract is a standing blank cheque — but note that a live ' +
      'approval is only exploitable by the SPENDER, so if the private key itself is compromised, revoking ' +
      'these is secondary to moving the assets. Revoking is a transaction: this tool tells you what, never signs.' };
}

module.exports = { checkApprovals, liveAllowance, EFFECTIVELY_UNLIMITED, APPROVAL_TOPIC };
