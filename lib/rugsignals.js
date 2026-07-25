'use strict';
/**
 * rugsignals.js — "can this token still be rugged, and BY WHOM?" — BIII's contract-level rug taxonomy.
 * =====================================================================================================
 * `meme.js` answers "is this the REAL contract for the symbol". That is a *disambiguation* question and it
 * says nothing about whether the real contract is itself a trap. This module answers the other half:
 * given the contract, what powers does its deployer still hold over your money?
 *
 * The load-bearing idea — and the reason naive scanners are noise: a dangerous capability only matters if
 * someone can still FIRE it. `is_mintable=1` with ownership renounced is inert; the same flag with a live
 * owner means the rug is armed. Proven on real data: BRETT reports unlocked LP but a renounced owner and is
 * not a rug, while a fresh deploy with the same LP reading plus a live owner is. So every owner-gated danger
 * is scored CONDITIONALLY on the owner still existing. Ungated dangers (honeypot, external call) always count.
 *
 * FAIL-CLOSED, like the rest of BIII: absent data is `unknown`, never `clean`. We would rather say "I could
 * not verify this" than hand out a green light we cannot defend. Source: GoPlus token-security (free, keyless).
 *
 * Pure + dependency-free: the HTTP fetch is injectable (fetchImpl) so it unit-tests offline.
 */
const https = require('node:https');

const GOPLUS = 'https://api.gopluslabs.io/api/v1/token_security/';
const HONEYPOT = 'https://api.honeypot.is/v2/IsHoneypot';
const CHAIN_IDS = { base: '8453', ethereum: '1', bsc: '56', polygon: '137', arbitrum: '42161', optimism: '10', avalanche: '43114' };

// Thresholds — deliberately conservative; each is a claim we must be willing to defend publicly.
const SELL_TAX_EXTRACTIVE = 0.10;   // >=10% sell tax bleeds the holder
const SELL_TAX_FATAL = 0.50;        // >=50% is a honeypot wearing a tax
const LP_LOCKED_MIN = 0.50;         // <50% of LP locked/burned = the pool can be drained
const TOP_HOLDER_MAX = 0.20;        // one non-contract wallet holding >20% can dump the chart
const MIN_HOLDERS = 50;             // below this, "holders" is not a distribution, it is a launch

const yes = (v) => v === '1' || v === 1 || v === true;
const num = (v) => { const n = parseFloat(v); return Number.isFinite(n) ? n : null; };

/** Ownership renounced? A zero/empty owner means the owner-gated powers below cannot be fired anymore. */
function ownerIsLive(r) {
  const o = String(r.owner_address == null ? '' : r.owner_address).toLowerCase();
  if (!o || o === '0x0000000000000000000000000000000000000000' || o === '0x') return false;
  return true;
}

/**
 * Share of LP that can no longer be pulled — burned (sent to a dead address) or held by a locker contract.
 * GoPlus marks these via `is_locked`, and burn addresses surface as tagged holders, so we count both.
 */
function lpLockedShare(r) {
  const lps = Array.isArray(r.lp_holders) ? r.lp_holders : null;
  if (!lps || !lps.length) return null;               // no data -> unknown, NOT "unlocked"
  let locked = 0;
  for (const h of lps) {
    const pct = num(h.percent) || 0;
    const tag = String(h.tag || '').toLowerCase();
    const burned = tag.includes('burn') || tag.includes('null') || tag.includes('dead');
    if (yes(h.is_locked) || burned) locked += pct;
  }
  return locked;
}

/** Largest holder that is a plain wallet (contracts = pools/lockers/bridges, not a dumper). */
function topWalletShare(r) {
  const hs = Array.isArray(r.holders) ? r.holders : null;
  if (!hs || !hs.length) return null;
  let top = 0;
  for (const h of hs) {
    if (yes(h.is_contract)) continue;
    const pct = num(h.percent) || 0;
    if (pct > top) top = pct;
  }
  return top;
}

/**
 * assessRugFields — the pure verdict, given one GoPlus result row. Exported so it unit-tests with fixtures
 * and so callers can score data they already hold without a second network round-trip.
 * @returns { verdict, armed[], flags[], unknowns[], owner, lpLockedPct, topWalletPct, holders, disclosure }
 *   verdict: 'rug_ready' | 'high_risk' | 'caution' | 'clean' | 'unknown'
 */
function assessRugFields(r, sim) {
  // Two independent kinds of evidence, and they fail at opposite ends: the curated index (`r`) knows owner
  // powers and LP locks but has never heard of a token minted ten minutes ago, while the live simulation
  // (`sim`) can always answer "does a sell actually go through right now" but sees nothing about who controls
  // the contract. Fresh launches — the ones that rug — are exactly the case where only the simulation exists,
  // so refusing to speak without the index would blind us precisely where it matters.
  if (!r || typeof r !== 'object') return assessFromSimulationOnly(sim);
  const live = ownerIsLive(r);
  const armed = [];     // the deployer can rug RIGHT NOW
  const flags = [];     // real risk, not directly fireable
  const unknowns = [];

  // --- Ungated traps: dangerous no matter who owns the contract ---------------------------------
  if (yes(r.is_honeypot)) armed.push('HONEYPOT — buys succeed, sells do not. This is a trap, not a token.');
  else if (r.is_honeypot === undefined) unknowns.push('honeypot status');
  if (yes(r.cannot_sell_all)) armed.push('you cannot sell your full position (partial honeypot)');
  if (yes(r.selfdestruct)) armed.push('the contract can self-destruct');
  if (yes(r.external_call)) flags.push('transfers make an external call — logic can be changed from outside the contract');
  if (yes(r.cannot_buy)) flags.push('buying is currently blocked');

  const sell = num(r.sell_tax), buy = num(r.buy_tax);
  if (sell != null && sell >= SELL_TAX_FATAL) armed.push('sell tax is ' + Math.round(sell * 100) + '% — economically a honeypot');
  else if (sell != null && sell >= SELL_TAX_EXTRACTIVE) flags.push('sell tax ' + Math.round(sell * 100) + '%');
  if (buy != null && buy >= SELL_TAX_EXTRACTIVE) flags.push('buy tax ' + Math.round(buy * 100) + '%');
  if (sell == null) unknowns.push('sell tax');

  // Live simulation overrides the index when they disagree: an actual attempted sell is stronger evidence
  // than a cached scan, and it is the fresher of the two.
  if (sim && sim.ok) {
    if (sim.honeypot) armed.push('HONEYPOT confirmed by live simulation — a sell does not go through' + (sim.reason ? ' (' + sim.reason + ')' : ''));
    if (sim.sellTax != null && sim.sellTax >= SELL_TAX_FATAL * 100) armed.push('live sell tax is ' + Math.round(sim.sellTax) + '%');
    else if (sim.sellTax != null && sim.sellTax >= SELL_TAX_EXTRACTIVE * 100 && sell == null) flags.push('live sell tax ' + Math.round(sim.sellTax) + '%');
    if (sell == null && sim.sellTax != null) { const i = unknowns.indexOf('sell tax'); if (i >= 0) unknowns.splice(i, 1); }
  }

  // --- Owner-gated powers: only ARMED while an owner still exists ------------------------------
  const gated = [
    [yes(r.is_mintable), 'supply is mintable — the owner can print and dump on you'],
    [yes(r.transfer_pausable), 'transfers are pausable — the owner can freeze the market'],
    [yes(r.is_blacklisted), 'the owner can blacklist wallets — including yours'],
    [yes(r.slippage_modifiable), 'the tax is modifiable — the owner can raise the sell tax after you buy'],
    [yes(r.personal_slippage_modifiable), 'the owner can set a per-wallet tax targeting you specifically'],
    [yes(r.is_proxy), 'proxy contract — the code you audited can be swapped for different code'],
    [yes(r.trading_cooldown), 'trading cooldown is enforced by the owner'],
  ];
  // Defused dangers are recorded so a reader can see what the contract CAN do, but they are counted
  // separately and must never drive an escalation. Letting them do so contradicts the module's own premise
  // and it showed immediately: BRETT, a token with roughly $944k of liquidity, jumped to high_risk on the
  // strength of one live flag plus one flag the verdict had itself declared inert.
  const defused = [];
  for (const [on, msg] of gated) {
    if (!on) continue;
    if (live) armed.push(msg); else defused.push('(defused by renounced ownership) ' + msg);
  }
  // A "renounced" owner that can be taken back is not renounced at all — this one is always armed.
  if (yes(r.can_take_back_ownership)) armed.push('ownership can be TAKEN BACK — any "renounced" claim is false');
  if (yes(r.hidden_owner)) armed.push('hidden owner — control exists outside the visible owner address');
  if (r.owner_address === undefined) unknowns.push('owner');

  // --- Liquidity: the "can they just pull the pool" question ------------------------------------
  // An unlocked pool is a FIREABLE power, and treating it as a soft flag was a mistake this module made
  // until real outcomes contradicted it: the first four tokens observed rugging had all been called
  // `caution`, none `rug_ready`, and every one of them died the same way — the deployer withdrew the
  // liquidity. No malicious contract function was required. The verdict had named the exact mechanism and
  // then filed it under the weakest category, which is the same failure as not naming it at all.
  // It still is not `armed` on its own: a legitimate project also launches with unlocked LP. But combined
  // with any second flag it escalates, because that is the shape the observed rugs actually had.
  const lpLocked = lpLockedShare(r);
  let pullablePool = false;
  if (lpLocked == null) unknowns.push('LP lock status');
  else if (lpLocked < LP_LOCKED_MIN) {
    pullablePool = true;
    flags.push('only ' + Math.round(lpLocked * 100) + '% of liquidity is locked or burned — the deployer can withdraw the pool at will, which is how most launches actually die');
  }

  // --- Distribution --------------------------------------------------------------------------
  const topW = topWalletShare(r);
  if (topW == null) unknowns.push('holder distribution');
  else if (topW > TOP_HOLDER_MAX) flags.push('one wallet holds ' + Math.round(topW * 100) + '% of supply');
  // A freshly indexed token reports holder_count 0 because the count has not been computed yet, not because
  // nobody holds it — the live simulation routinely sees a dozen holders on the same contract. Reading that
  // zero literally would stamp a flag on every new launch, which is the exact noise that makes scanners
  // ignorable. So zero means "not computed", and the simulation's count wins when we have it.
  const idxHolders = num(r.holder_count);
  const holders = (sim && sim.ok && sim.holders != null) ? sim.holders : (idxHolders || null);
  if (holders != null && holders < MIN_HOLDERS) flags.push('only ' + holders + ' holders — a launch, not a distribution');
  else if (holders == null) unknowns.push('holder count');

  // --- Verdict ---------------------------------------------------------------------------------
  let verdict;
  if (armed.length) verdict = 'rug_ready';
  else if (flags.length >= 3) verdict = 'high_risk';
  else if (pullablePool && flags.length >= 2) verdict = 'high_risk';   // a pool that can be pulled, plus anything else
  else if (flags.length) verdict = 'caution';
  else if (unknowns.length > 2) verdict = 'unknown';   // fail-closed: too little data to call it clean
  else verdict = 'clean';

  const reason = armed.length ? armed[0]
    : flags.length ? flags[0]
    : verdict === 'unknown' ? 'not enough security data to make a defensible call'
    : 'no fireable rug power found: ' + (live ? 'owner is live but holds no dangerous capability' : 'ownership renounced') + (lpLocked != null ? ', ' + Math.round(lpLocked * 100) + '% of LP locked/burned' : '');

  return { verdict, reason, armed, flags, defused, unknowns, ownerLive: live, owner: r.owner_address || null,
    lpLockedPct: lpLocked, topWalletPct: topW, holders, disclosure: DISCLOSURE };
}

/**
 * The fresh-launch path: no curated security record exists yet, only a live trade simulation. We can say
 * whether a sell goes through today; we cannot say who is allowed to change that tomorrow. So this NEVER
 * returns `clean` — "you can sell it right now" is real information, but it is not safety, and the gap
 * between the two is where the money is lost.
 */
function assessFromSimulationOnly(sim) {
  const base = { armed: [], flags: [], unknowns: ['owner', 'LP lock status', 'holder distribution'], lpLockedPct: null, topWalletPct: null, disclosure: DISCLOSURE, simulationOnly: true };
  if (!sim || !sim.ok) return { ...base, verdict: 'unknown', reason: 'no security record and no live trade simulation for this contract', unknowns: ['*'] };
  if (sim.honeypot) return { ...base, verdict: 'rug_ready', reason: 'HONEYPOT confirmed by live simulation — a sell does not go through' + (sim.reason ? ' (' + sim.reason + ')' : ''), armed: ['honeypot (live simulation)'] };
  const armed = [], flags = [];
  if (sim.sellTax != null && sim.sellTax >= SELL_TAX_FATAL * 100) armed.push('live sell tax is ' + Math.round(sim.sellTax) + '% — economically a honeypot');
  else if (sim.sellTax != null && sim.sellTax >= SELL_TAX_EXTRACTIVE * 100) flags.push('live sell tax ' + Math.round(sim.sellTax) + '%');
  if (sim.buyTax != null && sim.buyTax >= SELL_TAX_EXTRACTIVE * 100) flags.push('live buy tax ' + Math.round(sim.buyTax) + '%');
  for (const f of (sim.flags || [])) flags.push('simulation flag: ' + f);
  if (sim.holders != null && sim.holders < MIN_HOLDERS) flags.push('only ' + sim.holders + ' holders — a launch, not a distribution');
  if (armed.length) return { ...base, verdict: 'rug_ready', reason: armed[0], armed, flags };
  return { ...base, verdict: flags.length >= 2 ? 'high_risk' : 'caution', armed: [], flags,
    reason: 'sells go through right now (simulated' + (sim.sellTax != null ? ', ' + Math.round(sim.sellTax) + '% sell tax' : '') + '), but this token is too new to have a security record — ownership powers and LP locks are UNVERIFIED' };
}

/** Live trade simulation — works on a contract minted minutes ago, where any curated index is still blind. */
async function simulateTrade(chain, address, fetchImpl) {
  const id = CHAIN_IDS[String(chain).toLowerCase()];
  if (!id) return { ok: false };
  try {
    const j = await getJSON(HONEYPOT + '?address=' + encodeURIComponent(address) + '&chainID=' + id, fetchImpl);
    const hr = (j && j.honeypotResult) || {}, s = (j && j.simulationResult) || {}, t = (j && j.token) || {};
    if (hr.isHoneypot === undefined && s.sellTax === undefined) return { ok: false };
    return { ok: true, honeypot: !!hr.isHoneypot, reason: hr.honeypotReason || null,
      buyTax: num(s.buyTax), sellTax: num(s.sellTax), flags: Array.isArray(j.flags) ? j.flags : [],
      holders: num(t.totalHolders) };
  } catch { return { ok: false }; }
}

const DISCLOSURE = 'ADVISORY, fail-closed. "clean" means no rug power was found that anyone can still fire — it is NOT a promise the price holds or the team is honest. Owner-gated dangers are scored only while an owner exists; missing data reads as unknown, never clean. Source: GoPlus token-security. Re-verify on the block explorer — a verdict is a pointer to the chain, not a badge.';

function getJSON(url, fetchImpl) {
  if (fetchImpl) return fetchImpl(url);
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { accept: 'application/json' } }, (res) => {
      let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error('goplus http ' + res.statusCode));
        try { resolve(JSON.parse(d)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

/**
 * scanRug — fetch + assess up to 20 contracts on one chain in a SINGLE request (GoPlus batches by comma).
 * Batching matters: the keyless tier is rate-limited per request, not per address, so this is ~20x cheaper.
 * @param {string} chain - 'base' | 'ethereum' | ... (see CHAIN_IDS)
 * @param {string[]} addresses
 * @returns {Promise<Object>} address(lowercased) -> assessment
 */
async function scanRug(chain, addresses, { fetchImpl } = {}) {
  const id = CHAIN_IDS[String(chain).toLowerCase()];
  const list = (addresses || []).filter(Boolean).slice(0, 20);
  const out = {};
  if (!id) { for (const a of list) out[String(a).toLowerCase()] = { verdict: 'unknown', reason: 'chain "' + chain + '" is not covered by the contract-security source', armed: [], flags: [], unknowns: ['*'], disclosure: DISCLOSURE }; return out; }
  if (!list.length) return out;

  // Pass 1 — the batch endpoint answers from cache only. Cheap, and it covers everything already indexed.
  const byLower = {};
  try {
    const res = await getJSON(GOPLUS + id + '?contract_addresses=' + list.map(encodeURIComponent).join(','), fetchImpl);
    for (const [k, v] of Object.entries((res && res.result) || {})) byLower[k.toLowerCase()] = v;
  } catch { /* fall through to per-address + simulation */ }

  // Pass 2 — a single-address query is what actually makes the index look at an unknown contract, so the
  // tokens the batch skipped are precisely the fresh ones we care about most. Sequential and throttled:
  // the keyless tier is rate-limited per request, and being rude to a free API is how we lose it.
  const missing = list.filter((a) => !byLower[String(a).toLowerCase()]);
  for (const a of missing) {
    try {
      const res = await getJSON(GOPLUS + id + '?contract_addresses=' + encodeURIComponent(a), fetchImpl);
      for (const [k, v] of Object.entries((res && res.result) || {})) byLower[k.toLowerCase()] = v;
    } catch { /* leave it to the simulation */ }
    if (!fetchImpl) await new Promise((r) => setTimeout(r, 250));
  }

  // Pass 3 — live simulation for every contract. It is the only source that works on a minutes-old token,
  // and where both exist it settles disagreements: an attempted sell beats a cached scan.
  const sims = {};
  await Promise.all(list.map(async (a) => { sims[String(a).toLowerCase()] = await simulateTrade(chain, a, fetchImpl); }));

  for (const a of list) {
    const key = String(a).toLowerCase();
    out[key] = assessRugFields(byLower[key], sims[key]);
  }
  return out;
}

/** One address, convenience wrapper. */
async function scanRugOne(chain, address, opts) {
  const r = await scanRug(chain, [address], opts);
  return r[String(address).toLowerCase()] || { verdict: 'unknown', reason: 'no result', armed: [], flags: [], unknowns: ['*'], disclosure: DISCLOSURE };
}

module.exports = { scanRug, scanRugOne, assessRugFields, lpLockedShare, topWalletShare, ownerIsLive,
  CHAIN_IDS, LP_LOCKED_MIN, TOP_HOLDER_MAX, SELL_TAX_FATAL, SELL_TAX_EXTRACTIVE, DISCLOSURE };
