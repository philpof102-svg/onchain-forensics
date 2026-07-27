'use strict';
/**
 * meme.js — "which contract is the REAL memecoin, and is it safe to ape?" — BIII genuineness for memes.
 * =====================================================================================================
 * A meme symbol has many look-alike contracts across chains (BRETT = 10, TOSHI = 8, proven live). Aping the
 * wrong one = total loss. This returns a FAIL-CLOSED verdict from live market data (DexScreener, free), the
 * same discipline as our RWA `assessAsset`: never falsely certify "this is the real one" — ABSTAIN when the
 * top candidates are tied, and flag look-alikes. Advisory + re-verifiable (DexScreener/basescan links).
 *
 * Layer 2: holders health (on-chain distribution) to detect rugs/pump schemes.
 *
 * Pure + dependency-free: the HTTP fetch is injectable (fetchImpl) so it unit-tests offline.
 */
const https = require('node:https');
const { checkHoldersHealth } = require('./holders-health');

const LIQ_FLOOR = 10000;          // below this = not a credible contract
const DOMINANCE = 3;              // canonical must hold >= 3x the runner-up's liquidity

function getJSON(url, fetchImpl) {
  if (fetchImpl) return fetchImpl(url);
  return new Promise((resolve, reject) => {
    https.get(url, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => {
      if (res.statusCode !== 200) return reject(new Error('dexscreener http ' + res.statusCode));
      try { resolve(JSON.parse(d)); } catch (e) { reject(e); } }); }).on('error', reject);
  });
}

/**
 * DexScreener indexe par SLUG ('base', 'solana'), jamais par nombre. Un appelant ecrit naturellement
 * 8453: on accepte les deux et on ramene tout au slug. `null` = « chaine non traduisible », ce qui n'est
 * PAS « pas de filtre ».
 */
const SLUG_PAR_ID = {
  1: 'ethereum', 8453: 'base', 137: 'polygon', 42161: 'arbitrum', 10: 'optimism', 56: 'bsc', 43114: 'avalanche',
};
function slugDeChaine(v) {
  if (v == null || v === '') return undefined;                     // aucun filtre demande
  if (typeof v === 'number' || /^\d+$/.test(String(v))) return SLUG_PAR_ID[Number(v)] || null;
  return String(v).toLowerCase();
}

/**
 * Collapse DexScreener pairs to one row per token contract (best pair's liquidity wins).
 *
 * ⚠️ CE QUI SUIT EST UN DURCISSEMENT, PAS LA CORRECTION D'UN VERDICT FAUX — mesure avant d'ecrire.
 *
 * Dans biii, `Number(chainId)` au site d'appel transformait 'base' en NaN (falsy, donc AUCUN filtre) et
 * faisait rendre un contrat SOLANA certifie « genuine » a qui demandait Base. ICI, rien ne coerce:
 * bin/onchain-forensics-mcp.js passe la valeur telle quelle et le schema annonce deja `type: 'string',
 * e.g. base`. L'ancienne comparaison `p.chainId !== chainId` marchait donc pour un slug exact.
 *
 * Comportement ancien, mesure: 'base' -> base · 'BASE' -> vide · 8453 -> vide · inconnue -> vide.
 * Toujours fail-closed, jamais une autre chaine. Ce qu'on gagne est la TOLERANCE D'ENTREE (casse,
 * identifiant numerique) et un refus EXPLICITE plutot qu'un vide accidentel — pas un verdict repare.
 */
function candidatesFrom(pairs, symbol, chainId) {
  const S = String(symbol || '').toUpperCase();
  const slug = slugDeChaine(chainId);
  /* FAIL-CLOSED: une chaine demandee mais non reconnue ne se degrade pas en « toutes les chaines ».
   * Zero candidat fait remonter thin/ambiguous — une abstention, jamais une certification deplacee. */
  if (slug === null) return [];
  const byTok = {};
  for (const p of (pairs || [])) {
    if (!p.baseToken || String(p.baseToken.symbol || '').toUpperCase() !== S) continue;
    if (slug && String(p.chainId || '').toLowerCase() !== slug) continue;
    const k = p.chainId + ':' + p.baseToken.address;
    const liq = (p.liquidity && p.liquidity.usd) || 0;
    if (!byTok[k] || byTok[k].liquidityUsd < liq) byTok[k] = {
      chain: p.chainId, address: p.baseToken.address, name: p.baseToken.name || '',
      liquidityUsd: liq, volume24: (p.volume && p.volume.h24) || 0, pairCreatedAt: p.pairCreatedAt || 0,
      dexscreener: p.url || ('https://dexscreener.com/' + p.chainId + '/' + p.baseToken.address),
    };
  }
  return Object.values(byTok).sort((a, b) => b.liquidityUsd - a.liquidityUsd);
}

/**
 * vetMeme — fail-closed verdict for a meme symbol (+ optional chain + a specific address to judge).
 * @param {object} opts - { symbol, chainId, address, fetchImpl, holderHealthImpl }
 * @returns { status, reason, canonical, candidates, disclosure, health }
 *   status: 'genuine' | 'impersonation' | 'ambiguous' | 'thin' | 'unknown'
 *   health: holders health metrics for the canonical candidate (if available)
 */
async function vetMeme({ symbol, chainId, address, fetchImpl, holderHealthImpl } = {}) {
  if (!symbol) return { status: 'unknown', reason: 'a symbol is required' };
  let pairs;
  try { pairs = (await getJSON('https://api.dexscreener.com/latest/dex/search?q=' + encodeURIComponent(symbol), fetchImpl)).pairs; }
  catch (e) { return { status: 'unknown', reason: 'market data unavailable', candidates: [] }; }

  const cands = candidatesFrom(pairs, symbol, chainId);
  const credible = cands.filter((c) => c.liquidityUsd >= LIQ_FLOOR);
  const disclosure = 'ADVISORY, fail-closed: "genuine" = one contract dominates liquidity (>=' + DOMINANCE + 'x the runner-up); tied leaders are AMBIGUOUS (never certified); look-alikes/thin never read as safe. Re-verify each on DexScreener/Basescan — a verdict is a pointer to the chain, not a badge.';

  if (!credible.length) return { status: 'thin', reason: 'no contract with credible liquidity for "' + symbol + '"' + (chainId ? ' on ' + chainId : ''), candidates: cands.slice(0, 12), disclosure };

  const top = credible[0], second = credible[1];
  const clearWinner = !second || top.liquidityUsd >= DOMINANCE * second.liquidityUsd;
  const canonical = clearWinner ? { chain: top.chain, address: top.address, liquidityUsd: top.liquidityUsd, dexscreener: top.dexscreener } : null;

  // Layer 2: holders health check (only for Base chain candidates with clear winner)
  let health = null;
  if (canonical && canonical.chain === 'base' && (holderHealthImpl || checkHoldersHealth)) {
    try {
      const healthCheck = holderHealthImpl || checkHoldersHealth;
      health = await healthCheck(canonical.address, { fetchImpl });
    } catch (e) {
      health = { healthy: false, score: 100, error: 'health check failed: ' + e.message };
    }
  }

  // Judging a SPECIFIC address the caller is about to ape:
  if (address) {
    const a = String(address).toLowerCase();
    const isTop = top.address.toLowerCase() === a;
    if (!clearWinner) return { status: 'ambiguous', reason: 'the top contracts are within ' + DOMINANCE + 'x liquidity of each other — cannot certify a single real one', canonical: null, candidates: credible.slice(0, 12), disclosure, health };
    if (isTop) return { status: 'genuine', reason: 'this IS the dominant-liquidity contract for "' + symbol + '"', canonical, candidates: credible.slice(0, 12), disclosure, health };
    const asCand = cands.find((c) => c.address.toLowerCase() === a);
    return { status: 'impersonation', reason: 'this is NOT the dominant contract — the real one holds far more liquidity', canonical, thisContract: asCand || { address, note: 'not found in credible set' }, candidates: credible.slice(0, 12), disclosure, health };
  }

  // No specific address: report which is canonical, or abstain.
  if (!clearWinner) return { status: 'ambiguous', reason: credible.length + ' contracts, top two within ' + DOMINANCE + 'x liquidity — no single real one can be certified', canonical: null, candidates: credible.slice(0, 12), disclosure, health };
  return { status: 'genuine', reason: 'one contract dominates for "' + symbol + '"', canonical, candidates: credible.slice(0, 12), disclosure, health };
}

module.exports = { vetMeme, candidatesFrom };
