'use strict';
/**
 * b20.js — is this actually a native B20, or a plain token wearing the B20 address prefix?
 * ========================================================================================
 * B20 is Base's native standard for COMPLIANT asset issuance — stablecoins and RWA — shipped with the Beryl
 * hardfork. Its tokens live at addresses beginning `0xb200`, and its logic runs in a Rust precompile rather
 * than in deployed EVM bytecode. That combination creates a brand-new impersonation surface: as issuers and
 * users learn to read `0xb200…` as "official Base asset standard", a plain ERC-20 deployed to a vanity
 * address with the same prefix inherits that credibility for free.
 *
 * Found while judging live launches: two tokens both starting `0xb200`. One carried a single byte of on-chain
 * code and twenty zero bytes of address padding — a genuine precompile-backed B20. The other carried 4.5 KB
 * of verified Solidity, in a contract literally named "BaseToken", behind a proxy. Landing on that prefix by
 * chance is roughly one in sixty-five thousand.
 *
 * The test is objective and free: a native B20 has essentially no EVM bytecode, because there is nothing to
 * deploy. Anything substantial at that prefix is a normal contract borrowing the standard's clothes.
 *
 * WHAT THIS DOES NOT CLAIM: a mismatch proves misrepresentation of the STANDARD, not fraud or intent. A
 * project may hold a vanity address for reasons of its own. What it does establish is that the token does not
 * carry the issuer controls, transfer policies, or compliance guarantees a B20 implies — so anyone treating
 * it as one is wrong about what they hold.
 *
 * Also relevant, and the reason RWA buyers should care in the other direction: a REAL B20 gives its issuer
 * freeze-and-seize powers at the standard level (a blocked holder's balance can be burned). That is a
 * capability no ERC-20 has and no ERC-20-shaped scanner looks for. Holding a genuine B20 is a different risk,
 * not a smaller one, and the two cases must be reported differently.
 */
const https = require('node:https');

const B20_PREFIX = '0xb200';
const NATIVE_CODE_MAX = 32;        // a precompile-backed token has ~0 bytes; anything real dwarfs this
const RPC = { base: 'https://mainnet.base.org' };

function rpc(url, method, params) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  return new Promise((resolve) => {
    const u = new URL(url);
    const req = https.request({ hostname: u.hostname, path: u.pathname, method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => {
      let d = ''; res.on('data', (c) => (d += c));
      res.on('end', () => { try { resolve(JSON.parse(d).result); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.end(body);
  });
}

/**
 * The canonical native layout is the prefix followed by a long run of zero bytes before the unique suffix —
 * the precompile factory assigns addresses, it does not grind them. A vanity address matches the prefix but
 * has random hex immediately after, so the zero run is the discriminator that survives even if code size
 * changes in a future upgrade.
 */
function zeroRunAfterPrefix(address) {
  const hex = String(address).toLowerCase().replace(/^0x/, '').slice(4);   // past 'b200'
  const m = hex.match(/^0*/);
  return m ? m[0].length : 0;
}

/**
 * classifyB20 — decide what a `0xb200…` address really is.
 * @returns { presentsAsB20, isNativeB20, impostor, codeBytes, zeroRun, verdict, reason }
 *   verdict: 'native_b20' | 'prefix_impostor' | 'not_b20' | 'unknown'
 */
async function classifyB20(chain, address, { rpcImpl } = {}) {
  const url = RPC[String(chain).toLowerCase()];
  const addr = String(address || '').toLowerCase();
  const presentsAsB20 = addr.startsWith(B20_PREFIX);
  if (!/^0x[0-9a-f]{40}$/.test(addr)) return { presentsAsB20: false, verdict: 'unknown', reason: 'not a well-formed address' };
  if (!url) return { presentsAsB20, verdict: 'unknown', reason: 'no RPC wired for chain "' + chain + '"' };

  const code = rpcImpl ? await rpcImpl(addr) : await rpc(url, 'eth_getCode', [addr, 'latest']);
  if (code == null) return { presentsAsB20, verdict: 'unknown', reason: 'could not read contract code' };
  const codeBytes = Math.max(0, (String(code).length - 2) / 2);
  const zeroRun = zeroRunAfterPrefix(addr);

  if (!presentsAsB20) return { presentsAsB20: false, isNativeB20: false, impostor: false, codeBytes, zeroRun,
    verdict: 'not_b20', reason: 'ordinary contract address — nothing claimed about the B20 standard' };

  const isNativeB20 = codeBytes <= NATIVE_CODE_MAX;
  if (isNativeB20) return { presentsAsB20: true, isNativeB20: true, impostor: false, codeBytes, zeroRun,
    verdict: 'native_b20',
    reason: 'native B20 (' + codeBytes + ' bytes of EVM code — the logic is a precompile). Its ISSUER can freeze and burn a blocked holder\'s balance at the standard level; that power is inherent to B20 and is not visible to ERC-20 scanners.' };

  return { presentsAsB20: true, isNativeB20: false, impostor: true, codeBytes, zeroRun,
    verdict: 'prefix_impostor',
    reason: 'wears the B20 address prefix but carries ' + codeBytes + ' bytes of ordinary contract code — a native B20 has none. It does NOT carry the issuer controls or transfer policies the standard implies. Landing on this prefix by chance is about 1 in 65,536.' };
}

module.exports = { classifyB20, zeroRunAfterPrefix, B20_PREFIX, NATIVE_CODE_MAX };
