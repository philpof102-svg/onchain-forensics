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

/**
 * ═══ THE MARKER IS EXACT, AND THE EVM ENFORCES IT ═══
 *
 * A native B20 account's code is not merely SHORT — it is the single byte `0xEF`. Measured 2026-07-27 by
 * raw eth_getCode against Base mainnet on several native tokens (MECHACOIN 0xb200…602c95f70b5d3aea2d and
 * STEAKHOUSE 0xb200…d3cb2af1e481a8b072 both return exactly `0xef`).
 *
 * And that marker cannot be forged: **EIP-3541 forbids deploying any runtime code beginning with 0xEF**.
 * Verified by experiment, not by reading the spec: a state-override CREATE with runtime `0xEF` returns the
 * zero address (rejected), while an identical CREATE with runtime `0x00` succeeds. So an ordinary contract
 * can grind a vanity address onto the b200 prefix, but it can NEVER present the native marker.
 *
 * ═══ WHY THE OLD THRESHOLD WAS A HOLE, AND NOT A SMALL ONE ═══
 * This used to be `codeBytes <= 32`. Demonstrated against the shipped classifier the same day:
 *
 *     code 0xef                -> native_b20   correct
 *     code 0x00  (1 byte)      -> native_b20   FALSE POSITIVE
 *     code 0xff  (1 byte)      -> native_b20   FALSE POSITIVE
 *     32 bytes of real code    -> native_b20   FALSE POSITIVE
 *
 * Three false positives out of four. Thirty-two bytes is ample for a minimal proxy delegating to arbitrary
 * logic, so an attacker never needed to forge 0xEF — only to stay under our threshold. The repair is not a
 * lower threshold, it is having none: an exact match on a marker the EVM will not let anyone else deploy.
 *
 * The constant is kept and exported because the loose check is precisely what we now refuse, and a reader
 * comparing this file against an older copy deserves to find the reason rather than a silent deletion.
 */
const NATIVE_CODE = '0xef';
const NATIVE_CODE_MAX = 32;        // RETIRED as a verdict input — see above. Kept for the historical note.
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

  /* EXACT match on the protocol marker — never a size threshold. See the NATIVE_CODE note at the top:
   * a threshold let anything 32 bytes or under through, which is ample for a minimal proxy delegating to
   * arbitrary logic. EIP-3541 makes this comparison something the EVM enforces rather than something we
   * hope holds. */
  const isNativeB20 = String(code).toLowerCase() === NATIVE_CODE;
  if (isNativeB20) return { presentsAsB20: true, isNativeB20: true, impostor: false, codeBytes, zeroRun,
    marker: NATIVE_CODE,
    verdict: 'native_b20',
    reason: 'native B20 — its account code is exactly ' + NATIVE_CODE + ', the protocol marker, and the logic is a precompile. '
      + 'EIP-3541 forbids DEPLOYING any contract whose runtime code starts with 0xEF, so this marker cannot be forged by an ordinary contract. '
      + 'Note this is NOT the safe outcome: the ISSUER of a native B20 can freeze and burn a blocked holder\'s balance at the standard level, '
      + 'a power no ERC-20 has and no ERC-20 scanner looks for.' };

  return { presentsAsB20: true, isNativeB20: false, impostor: true, codeBytes, zeroRun,
    marker: String(code).slice(0, 6),
    verdict: 'prefix_impostor',
    reason: 'wears the B20 address prefix but its account code is ' + codeBytes + ' byte(s) starting ' + String(code).slice(0, 12)
      + ' — a native B20 carries exactly ' + NATIVE_CODE + ' and nothing else. It does NOT carry the issuer controls or transfer policies '
      + 'the standard implies. Landing on this prefix by chance is about 1 in 65,536, so it is far more likely to be ground on purpose.' };
}

module.exports = { classifyB20, zeroRunAfterPrefix, B20_PREFIX, NATIVE_CODE, NATIVE_CODE_MAX };
