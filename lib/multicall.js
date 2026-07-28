'use strict';
/**
 * multicall.js â€” ask the chain forty questions in one request.
 * ===========================================================
 * Built because the wallet guard was blind on roughly a third of its own perimeter. Reading forty allowances
 * meant forty sequential `eth_call`s against a public RPC, and eleven to thirteen of them came back empty
 * every run. The guard reported that blindness honestly, which is the minimum â€” but a guard that cannot see
 * a third of the doors is not a guard, and an attacker's approval could sit precisely in the unread set.
 * Rate limiting was the whole problem, so the fix is to stop making forty requests.
 *
 * Multicall3 sits at the same address on every chain that has it, verified on Base before a line of this was
 * written (3808 bytes of code, registry name "Multicall3"). `aggregate3` takes a list of (target, allowFailure,
 * calldata) and returns a list of (success, returnData), so one round trip replaces the batch and a single
 * reverting call cannot poison its neighbours.
 *
 * The ABI encoding here is written by hand rather than pulled from a library, because this codebase takes no
 * dependencies â€” so it is verified against values already known from the sequential path rather than trusted.
 * A response is not a correct response: the first hand-rolled attempt returned 770 bytes of plausible-looking
 * data, which proves only that the node answered something.
 */
const https = require('node:https');

const MULTICALL3 = '0xcA11bde05977b3631167028862bE2a173976CA11';
const AGGREGATE3 = '0x82ad56cb';
const RPC = { base: 'https://mainnet.base.org', ethereum: 'https://ethereum-rpc.publicnode.com' };
const MAX_PER_BATCH = 60;   // keep the calldata comfortably inside any node's request limits

const word = (n) => BigInt(n).toString(16).padStart(64, '0');
const addrWord = (a) => String(a).toLowerCase().replace(/^0x/, '').padStart(64, '0');

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

/**
 * Encode aggregate3((address,bool,bytes)[]). Dynamic structs, so the array is a list of offsets followed by
 * the structs themselves â€” each of which is in turn (address, bool, offset-to-bytes, length, padded data).
 */
function encodeAggregate3(calls) {
  const structs = calls.map((c) => {
    const cd = String(c.callData).replace(/^0x/, '');
    const padded = cd.padEnd(Math.ceil(cd.length / 64) * 64, '0');
    return addrWord(c.target) + word(c.allowFailure ? 1 : 0) + word(96) + word(cd.length / 2) + padded;
  });
  // Offsets are measured from the start of the array's element region, past the offset table itself.
  let cursor = 32 * structs.length;
  const offsets = structs.map((s) => { const at = cursor; cursor += s.length / 2; return word(at); });
  return AGGREGATE3 + word(32) + word(structs.length) + offsets.join('') + structs.join('');
}

const HEX_WORD = /^[0-9a-f]{64}$/;

/**
 * Decode (bool success, bytes returnData)[] back into a flat list, preserving input order.
 *
 * âš ï¸ THIS FUNCTION READ ITS INPUT AS IF THE INPUT WERE ALREADY TRUSTED â€” in a file whose own header says
 * "a response is not a correct response: the first hand-rolled attempt returned 770 bytes of
 * plausible-looking data, which proves only that the node answered something." Measured 2026-07-29, three
 * ways of not being ABI data and three different wrong outcomes:
 *
 *   a word that is not hex          -> SyntaxError THROWN out of multiCall, killing the whole batch
 *   truncated just before the data  -> { data: '0x' }, which allowancesBatch reads as a definitive revert
 *   dataLen says 32, 8 bytes remain -> allowance 123456789 decoded as 0        <- A WRONG NUMBER
 *
 * The third is the one that matters. It is not an error and not a null: it is a plausible answer. And it
 * does not stay local â€” `approvals` then declares the sweep `complete`, `wallet-watch` replaces its stored
 * reference, and the next run reports the real allowance as "NEW approval, someone granted it since". A
 * missing byte becomes an accusation that a third party signed something.
 *
 * So every word is now bounds- and hex-checked before it is read, every offset must be a multiple of 32,
 * and a declared length must actually BE present. Any of those failing yields `null` â€” the module's
 * existing, disclosed meaning for "unread", which the caller already distinguishes from "empty".
 */
function decodeAggregate3(hex, expected) {
  const h = String(hex).replace(/^0x/, '').toLowerCase();
  if (h.length < 128) return null;
  // A word that is not a full 64 hex characters means the response ended early, or carries something that
  // is not ABI data. Both are UNREAD; reading either with BigInt throws out of the entire batch.
  const at = (i) => { const s = h.slice(i * 64, (i + 1) * 64); return HEX_WORD.test(s) ? s : null; };
  const num = (i) => { const s = at(i); return s === null ? null : Number(BigInt('0x' + s)); };
  /* ⚠️ `% 32 !== 0` EST REDONDANT ET C'EST ECRIT ICI PLUTOT QUE CACHE. Mesure du 2026-07-29: en le
   * retirant, les trois formes desalignees (tableau, struct, donnee) rendent `null` quand meme — un indice
   * fractionnaire finit toujours par produire une tranche qui n'est pas 64 caracteres hex, et `at()` la
   * refuse. La mutation qui l'enleve SURVIT donc a la suite. Gardee comme precondition explicite, pas
   * comme protection prouvee: la prochaine personne qui la lit doit savoir qu'aucun test ne la tient. */
  const offset = (i) => { const n = num(i); return n === null || n % 32 !== 0 ? null : n / 32; };

  const arrayAt = offset(0);                                   // offset to the array
  if (arrayAt === null) return null;
  const len = num(arrayAt);
  if (len === null || len !== expected) return null;           // shape mismatch: refuse rather than guess
  const out = [];
  for (let i = 0; i < len; i++) {
    const structOff = offset(arrayAt + 1 + i);
    if (structOff === null) return null;
    const structAt = arrayAt + 1 + structOff;
    const successWord = at(structAt);
    if (successWord === null) return null;
    const success = BigInt('0x' + successWord) === 1n;
    const dataOff = offset(structAt + 1);
    if (dataOff === null) return null;
    const dataAt = structAt + dataOff;
    const dataLen = num(dataAt);
    if (dataLen === null) return null;
    const start = (dataAt + 1) * 64;
    // The declared length must actually be there. Without this the tail was silently short and the number
    // decoded SMALLER instead of failing â€” a zero-length return, which is a real answer, stays '0x'.
    if (h.length - start < dataLen * 2) return null;
    const data = dataLen ? '0x' + h.slice(start, start + dataLen * 2) : '0x';
    out.push({ success, data });
  }
  return out;
}

/**
 * multiCall â€” run many read-only calls in as few round trips as possible.
 * @param {string} chain
 * @param {Array<{target:string, callData:string}>} calls
 * @returns {Promise<Array<{success:boolean,data:string}|null>>} same order as input; null where the batch itself failed
 */
async function multiCall(chain, calls) {
  const rpc = RPC[String(chain).toLowerCase()];
  if (!rpc || !calls.length) return calls.map(() => null);
  const out = [];
  for (let i = 0; i < calls.length; i += MAX_PER_BATCH) {
    const slice = calls.slice(i, i + MAX_PER_BATCH).map((c) => ({ ...c, allowFailure: true }));
    let decoded = null;
    for (let attempt = 0; attempt < 3 && !decoded; attempt++) {
      const res = await post(rpc, { jsonrpc: '2.0', id: 1, method: 'eth_call',
        params: [{ to: MULTICALL3, data: encodeAggregate3(slice) }, 'latest'] });
      // Belt and braces: the decoder is written not to throw, but if it ever does, a single malformed
      // response must not take the batch â€” and the calls it would have read â€” down with it. `null` here
      // means exactly what it means everywhere else in this file: unread.
      if (res && typeof res.result === 'string') {
        try { decoded = decodeAggregate3(res.result, slice.length); } catch { decoded = null; }
      }
      if (!decoded) await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
    }
    // A failed BATCH yields nulls, never zeros â€” the caller must be able to tell "unread" from "empty",
    // which is the distinction that made the approval sweep honest in the first place.
    out.push(...(decoded || slice.map(() => null)));
  }
  return out;
}

/** allowance(owner, spender) for many (token, spender) pairs, in one or two round trips. */
async function allowancesBatch(chain, owner, pairs) {
  const calls = pairs.map(({ token, spender }) => ({
    target: token,
    callData: '0xdd62ed3e' + addrWord(owner) + addrWord(spender),
  }));
  const res = await multiCall(chain, calls);
  // Three return kinds on purpose. A BigInt is an answer; `null` means the node never answered and the pair
  // is genuinely unread; `false` means the call REVERTED, which is itself a definitive answer â€” the target
  // has no allowance() to read, or the pair is nonsense. Folding the last two together made one garbage
  // Approval event keep the whole sweep permanently short of "complete".
  return res.map((r) => {
    if (!r) return null;
    if (!r.success || r.data === '0x') return false;
    /* UN QUATRIEME CAS: `success` vrai et donnee non vide, mais qui ne se decode pas. L'appel a abouti,
     * son retour est illisible â€” c'est un NON-LU, pas un revert. Le classer en `false` (Â« repondu
     * definitivement: aucune allocation Â») laissait approvals.js declarer le balayage `complete`, ce qui
     * autorisait wallet-watch a remplacer sa reference et a rapporter ensuite une allocation jamais lue
     * comme Â« nouvellement accordee Â». Corrige dans biii le 2026-07-27; porte ici le meme jour. */
    try { return BigInt(r.data); } catch { return null; }
  });
}

module.exports = { multiCall, allowancesBatch, encodeAggregate3, decodeAggregate3, MULTICALL3 };
