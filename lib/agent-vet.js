'use strict';
/**
 * agent-vet.js — is this agent safe to connect to, and safe to pay?
 * =================================================================
 * The rest of this repository judges tokens, launches, thefts, offers and wallets. It never judged AGENTS,
 * which is the odd gap, because an agent is the thing that actually holds the tools. And it cuts both ways:
 * this node exposes 25 MCP tools, and nothing lets a stranger verify that they are read-only.
 *
 * Four things make an agent dangerous, and every one is checkable without trusting a word of its description:
 *
 *   1. IT DOES NOT EXIST. Paying an endpoint that never answers is the simplest loss there is, and a listing
 *      is not a service — a scanner audited this week called five platform APIs and every one was dead, one
 *      of them a domain that does not resolve, while it went on producing confident summaries.
 *   2. ITS TOOLS CAN MOVE MONEY. A tool named `portfolio_action` that sends is indistinguishable from one
 *      that reads, until you read the schema. Names are marketing; the surface is what the agent can do.
 *   3. IT ASKS FOR KEY MATERIAL. An input schema with a field for a private key or seed phrase is the whole
 *      attack, declared in the open. Nothing legitimate needs one.
 *   4. IT IS PAID TO AN ADDRESS WITH NO PAST. Take the payment, vanish. The address is checkable before
 *      anything moves.
 *
 * WHAT THIS DELIBERATELY REFUSES TO DO: score how good the description reads. That lesson was expensive — a
 * 35-question production dossier citing real work fooled someone who verifies counterparties professionally,
 * because effort used to cost human hours and no longer does. A well-written tool listing is now free to
 * fabricate, so grading prose would hand a forgery a good mark. Only the surface and the money are judged.
 *
 * Read-only. It connects, asks what the agent can do, and never calls a tool.
 */
const https = require('node:https');
const { spawn } = require('node:child_process');

// Verbs that mean an agent can move value.
//
// Matched against TOKENS, not with \b, because the first version used word boundaries and caught zero of nine
// obvious cases: in `wallet_transfer` the character before "transfer" is an underscore, which regex counts as
// a word character, so there is no boundary and no match. MCP tool names are almost universally snake_case,
// so that single detail made the check report "no value-moving tools" on an endpoint exposing a send tool —
// a false clearance, which is worse than no check at all.
const VALUE_VERBS = new Set(['send', 'transfer', 'swap', 'sign', 'approve', 'withdraw', 'bridge', 'stake',
  'unstake', 'mint', 'burn', 'buy', 'sell', 'trade', 'execute', 'settle', 'pay', 'tip', 'deposit', 'claim']);
// Fields that turn a value-moving NAME into a value-moving SURFACE. The schema is the capability.
//
// Only QUANTITY fields are triggers, and the reason is worth stating because the first version got it wrong:
// a recipient is not evidence. `to`, `recipient` and `destination` were in this set, and our own endpoint's
// message-sending tool tripped it — a message has a recipient exactly as a payment does. What a payment
// cannot do without is a quantity: you cannot move value without saying how much. The amount is mechanically
// necessary, the recipient is not, so the amount is what discriminates.
const VALUE_FIELDS = new Set(['amount', 'amountusd', 'amountmicro', 'amountwei', 'value', 'wei',
  'quantity', 'qty', 'sum', 'lamports', 'satoshis']);
// Kept as CONTEXT only — reported alongside a real amount to describe the surface, never as a trigger.
const RECIPIENT_FIELDS = new Set(['recipient', 'to', 'payto', 'destination', 'receiver', 'dest']);

// Fields that mean "the caller had to authorize this themselves". Only these disarm a payment surface, and
// only when REQUIRED. Note what is absent: `apikey`, `token`, `bearer`, `password`. Those authorize the AGENT,
// standing credentials it already holds, which is the unattended case this whole check exists to catch —
// putting them here would turn the gate into a rubber stamp for every drainer with an auth header.
const CALLER_AUTHORIZED = new Set(['signature', 'sig', 'signedmessage', 'signedtx', 'signedtransaction',
  'permit', 'authorization', 'attestation', 'voucher']);

// Fields that mean "this tool WITNESSES a payment that already happened rather than causing one". A required
// transaction HASH is a backward reference: it names a transaction that is already confirmed, and a hash
// cannot be broadcast. That is the exact line — a hash points at the past, a raw signed transaction acts on
// the future — which is why `signedtx` is in the set above and deliberately not in this one.
//
// A caution about where this came from, because it matters to whether you should believe it. This category
// was added while auditing our OWN endpoints, where the check had flagged a settlement-recording tool. That
// is precisely the situation in which a false-positive story is most tempting, so the test applied was
// whether the reasoning would be accepted for a stranger's server: can an agent holding only this tool move
// value? It cannot — it can assert that a payment occurred, and the assertion is checked against the chain.
//
// The residual risk is real but different, and is named rather than dissolved: a witness tool can claim a
// payment that did not happen. That is a false-record risk, not a drain risk, and a check about unattended
// spending has no business pretending to cover it.
const WITNESSES_PAYMENT = new Set(['txhash', 'transactionhash', 'txid', 'transactionid', 'receipt',
  'receipthash', 'settlementtx', 'settlementhash', 'proofoftransfer']);

const WANTS_SECRET = /(private[_\s-]?key|privatekey|secret[_\s-]?key|seed[_\s-]?phrase|mnemonic|keystore|passphrase|wallet[_\s-]?file)/i;

/**
 * Browser control: a capability that is dangerous by COMPOSITION and that no schema declares.
 *
 * Found by pointing this checker at a real trending project whose pitch is "your agent inherits your existing
 * logins, cookies, extensions and bookmarks", with in-page tools named snapshot, fill, click, wait, navigate,
 * capture. All six land in `readOnly` here, and that is not a bug in the matching — it is the two-condition rule
 * working exactly as written. A value VERB is required in the name before the schema is examined at all, and
 * browser automation has no value verb by design. `fill` even carries a `value` field, which IS in VALUE_FIELDS,
 * and it is never reached.
 *
 * The danger is not in any tool. It is in what the browser can REACH: a profile holding a wallet extension. An
 * agent that can navigate and click inside that profile can drive the wallet's own interface, which is a
 * payment surface that no input schema will ever advertise.
 *
 * So this does not flag browser control as dangerous — that would fire on every legitimate web-automation agent
 * and get the tool muted, the failure mode this codebase keeps refusing. It flags the COMBINATION, and the
 * second half is checkable: `localVaults` comes from the caller (see keyscan's findVaults) and says whether a
 * browser wallet vault actually exists on this machine. Browser control on a clean container is ordinary
 * automation. The same tools pointed at a profile with 27 MB of MetaMask state is something else.
 */
// Keyed on SCHEMA FIELDS, not on verbs — and the first version was keyed on verbs, which is the mistake this
// whole file is a monument to. `open` and `execute` are the two most generic verbs in software, so a set built
// around them fired on five of six honest tool sets: a trading agent (open_position + execute_order), a file
// manager (open_file + type_text), a database client (open_connection + execute_query), a terminal
// (open_shell + execute_command) and a CI runner (open_pr + execute_workflow). Every one of those would have
// been told it can drive a wallet. That is the noise that gets a security tool muted, reached for a THIRD time
// in the module whose opening rule is that names are marketing and the schema is the capability.
//
// The real tell is a parameter. A SELECTOR — css, xpath, a DOM ref — exists for exactly one purpose: reaching
// into a rendered page. `open_file` takes a path, `execute_query` takes sql, `open_position` takes a size.
// None of them take a selector, because none of them touch a DOM.
const REACH_NAME = /(navigate|goto|browse|visit)/i;
const REACH_FIELDS = new Set(['url', 'href', 'link', 'address', 'uri']);
// Split by how much the field alone proves, because one of them collides. STRONG fields exist only to address
// something rendered on a screen. WEAK ones are real browser fields that other domains also use — `ref` is a
// DOM handle in one MCP and a git branch in another — so they count only inside a tool set that also has a
// browser-specific navigation tool, which the caller already requires.
const DOM_FIELDS_STRONG = new Set(['selector', 'xpath', 'css', 'cssselector', 'locator', 'testid',
  'elementid', 'nodeid', 'coordinate', 'coordinates', 'domid']);
const DOM_FIELDS_WEAK = new Set(['ref', 'element', 'aria', 'node', 'handle']);
const DOM_FIELDS = new Set([...DOM_FIELDS_STRONG, ...DOM_FIELDS_WEAK]);
const ACT_NAME = /(click|fill|type|press|select|submit|tap|drag|hover|keyboard|mouse|evaluate)/i;

/**
 * Two halves are needed: reaching a page, and acting inside one. Either alone is not control — a fetcher that
 * only navigates cannot press a button, and a clicker with no navigation is bound to wherever it already is.
 */
function detectBrowserControl(tools) {
  const reach = [], act = [];
  for (const t of tools || []) {
    const name = String(t.name || '');
    const fields = new Set(Object.keys((t.inputSchema && t.inputSchema.properties) || {})
      .map((f) => f.toLowerCase().replace(/[^a-z0-9]/g, '')));
    const hasDom = [...fields].some((f) => DOM_FIELDS.has(f));
    const hasUrl = [...fields].some((f) => REACH_FIELDS.has(f));

    // Reaching a page: it has to be about a URL. Either the name says navigation, or a url field plus a
    // navigational name — never a bare `url` field, since half of all tools take one.
    if (REACH_NAME.test(name) && (hasUrl || !fields.size)) reach.push(name);
    // Acting inside a page. A DOM field decides on its own, WITHOUT the name having to agree — requiring the
    // name too was a false NEGATIVE, and on a security check that is the worse direction. Our own Chrome MCP
    // slipped through it: its action tools are called `computer` and `form_input`, which match no action verb,
    // while taking `ref` and `coordinate`. A browser-driving surface that this check calls read-only is exactly
    // the confident wrong answer the rest of this module exists to avoid.
    if (hasDom) act.push(name);
    else if (ACT_NAME.test(name) && !fields.size) act.push(name);   // in-page idiom: `click` with no schema
  }
  return reach.length && act.length ? { reach, act } : null;
}

/** Split an identifier into lowercase words: snake_case, kebab-case, camelCase and dotted names all included. */
function tokenize(s) {
  return String(s || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

const post = (url, body, timeout = 12000) => new Promise((resolve) => {
  const data = JSON.stringify(body);
  const u = new URL(url);
  const req = https.request({ hostname: u.hostname, path: u.pathname + (u.search || ''), method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
      'content-length': Buffer.byteLength(data) }, timeout }, (res) => {
    let d = ''; res.on('data', (c) => (d += c));
    res.on('end', () => resolve({ status: res.statusCode, body: d }));
  });
  req.on('timeout', () => { req.destroy(); resolve(null); });
  req.on('error', () => resolve(null));
  req.end(data);
});

/** Parse an MCP reply whether it came back as plain JSON or as a server-sent-events frame. */
function parseMcp(raw) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { /* fall through */ }
  const line = String(raw).split('\n').find((l) => l.startsWith('data:'));
  if (!line) return null;
  try { return JSON.parse(line.slice(5).trim()); } catch { return null; }
}

/** Ask an HTTP MCP endpoint what it can do. Never calls a tool. */
async function introspectHttp(url) {
  const init = await post(url, { jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'agent-vet', version: '1' } } });
  if (!init) return { reachable: false, reason: 'no response — the endpoint did not answer at all' };
  // 401 and 403 are not absence. They mean the agent is there and gated, which is a different fact and a
  // different decision: an unauthenticated stranger cannot audit it, but it is running. Reporting that as
  // "unreachable" is the same error this codebase keeps finding elsewhere — treating "I could not see" as
  // "there is nothing there". Found by surveying the public registry, where most listed servers answer 401.
  if (init.status === 401 || init.status === 403) {
    return { reachable: true, gated: true, status: init.status, tools: null,
      reason: 'HTTP ' + init.status + ' — the agent exists but requires credentials, so its tool surface cannot be audited from outside' };
  }
  if (init.status !== 200) return { reachable: false, reason: 'HTTP ' + init.status, status: init.status };
  const parsedInit = parseMcp(init.body);
  const list = await post(url, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const parsedList = parseMcp(list && list.body);
  const tools = (parsedList && parsedList.result && parsedList.result.tools) || null;
  return {
    reachable: true,
    serverInfo: (parsedInit && parsedInit.result && parsedInit.result.serverInfo) || null,
    tools,
    reason: tools ? null : 'answered initialize but returned no tool list',
  };
}

/**
 * Read every tool's surface. A description is a claim; an input schema is a capability, so both are scanned
 * but only the schema can prove what the tool takes.
 */
function auditTools(tools) {
  const movesValue = [], callerSigned = [], witnessesPayment = [], namedButNoSurface = [], wantsSecret = [], readOnly = [];
  for (const t of tools || []) {
    const name = String(t.name || '');
    const desc = String(t.description || '');
    const schema = t.inputSchema || {};
    const props = schema.properties || {};
    const fields = Object.keys(props);
    const fieldTokens = new Set(fields.flatMap(tokenize));
    // What the schema DEMANDS, not merely what it accepts. The distinction is the whole gate below.
    const requiredList = Array.isArray(schema.required) ? schema.required : [];
    const required = new Set(requiredList.flatMap(tokenize));
    // Whole names too, normalised. `txHash` tokenizes to `tx` + `hash`, and neither token alone means anything
    // safe — `tx` on its own could be a raw transaction to broadcast. The compound is what carries the meaning.
    const requiredNames = new Set(requiredList.map((f) => String(f).toLowerCase().replace(/[^a-z0-9]/g, '')));

    // Only the SCHEMA is searched for secrets, not the description. This module's own file mentions "private
    // key" and "seed phrase" repeatedly while asking for neither, and so do good security tools — scanning
    // prose would flag every honest one.
    if (WANTS_SECRET.test(fields.join(' '))) { wantsSecret.push({ name, where: 'input schema' }); continue; }

    const verb = tokenize(name).find((w) => VALUE_VERBS.has(w));
    if (!verb) { readOnly.push(name); continue; }

    // A value verb in the name plus a value field in the schema is a payment surface. The verb alone is a
    // label: `lawbor_m1_send` sends a message, and calling that a money-moving tool would be the kind of
    // false alarm that gets a security tool muted.
    const valueField = [...fieldTokens].find((f) => VALUE_FIELDS.has(f));
    const recipient = [...fieldTokens].find((f) => RECIPIENT_FIELDS.has(f));
    if (!valueField) { namedButNoSurface.push({ name, verb, recipientField: recipient || null }); continue; }

    // A payment surface only counts against an agent if the AGENT can fire it.
    //
    // This is the same rule `rugsignals.js` applies to contracts — a dangerous capability is inert if nobody
    // can still trigger it — and it was missing here until the tool returned `high_risk` on an endpoint whose
    // tip tool cannot move a cent without an EIP-712 signature the caller has to produce. The signature is the
    // agent-tool equivalent of renounced ownership: the wallet still decides, so an unattended agent holding
    // this tool cannot drain anything. I had written the principle for rug powers and failed to carry it
    // across, which is why a second use of a rule is worth as much scrutiny as the first.
    //
    // The gate is deliberately narrow, because a loose reading of it would excuse every payment tool on earth:
    //   - the field must be REQUIRED, not merely accepted. An optional signature gates nothing.
    //   - it must be an authorization the CALLER supplies. An `apiKey` the operator configures does not count:
    //     that authorizes the agent, which is precisely the unattended case being tested for.
    // What this cannot see is whether the server actually verifies the signature. That is off-chain code and
    // unauditable from outside, so the finding is reported as a described gate, never as proof of one.
    // Matched against BOTH the tokens and the whole normalised names. A single-word field like `sig` only
    // exists as a token; a compound like `signedTx` only exists as a whole name, because tokenize splits it
    // into `signed` + `tx` and neither half is in the set. Checking tokens alone silently missed every
    // compound entry — the third time in this file that splitting an identifier quietly disabled a rule, after
    // `\bsend\b` never matching `wallet_transfer`. The truth table caught it on the run it was written.
    const gate = [...required].find((f) => CALLER_AUTHORIZED.has(f)) ||
                 [...requiredNames].find((f) => CALLER_AUTHORIZED.has(f));
    if (gate) { callerSigned.push({ name, verb, field: valueField, recipientField: recipient || null, gate }); continue; }

    // Or the tool witnesses a payment instead of causing one. Checked AFTER the signature gate, so a tool
    // carrying both is reported as caller-signed — the stronger and more specific of the two claims.
    const witness = [...requiredNames].find((f) => WITNESSES_PAYMENT.has(f));
    if (witness) { witnessesPayment.push({ name, verb, field: valueField, recipientField: recipient || null, witness }); continue; }

    movesValue.push({ name, verb, field: valueField, recipientField: recipient || null });
  }
  return { movesValue, callerSigned, witnessesPayment, namedButNoSurface, wantsSecret, readOnly };
}

/**
 * vetAgent — judge an agent before connecting to it or paying it.
 * @param {object} opts { url, payTo, chain, knownBadScreen, screenFn }
 * @returns { verdict, reason, liveness, surface, payment, disclosure }
 *   verdict: 'refuse' | 'high_risk' | 'caution' | 'answers' | 'unreachable'
 */
async function vetAgent({ url, payTo, chain = 'base', knownBadScreen = null, screenFn = null,
  localVaults = null } = {}) {
  const out = { url: url || null, payTo: payTo || null };

  // 1. Liveness first. Everything else is moot if nothing is there, and this is the cheapest check.
  const live = url ? await introspectHttp(url) : { reachable: null, reason: 'no endpoint given, so liveness was not tested' };
  out.liveness = live;
  if (url && !live.reachable) {
    return { ...out, verdict: 'unreachable',
      reason: 'the endpoint did not answer (' + live.reason + '). A listing is not a service, and paying one that does not respond is the simplest loss available.',
      disclosure: DISCLOSURE };
  }
  if (live.gated) {
    return { ...out, verdict: 'unauditable',
      reason: live.reason + '. It is running — that is more than many listings manage — but nothing about what its tools can do is verifiable without an account, so this is neither a pass nor a fail.',
      disclosure: DISCLOSURE };
  }

  // 2. The surface: what can it actually do?
  out.surface = live.tools ? auditTools(live.tools) : null;
  out.browserControl = live.tools ? detectBrowserControl(live.tools) : null;
  if (live.tools) out.surface.toolCount = live.tools.length;

  // 3. The money: who gets paid, and do they have a past?
  if (payTo) {
    const screened = (screenFn && knownBadScreen) ? screenFn(payTo, knownBadScreen) : null;
    const info = await new Promise((resolve) => {
      https.get('https://base.blockscout.com/api/v2/addresses/' + payTo, { headers: { accept: 'application/json' } }, (res) => {
        let d = ''; res.on('data', (c) => (d += c));
        res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      }).on('error', () => resolve(null));
    });
    out.payment = {
      knownBad: !!(screened && screened.blocked),
      flaggedScam: !!(info && info.is_scam),
      isContract: !!(info && info.is_contract),
      verified: !!(info && info.is_verified),
      resolved: !!info,
    };
  }

  // ---- verdict ----------------------------------------------------------------------------------------
  const s = out.surface, p = out.payment;
  if (s && s.wantsSecret.length) return { ...out, verdict: 'refuse',
    reason: 'a tool asks for key material (' + s.wantsSecret.map((x) => x.name + ' — in its ' + x.where).join('; ') +
      '). Nothing legitimate needs a private key or seed to do its job. This is the attack, declared in the open.',
    disclosure: DISCLOSURE };

  if (p && p.knownBad) return { ...out, verdict: 'refuse',
    reason: 'the address that would be paid is on the local known-bad list.', disclosure: DISCLOSURE };
  if (p && p.flaggedScam) return { ...out, verdict: 'high_risk',
    reason: 'the address that would be paid carries a scam reputation on the explorer.', disclosure: DISCLOSURE };

  // A caller-signed payment surface never escalates, and is never dropped either. It is reported on every
  // verdict below, including the clean ones, because "we found a tip tool and decided it was fine" is
  // information the reader is entitled to disagree with. Silently swallowing a finding you resolved yourself
  // is how a scanner starts hiding the reasoning that makes it worth trusting.
  if (s && s.callerSigned.length) {
    out.gatedPayment = s.callerSigned.map((x) => x.name + ' takes ' + x.field + ' but REQUIRES ' + x.gate +
      ' from the caller, so the agent cannot fire it alone — as described by its schema, which is not proof the server enforces it');
  }
  if (s && s.witnessesPayment.length) {
    out.witnessedPayment = s.witnessesPayment.map((x) => x.name + ' takes ' + x.field + ' but REQUIRES ' + x.witness +
      ', so it records a payment that already happened rather than causing one — a hash cannot be broadcast. ' +
      'The residual risk is a FALSE RECORD, not a drain, and this check does not cover false records');
  }

  // Browser control plus a wallet vault on this machine. Checked BEFORE the declared payment surfaces, because
  // this one is invisible to every schema and a reader who stops at "no tool takes an amount" will miss it.
  const bc = out.browserControl;
  if (bc && Array.isArray(localVaults) && localVaults.length) {
    const wallets = [...new Set(localVaults.map((v) => v.wallet))].join(', ');
    return { ...out, verdict: 'high_risk',
      reason: 'No tool here declares a payment surface, and that is not the finding. This agent can reach a page (' +
        bc.reach.join(', ') + ') and act on it (' + bc.act.join(', ') + '), and this machine has ' +
        localVaults.length + ' browser wallet vault(s) on disk (' + wallets + '). An agent driving a profile that ' +
        'holds a wallet extension can drive the WALLET, which is a payment surface no input schema will ever ' +
        'advertise. The danger is the combination, not either half: the same tools against a clean profile are ' +
        'ordinary web automation.',
      disclosure: DISCLOSURE };
  }
  if (bc) {
    out.note = 'This agent can reach a page (' + bc.reach.join(', ') + ') and act on it (' + bc.act.join(', ') +
      '). Browser control is a payment surface by COMPOSITION when the profile it drives holds a wallet ' +
      'extension — no vault was reported to this check, so nothing is claimed. If you run it against your own ' +
      'logged-in browser, judge it as if it held every permission that browser holds.';
  }

  if (s && s.movesValue.length) return { ...out, verdict: 'high_risk',
    reason: s.movesValue.length + ' tool(s) expose a payment surface the agent can fire by itself (' +
      s.movesValue.map((x) => x.name + ' takes ' + x.field).join(', ') +
      '). That is not automatically malicious — a payment agent is supposed to pay — but an agent you let run unattended should not hold that surface unless you meant it to.',
    disclosure: DISCLOSURE };

  // The passing reason is assembled from what was actually found rather than asserted as a blanket all-clear.
  // Its first draft read "none of which name a value-moving action" and stayed hardcoded once the caller-signed
  // gate landed — so on our own endpoint it claimed no tool named a value-moving action while `surface` in the
  // same response listed a tip tool and a send tool that do. A verdict line that contradicts its own evidence
  // is worse than a wrong verdict, because a reader who checks stops believing the parts that were right.
  let why = '';
  if (url) {
    const named = ((s && s.callerSigned) || []).length + ((s && s.witnessesPayment) || []).length +
      ((s && s.namedButNoSurface) || []).length;
    why = 'the endpoint answers and exposes ' + ((s && s.toolCount) || 0) + ' tool(s). None asks for key ' +
      'material, and none can move value on the agent\'s own authority. ';
    why += named
      ? named + ' name a value-moving action without an unattended payment surface — see `surface` and ' +
        '`gatedPayment` for exactly which, and judge them yourself. '
      : 'No tool names a value-moving action at all. ';
    why += 'That is the floor, not a clearance.';
  } else {
    why = 'nothing was checkable without an endpoint.';
  }
  return { ...out, verdict: url ? 'answers' : 'caution', reason: why, disclosure: DISCLOSURE };
}

const DISCLOSURE = 'This never returns "safe". It deliberately does NOT grade how good the description reads: ' +
  'a well-written tool listing is free to fabricate now, and scoring prose would hand a forgery a good mark. ' +
  'It judges only what is checkable — whether the endpoint answers, what its tools take as input, whether any ' +
  'names a value-moving action, and whether the address that gets paid has a past. Read-only: it introspects ' +
  'and never calls a tool.';

module.exports = { vetAgent, introspectHttp, auditTools, detectBrowserControl, tokenize, VALUE_VERBS, VALUE_FIELDS, WANTS_SECRET, DISCLOSURE };
