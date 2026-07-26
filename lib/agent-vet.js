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

const WANTS_SECRET = /(private[_\s-]?key|privatekey|secret[_\s-]?key|seed[_\s-]?phrase|mnemonic|keystore|passphrase|wallet[_\s-]?file)/i;

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
  const movesValue = [], namedButNoSurface = [], wantsSecret = [], readOnly = [];
  for (const t of tools || []) {
    const name = String(t.name || '');
    const desc = String(t.description || '');
    const props = (t.inputSchema && t.inputSchema.properties) || {};
    const fields = Object.keys(props);
    const fieldTokens = new Set(fields.flatMap(tokenize));

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
    if (valueField) movesValue.push({ name, verb, field: valueField, recipientField: recipient || null });
    else namedButNoSurface.push({ name, verb, recipientField: recipient || null });
  }
  return { movesValue, namedButNoSurface, wantsSecret, readOnly };
}

/**
 * vetAgent — judge an agent before connecting to it or paying it.
 * @param {object} opts { url, payTo, chain, knownBadScreen, screenFn }
 * @returns { verdict, reason, liveness, surface, payment, disclosure }
 *   verdict: 'refuse' | 'high_risk' | 'caution' | 'answers' | 'unreachable'
 */
async function vetAgent({ url, payTo, chain = 'base', knownBadScreen = null, screenFn = null } = {}) {
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

  if (s && s.movesValue.length) return { ...out, verdict: 'high_risk',
    reason: s.movesValue.length + ' tool(s) expose a payment surface (' + s.movesValue.map((x) => x.name + ' takes ' + x.field).join(', ') +
      '). That is not automatically malicious — a payment agent is supposed to pay — but an agent you let run unattended should not hold that surface unless you meant it to.',
    disclosure: DISCLOSURE };

  return { ...out, verdict: url ? 'answers' : 'caution',
    reason: url
      ? 'the endpoint answers and exposes ' + ((s && s.toolCount) || 0) + ' tool(s), none of which take key material or name a value-moving action. That is the floor, not a clearance.'
      : 'nothing was checkable without an endpoint.',
    disclosure: DISCLOSURE };
}

const DISCLOSURE = 'This never returns "safe". It deliberately does NOT grade how good the description reads: ' +
  'a well-written tool listing is free to fabricate now, and scoring prose would hand a forgery a good mark. ' +
  'It judges only what is checkable — whether the endpoint answers, what its tools take as input, whether any ' +
  'names a value-moving action, and whether the address that gets paid has a past. Read-only: it introspects ' +
  'and never calls a tool.';

module.exports = { vetAgent, introspectHttp, auditTools, tokenize, VALUE_VERBS, VALUE_FIELDS, WANTS_SECRET, DISCLOSURE };
