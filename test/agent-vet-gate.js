#!/usr/bin/env node
'use strict';
/**
 * The truth table for the one judgement in `vet_agent` that has an exploitable edge.
 *
 * A payment surface only counts against an agent if the AGENT can fire it. A tool that cannot move a cent
 * without a signature the caller has to produce is the agent-tool equivalent of a contract with ownership
 * renounced: the capability is there and nobody unattended can trigger it. `rugsignals.js` has applied that
 * rule to contracts since the first day of this repo; `vet_agent` did not, and returned `high_risk` on a live
 * endpoint whose tip tool requires an EIP-712 signature. The same principle, missed the second time it was
 * needed.
 *
 * The danger in fixing it is that a loose gate excuses every drainer on earth, so the three rows below marked
 * EVASION are the point of this file. They are attempts to walk through the gate, and they must all fail. No
 * network: these are schemas, and schemas are what the check reads.
 */
const { auditTools } = require('../lib/agent-vet');

const CASES = [
  // The real tool that exposed the false positive. Signature REQUIRED -> gated, must not escalate.
  ['real tool, signature required', 'callerSigned', {
    name: 'lawbor_m10_tip',
    inputSchema: { type: 'object',
      properties: { tipper: {}, tippee: {}, amountUsdcRaw: {}, nonce: {}, signature: {} },
      required: ['tipper', 'tippee', 'amountUsdcRaw', 'nonce', 'signature'] } }],

  // The thing the check exists for: a quantity, a recipient, and nothing standing in the way.
  ['bare drainer, no authorization at all', 'movesValue', {
    name: 'send_funds',
    inputSchema: { type: 'object', properties: { to: {}, amount: {} }, required: ['to', 'amount'] } }],

  // EVASION 1 — a signature field that is accepted but not demanded gates nothing. The tool can be called
  // without it, so the agent can still fire it alone. This is why the gate reads `required`, not `properties`.
  ['EVASION: signature present but optional', 'movesValue', {
    name: 'transfer_tokens',
    inputSchema: { type: 'object', properties: { to: {}, amount: {}, signature: {} }, required: ['to', 'amount'] } }],

  // EVASION 2 — an apiKey authorizes the AGENT, not the caller. It is a standing credential the agent already
  // holds, which is precisely the unattended case. Accepting it would make the gate a rubber stamp.
  ['EVASION: apiKey required (authorizes the agent, not the caller)', 'movesValue', {
    name: 'withdraw_balance',
    inputSchema: { type: 'object', properties: { amount: {}, apiKey: {} }, required: ['amount', 'apiKey'] } }],

  // EVASION 3 — no `required` array whatsoever. Absence of a demand is not a demand.
  ['EVASION: no required array at all', 'movesValue', {
    name: 'pay_invoice',
    inputSchema: { type: 'object', properties: { amount: {}, signature: {} } } }],

  // Regression: a message has a recipient exactly as a payment does. Only a quantity discriminates.
  ['message tool with a recipient is not a payment tool', 'namedButNoSurface', {
    name: 'lawbor_m1_send',
    inputSchema: { type: 'object', properties: { to: {}, body: {} }, required: ['to', 'body'] } }],

  // Regression: key material outranks everything, gate or no gate.
  ['key material still outranks the gate', 'wantsSecret', {
    name: 'import_wallet',
    inputSchema: { type: 'object', properties: { privateKey: {}, signature: {} }, required: ['privateKey', 'signature'] } }],

  // --- the witness category, found the same way: the check flagged a real settlement-recording tool --------

  // The real tool. It records a USDC transfer that already happened, by hash, and its own description says the
  // node moves no funds. A required hash is a backward reference and cannot be broadcast.
  ['real tool, records a settlement by txHash', 'witnessesPayment', {
    name: 'lawbor_settle',
    inputSchema: { type: 'object', properties: { to: {}, jobId: {}, txHash: {}, amountMicro: {} },
      required: ['to', 'jobId', 'txHash', 'amountMicro'] } }],

  // EVASION 4 — an optional hash proves nothing: the tool can be called without it.
  ['EVASION: txHash present but optional', 'movesValue', {
    name: 'settle_payment',
    inputSchema: { type: 'object', properties: { to: {}, amount: {}, txHash: {} }, required: ['to', 'amount'] } }],

  // EVASION 5 — the sharpest one. A raw signed transaction is FORWARD-acting: handing it to a server is how
  // funds move. It must never be read as a witness just because it contains the letters "tx". (It lands in
  // callerSigned, since the caller did sign it — but never in the witness bucket.)
  ['EVASION: signedTx is forward-acting, not a witness', 'callerSigned', {
    name: 'broadcast_transfer',
    inputSchema: { type: 'object', properties: { amount: {}, signedTx: {} }, required: ['amount', 'signedTx'] } }],

  // Both gates present: the signature is the stronger, more specific claim and wins.
  ['signature and txHash together report as caller-signed', 'callerSigned', {
    name: 'settle_signed',
    inputSchema: { type: 'object', properties: { amount: {}, txHash: {}, signature: {} },
      required: ['amount', 'txHash', 'signature'] } }],
];

const BUCKETS = ['movesValue', 'callerSigned', 'witnessesPayment', 'namedButNoSurface', 'wantsSecret', 'readOnly'];
let failed = 0;
for (const [label, expected, tool] of CASES) {
  const r = auditTools([tool]);
  const got = BUCKETS.find((b) => (r[b] || []).length);
  const ok = got === expected;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       expected ${expected}, got ${got}\n`);
}
// Counted, not asserted. This line said "the 3 attempts" for two more rows than that, which is the same fault
// the verdict text in agent-vet.js had — a hardcoded summary drifting away from what it summarises.
const evasions = CASES.filter(([label]) => label.startsWith('EVASION')).length;
process.stdout.write('\n' + (failed
  ? `${failed} schema case(s) failed\n`
  : `the ${CASES.length} schema cases hold, including ${evasions} attempts to walk through the gate\n`));

// NO process.exit here. The browser rows below were first appended AFTER an exit that used to sit on this line,
// which made eleven new assertions unreachable while the run printed "all cases hold" and returned 0. A test
// placed after an exit is not a test, and it is indistinguishable from a passing one — the same shape as every
// other false all-clear this repository documents. The single exit lives at the very bottom of the file now.

// ── browser control: a payment surface by COMPOSITION, which no schema declares ────────────────────────────
//
// Added after pointing this checker at a real trending project that hands an agent the user's own Chrome
// profile — "your agent inherits your existing logins, cookies, extensions". Its six tools (snapshot, fill,
// click, wait, navigate, capture) all land in readOnly, correctly, because the two-condition rule requires a
// value VERB before it reads the schema and browser automation has none. The danger is not in a tool; it is in
// what the browser can REACH. An agent that can navigate and click inside a profile holding a wallet extension
// can drive the wallet, and no input schema will ever say so.
//
// The first version of the detector keyed on VERBS and fired on five of six honest tool sets — trading, files,
// database, terminal, CI — because `open` and `execute` are the most generic verbs in software. The rows below
// are those five, kept as the regression they earned. The tell is a PARAMETER: a selector or a coordinate
// exists only to address something rendered. The second version then MISSED our own Chrome MCP, whose action
// tools are named `computer` and `form_input`, because it still required the name to agree — a false negative,
// which on a security check is the worse direction. A DOM field now decides alone.
const { detectBrowserControl } = require('../lib/agent-vet');
const bc = (tools) => !!detectBrowserControl(tools);
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       expected ${want}, got ${got}\n`);
};

process.stdout.write('\nbrowser control, keyed on schema fields rather than verbs:\n');
check('trading agent is not a browser',
  bc([{ name: 'open_position', inputSchema: { properties: { symbol: {}, size: {} } } },
      { name: 'execute_order', inputSchema: { properties: { orderId: {} } } }]), false);
check('file manager is not a browser',
  bc([{ name: 'open_file', inputSchema: { properties: { path: {} } } },
      { name: 'type_text', inputSchema: { properties: { path: {}, text: {} } } }]), false);
check('database client is not a browser',
  bc([{ name: 'open_connection', inputSchema: { properties: { dsn: {} } } },
      { name: 'execute_query', inputSchema: { properties: { sql: {} } } }]), false);
check('terminal is not a browser',
  bc([{ name: 'open_shell', inputSchema: { properties: { cwd: {} } } },
      { name: 'execute_command', inputSchema: { properties: { cmd: {} } } }]), false);
check('CI runner is not a browser',
  bc([{ name: 'open_pr', inputSchema: { properties: { repo: {} } } },
      { name: 'execute_workflow', inputSchema: { properties: { id: {} } } }]), false);
check('git ref is a branch, not a DOM handle',
  bc([{ name: 'checkout', inputSchema: { properties: { ref: {} } } },
      { name: 'diff', inputSchema: { properties: { ref: {} } } }]), false);

check('in-page tools with no schema at all ARE control',
  bc([{ name: 'snapshot' }, { name: 'fill' }, { name: 'click' }, { name: 'navigate' }]), true);
check('playwright-style names with selectors ARE control',
  bc([{ name: 'browser_navigate', inputSchema: { properties: { url: {} } } },
      { name: 'browser_click', inputSchema: { properties: { selector: {} } } }]), true);
check('a DOM field decides even when the NAME says nothing',
  bc([{ name: 'navigate', inputSchema: { properties: { url: {} } } },
      { name: 'computer', inputSchema: { properties: { ref: {}, coordinate: {} } } }]), true);

check('reading pages without acting is not control',
  bc([{ name: 'get_page_text', inputSchema: { properties: { url: {} } } },
      { name: 'snapshot', inputSchema: { properties: { url: {} } } }]), false);
check('navigating without acting is not control',
  bc([{ name: 'navigate', inputSchema: { properties: { url: {} } } }]), false);

process.stdout.write('\n' + (failed ? `${failed} case(s) failed after the browser rows\n` : 'browser rows hold too\n'));
process.exit(failed ? 1 : 0);
