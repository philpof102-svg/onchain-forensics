#!/usr/bin/env node
'use strict';
/**
 * onchain-forensics — an MCP server for the questions you ask before you pay, and after you've been robbed.
 *
 * Every tool here was written while answering one of these for real, on live data, and kept only after it
 * reproduced a fact that was already established by hand. Where a check turned out to be wrong, the fix and
 * the reason are recorded in the module it lives in — those comments are the useful part of this repository.
 *
 * No API keys. No accounts. Every source is a public endpoint anyone can query.
 * Read-only throughout: nothing here can move funds, and none of it ever asks for a key.
 */
const readline = require('node:readline');
const { vetMeme } = require('../lib/meme');
const { scanRugOne } = require('../lib/rugsignals');
const { classifyB20 } = require('../lib/b20');
const { traceFeeder } = require('../lib/feeder');
const { whatMoved, readBridgeExit, followTron } = require('../lib/trace');
const { assessRecoveryOffer } = require('../lib/recovery');
const { vetApproach } = require('../lib/lure');

const TOOLS = [
  { name: 'vet_meme', description: 'Which contract is the REAL token behind a ticker? A meme symbol routinely has ten or more look-alike contracts across chains, and buying the wrong one is a total loss. Fail-closed from live liquidity: genuine (one contract dominates), ambiguous (top two tied — NEVER certified), impersonation (the address you passed is not the dominant one), thin (nothing credible).',
    inputSchema: { type: 'object', properties: {
      symbol: { type: 'string' }, chainId: { type: 'string', description: 'optional: restrict to one chain, e.g. base' },
      address: { type: 'string', description: 'optional: judge THIS specific contract' } }, required: ['symbol'] } },

  { name: 'rug_powers', description: 'Given the contract, what powers does its deployer still hold over your money? The load-bearing idea, and why flag-listing scanners are noise: a dangerous capability only counts if someone can still FIRE it. Mintable with ownership renounced is inert; the same flag with a live owner is an armed rug. Merges a curated index (owner powers, LP locks) with a live trade simulation, because the index has never heard of a token minted ten minutes ago and the simulation cannot see who is in control. Never returns clean on simulation alone.',
    inputSchema: { type: 'object', properties: {
      address: { type: 'string' }, chain: { type: 'string', description: 'base (default) | ethereum | bsc | polygon | arbitrum | optimism | avalanche' } }, required: ['address'] } },

  { name: 'b20_authentic', description: 'Is this a genuine Base-native B20 asset, or an ordinary ERC-20 wearing its address prefix? B20 is Base\'s standard for compliant issuance (stablecoins, RWA); its tokens sit at 0xb200… and run as a precompile, so a real one carries almost no EVM bytecode. As people learn to read that prefix as "official", a vanity-address ERC-20 inherits the credibility for free. Both answers matter: an impostor lacks the issuer controls the standard implies, and a GENUINE B20 lets its issuer freeze and burn a blocked holder\'s balance — a power no ERC-20 has and no ERC-20-shaped scanner looks for.',
    inputSchema: { type: 'object', properties: { address: { type: 'string' }, chain: { type: 'string' } }, required: ['address'] } },

  { name: 'launch_funder', description: 'Who paid for this launch, and what else did they pay for? A token names its creator; a creator minted minutes ago names the wallet that funded it; and that funder usually funded others. Three free queries surface a cluster no buyer sees from a chart. Reports STRUCTURE, never intent — a shared paymaster proves shared control or shared infrastructure, and a launchpad is indistinguishable from a rug factory on the graph alone. What it does prove is that those tokens share fate.',
    inputSchema: { type: 'object', properties: { address: { type: 'string' }, chain: { type: 'string' } }, required: ['address'] } },

  { name: 'trace_theft', description: 'Follow stolen funds from the victim\'s transaction to where the trail dies. moved: what actually left a wallet, marking which transfers are authentic — ERC-20 Transfer logs are attacker-controlled text, so only the transaction signer is authoritative. bridge: read a cross-chain exit; aggregators write the destination into their own calldata because the far side needs it, and chain ids are checked against a table before any field is called an amount. tron: walk a TRON account, detecting relay hops — an account forwarding what it received, within seconds, is a pass-through and not a destination.',
    inputSchema: { type: 'object', properties: {
      mode: { type: 'string', description: 'moved | bridge | tron' },
      txHash: { type: 'string' }, address: { type: 'string', description: 'TRON T-address for mode tron' },
      chain: { type: 'string' }, maxHops: { type: 'number' } }, required: ['mode'] } },

  { name: 'recovery_offer', description: 'Judge an offer to recover already-stolen funds. Answerable with certainty rather than a score, because the ask is the tell: recovery happens through the thief, a court, an exchange, or an issuer — never through the victim\'s wallet. A recovery needing your signature or an upfront fee is not merely suspect, it is structurally impossible as described, however credible the person sounds and however accurately they recite your loss (the theft is public; anyone can read it back to you). Never returns "safe".',
    inputSchema: { type: 'object', properties: {
      address: { type: 'string', description: 'the address you were asked to pay (optional — its absence is not reassurance)' },
      chain: { type: 'string' },
      asksForSignature: { type: 'boolean' }, asksForUpfrontPayment: { type: 'boolean' },
      asksForSeedOrKey: { type: 'boolean' }, asksToInstall: { type: 'boolean' } }, required: [] } },
  { name: 'vet_approach', description: 'Judge an inbound opportunity — podcast, interview, partnership, job, AMA — by what it ASKS, not by how good it looks. Built from a lure that worked on someone who verifies counterparties professionally: a 35-question production dossier citing his real work, using his own catchphrase, quoting his posts, and asking genuinely hard questions, because a flatterer never includes criticism and including it is what makes an approach read as journalism. The mechanism is effort as a trust signal: that much detail used to cost hours of human work, so nobody spent it on one target. That arithmetic no longer holds. So this does NOT score how convincing an approach is — that would give a forgery a good grade. It grades where a link actually points (a brand to the left of the registrable domain is a free label: wechat.web09eu.com is web09eu.com) and what the sender wants from you. Never returns safe.',
    inputSchema: { type: 'object', properties: {
      links: { type: 'array', items: { type: 'string' } },
      platform: { type: 'string' },
      asksToInstall: { type: 'boolean' }, asksForKeyOrSeed: { type: 'boolean' },
      asksForSignature: { type: 'boolean' }, asksForUpfrontPayment: { type: 'boolean' },
      urgency: { type: 'boolean' } }, required: [] } },
];

async function callTool(name, a = {}) {
  if (name === 'vet_meme') return await vetMeme({ symbol: a.symbol, chainId: a.chainId, address: a.address });
  if (name === 'rug_powers') return await scanRugOne(a.chain || 'base', a.address);
  if (name === 'b20_authentic') return await classifyB20(a.chain || 'base', a.address);
  if (name === 'launch_funder') {
    const f = await traceFeeder(a.chain || 'base', a.address);
    return (f && f.ok) ? f : { error: (f && f.reason) || 'could not trace this launch' };
  }
  if (name === 'trace_theft') {
    const chain = a.chain || 'base';
    if (a.mode === 'moved') {
      if (!a.txHash) return { error: 'txHash required' };
      const m = await whatMoved(chain, a.txHash);
      return m.ok ? { ...m, note: m.forgedTransfers ? m.forgedTransfers + ' transfer event(s) name a sender who did not sign this transaction — forged logs, do not follow them.' : 'All transfer events match the signer.' } : { error: m.reason };
    }
    if (a.mode === 'bridge') return a.txHash ? await readBridgeExit(chain, a.txHash) : { error: 'txHash required' };
    if (a.mode === 'tron') return a.address ? await followTron(a.address, { maxHops: a.maxHops || 3 }) : { error: 'address required' };
    return { error: 'mode must be moved | bridge | tron' };
  }
  if (name === 'recovery_offer') return await assessRecoveryOffer(a);
  if (name === 'vet_approach') return vetApproach(a);
  return { error: 'unknown tool: ' + name };
}

const send = (o) => process.stdout.write(JSON.stringify(o) + '\n');

async function handle(m) {
  if (m.method === 'initialize') return send({ jsonrpc: '2.0', id: m.id, result: {
    protocolVersion: '2024-11-05', capabilities: { tools: {} },
    serverInfo: { name: 'onchain-forensics', version: '0.1.0' } } });
  if (m.method === 'notifications/initialized') return;
  if (m.method === 'tools/list') return send({ jsonrpc: '2.0', id: m.id, result: { tools: TOOLS } });
  if (m.method === 'tools/call') {
    try {
      const out = await callTool(m.params && m.params.name, (m.params && m.params.arguments) || {});
      return send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] } });
    } catch (e) {
      // Never leak an internal message to the caller; say plainly that it failed.
      return send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'the check could not be completed' }) }], isError: true } });
    }
  }
  if (m.id !== undefined) send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'method not found' } });
}

readline.createInterface({ input: process.stdin }).on('line', (line) => {
  if (!line.trim()) return;
  let m; try { m = JSON.parse(line); } catch { return; }
  handle(m);
});
