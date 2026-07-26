'use strict';
/**
 * wallet-watch.js — what CHANGED around this wallet since we last looked, and does it matter?
 * ===========================================================================================
 * The other modules answer a question at a point in time. This one is the part that makes them a guard:
 * it remembers, so it can tell a new door from an old one. A wallet with three unlimited approvals granted
 * last year is a standing condition; a fourth appearing this morning is an event, and only the second one
 * deserves to interrupt someone.
 *
 * That distinction is the whole design. A monitor that re-reports the same three approvals every hour trains
 * its reader to close it, and a closed monitor is worth exactly nothing — the same reason a scanner that
 * flags every new launch stops being read. So state is persisted per address, and the output is a DIFF.
 *
 * Everything here follows the rules the rest of this codebase paid for:
 *   - transactions, not events: an ERC-20 Transfer log names whoever the emitting contract chose, so a
 *     counterparty only counts once the transaction's signer confirms it;
 *   - three outcomes, never two: a check that could not run is reported as such and never as "nothing found",
 *     because on a wallet monitor a silent failure reads as "you are safe";
 *   - read-only, no key, no signature, ever. It watches and it tells you. Acting is yours.
 */
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { checkApprovals } = require('./approvals');

const EXPLORER = { base: 'https://base.blockscout.com', ethereum: 'https://eth.blockscout.com' };
const STATE_DIR = path.join(__dirname, '..', 'data', 'wallet-watch');

const getJSON = (url) => new Promise((resolve) => {
  https.get(url, { headers: { accept: 'application/json' } }, (res) => {
    let d = ''; res.on('data', (c) => (d += c));
    res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
  }).on('error', () => resolve(null));
});

const statePath = (chain, owner) => path.join(STATE_DIR, chain + '-' + String(owner).toLowerCase() + '.json');
const readState = (chain, owner) => { try { return JSON.parse(fs.readFileSync(statePath(chain, owner), 'utf8')); } catch { return null; } };

/**
 * watchWallet — diff the wallet against what we last recorded.
 * @returns { ok, owner, chain, firstRun, alerts[], quiet[], unavailable[], state }
 *   alerts: things that changed and matter. Empty on a healthy run — that is the point.
 */
async function watchWallet(chain, owner, { persist = true } = {}) {
  const exp = EXPLORER[String(chain).toLowerCase()];
  if (!exp) return { ok: false, reason: 'chain "' + chain + '" not wired' };
  const addr = String(owner).toLowerCase();

  const prev = readState(chain, owner);
  const firstRun = !prev;
  const known = {
    approvals: new Set((prev && prev.approvals) || []),
    counterparties: new Set((prev && prev.counterparties) || []),
  };

  const alerts = [], quiet = [], unavailable = [];

  // ---- 1. Doors: has a NEW allowance appeared? ------------------------------------------------------
  const ap = await checkApprovals(chain, addr);
  const liveKeys = [];
  if (!ap.ok) {
    unavailable.push('approval sweep failed entirely — no conclusion can be drawn about open doors');
  } else {
    if (!ap.complete) unavailable.push(ap.unchecked + ' allowance(s) could not be read from the chain this run — an unanswered call is not a closed door');
    for (const l of ap.live) {
      const key = l.token + '|' + l.spender;
      liveKeys.push(key);
      if (known.approvals.has(key)) { quiet.push('standing approval: ' + l.tokenName + ' → ' + l.spender.slice(0, 12) + '…'); continue; }
      alerts.push({
        kind: 'new_approval', severity: l.unlimited ? 'high' : 'medium',
        what: 'NEW approval: ' + (l.unlimited ? 'UNLIMITED ' : l.allowance + ' ') + l.tokenName +
          ' to ' + l.spender + (l.spenderName ? ' (' + l.spenderName + ')' : '') +
          (l.spenderVerified ? '' : ' — UNVERIFIED contract'),
        why: firstRun
          ? 'First run, so this is inventory rather than an event — it is what already existed.'
          : 'This allowance was not present when we last looked. Someone granted it since.',
      });
    }
    // A door that closed is worth one quiet line: it is the good news, and it confirms the watcher works.
    for (const k of known.approvals) if (!liveKeys.includes(k)) quiet.push('approval revoked or spent since last run: ' + k.split('|')[1].slice(0, 12) + '…');
  }

  // ---- 2. Money out: a counterparty we have never seen ---------------------------------------------
  // Transactions only. An ERC-20 Transfer log is text the emitting contract chose, so it cannot establish
  // that this wallet sent anything.
  const txs = await getJSON(exp + '/api/v2/addresses/' + addr + '/transactions?filter=from');
  const seenNow = [];
  if (!txs || !Array.isArray(txs.items)) {
    unavailable.push('outgoing transaction list unavailable — cannot tell whether anything left');
  } else {
    for (const t of txs.items) {
      const to = (t.to && t.to.hash || '').toLowerCase();
      if (!to) continue;
      seenNow.push(to);
      if (known.counterparties.has(to) || firstRun) continue;
      const val = Number(t.value || 0) / 1e18;
      alerts.push({
        kind: 'new_counterparty', severity: val > 0 ? 'medium' : 'low',
        what: 'first interaction with ' + to + (t.to.name ? ' (' + t.to.name + ')' : '') +
          ' — method ' + (t.method || 'transfer') + (val > 0 ? ', ' + val.toFixed(6) + ' native' : ''),
        why: 'This address had never appeared as a destination from this wallet before ' + (t.timestamp || 'now') + '.',
      });
    }
  }

  const state = {
    owner: addr, chain, lastRun: new Date().toISOString(),
    approvals: liveKeys.length || ap.ok ? liveKeys : [...known.approvals],
    counterparties: [...new Set([...known.counterparties, ...seenNow])].slice(0, 500),
  };
  if (persist) {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(statePath(chain, owner), JSON.stringify(state, null, 2) + '\n');
  }

  return { ok: true, owner: addr, chain, firstRun, alerts, quiet, unavailable, state,
    note: (firstRun
        ? 'FIRST RUN: this is an inventory, not a set of events. Nothing here happened "just now" — it is the baseline the next run will diff against. '
        : '')
      + (unavailable.length
        ? '⚠️ ' + unavailable.length + ' check(s) could not complete, so an empty alert list does NOT mean nothing happened. '
        : '')
      + 'Read-only. This watches and reports; it holds no key and can neither revoke nor sign. A quiet run is the expected result — the value is that a new door is distinguishable from an old one.' };
}

module.exports = { watchWallet, readState, STATE_DIR };
