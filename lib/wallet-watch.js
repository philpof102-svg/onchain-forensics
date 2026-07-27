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

// The local known-bad screen is OPTIONAL here, and that is deliberate rather than lazy. It is a curated
// address list that belongs to whoever deploys this — a standalone install has no reason to carry one — so
// the module loads and works without it and says so in its output instead of pretending the check ran.
//
// Written after publishing this file with a hard `require('./screen')` for a module that was never shipped
// alongside it, which broke the whole server on load. My own smoke test had passed, because I ran it BEFORE
// adding the dependency and then copied the changed file over without re-running it. A stale test feels
// exactly like a passing one. `test/publishable.js` now refuses to publish a repo with an unresolvable
// require, and the `optional-require` marker below is how a deliberately-absent one declares itself — an
// absence has to be claimed in the source to be tolerated, so the next copied-in file fails loudly.
let screenAddress = null, FLOOR = null;
try {
  screenAddress = require('./screen').screenAddress; // optional-require: local known-bad list, deployer-supplied
  FLOOR = require('./vet').loadFloor();              // optional-require: same
} catch { /* no local floor available — judgeCounterparty reports that rather than assuming clean */ }

/**
 * Judge an address the wallet just met, rather than merely announcing that it met one. Everything here is
 * already built elsewhere in this repository; the guard was detecting and then declining to think, which is
 * half a product. Order matters: the local floor first, because it needs no network and cannot be wrong about
 * a match, then whatever the explorer will tell us.
 */
async function judgeCounterparty(exp, address) {
  const notes = [];
  let severity = null;

  const local = (screenAddress && FLOOR) ? screenAddress(address, FLOOR) : { available: false };
  if (local.blocked) { severity = 'high'; notes.push('ON THE LOCAL KNOWN-BAD LIST — ' + (local.reason || '')); }
  else if (!local.available) notes.push('the local known-bad screen is unavailable, so this address was NOT screened against it');

  const info = await getJSON(exp + '/api/v2/addresses/' + address);
  if (!info) { notes.push('the explorer did not answer, so nothing is known about this address beyond the transaction itself'); return { severity, notes }; }

  if (info.is_scam) { severity = 'high'; notes.push('the explorer flags this address as scam-reputation'); }
  if (info.is_contract) {
    notes.push(info.is_verified ? 'verified contract' + (info.name ? ' (' + info.name + ')' : '') : 'UNVERIFIED contract — its source is not published');
    if (!info.is_verified && severity !== 'high') severity = 'medium';
  } else {
    notes.push('a plain wallet, not a contract');
  }
  return { severity, notes };
}

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
      const j = await judgeCounterparty(exp, l.spender);
      alerts.push({
        kind: 'new_approval',
        // The judgment can only ever RAISE severity. An unlimited allowance is already high; a known-bad
        // spender cannot make it worse, but a known-bad spender on a small allowance must not read as minor.
        severity: j.severity === 'high' ? 'high' : (l.unlimited ? 'high' : (j.severity || 'medium')),
        what: 'NEW approval: ' + (l.unlimited ? 'UNLIMITED ' : l.allowance + ' ') + l.tokenName +
          ' to ' + l.spender + (l.spenderName ? ' (' + l.spenderName + ')' : ''),
        judgment: j.notes,
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
      const j = await judgeCounterparty(exp, to);
      alerts.push({
        kind: 'new_counterparty',
        severity: j.severity || (val > 0 ? 'medium' : 'low'),
        what: 'first interaction with ' + to + (t.to.name ? ' (' + t.to.name + ')' : '') +
          ' — method ' + (t.method || 'transfer') + (val > 0 ? ', ' + val.toFixed(6) + ' native' : ''),
        judgment: j.notes,
        why: 'This address had never appeared as a destination from this wallet before ' + (t.timestamp || 'now') + '.',
      });
    }
  }

  /* ⚠️ CE QU'ON ECRIT COMME REFERENCE decide si le PROCHAIN run dira vrai. Deux fautes, corrigees dans
   * biii le 2026-07-27 et portees ici — les deux depots embarquent une copie de ce module.
   *
   * (A) `approvals: liveKeys.length || ap.ok ? liveKeys : [...]` — sur un balayage PARTIEL (`ap.ok` vrai,
   *     `ap.complete` faux) la reference ne gardait que ce qui avait pu etre LU. Les allocations non lues
   *     disparaissaient, et au run suivant elles ressortaient en « NEW approval … Someone granted it
   *     since »: une affirmation FAUSSE sur la date d'octroi, a propos d'un beneficiaire, nee de notre
   *     propre oubli. On ne remplace donc que sur un balayage COMPLET; sinon on prend l'UNION. Rater une
   *     revocation coute moins cher qu'inventer un octroi.
   *     `=== true` et non `!== false`: un `complete` absent veut dire « on ne sait pas ».
   *
   * (B) Le plafond gardait les plus ANCIENS: `[...known, ...seenNow].slice(0, 500)` coupe la FIN, donc
   *     `seenNow`. Passe 500 contreparties, une nouvelle etait alertee, jamais enregistree, et realertait
   *     a CHAQUE run — le plafond detruisait la propriete meme du module. Ce qu'on vient de voir passe
   *     desormais en tete. */
  const balayageComplet = ap.ok === true && ap.complete === true;
  const approvals = balayageComplet ? liveKeys : [...new Set([...known.approvals, ...liveKeys])];

  const CAP = 500;
  const vues = [...new Set([...seenNow, ...known.counterparties])];
  if (vues.length > CAP) {
    unavailable.push('counterparty memory is capped at ' + CAP + ' and ' + (vues.length - CAP)
      + ' older entries were dropped this run — an address that falls off the end can be reported as a '
      + 'first interaction again later');
  }

  const state = {
    owner: addr, chain, lastRun: new Date().toISOString(),
    approvals,
    counterparties: vues.slice(0, CAP),
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

module.exports = { watchWallet, judgeCounterparty, readState, STATE_DIR };
