#!/usr/bin/env node
'use strict';
/**
 * wallet-watch — the module that states the rule, and broke it in its own state reader.
 * ======================================================================================
 * Its header reads: "three outcomes, never two: a check that could not run is reported as such and never
 * as 'nothing found', because on a wallet monitor a silent failure reads as 'you are safe'."
 *
 * ⚠️ THE DEFECT, measured 2026-07-29. `readState` was `try { JSON.parse(readFileSync(...)) } catch { null }`,
 * which folded five situations into two:
 *
 *   file ABSENT (genuine first run)     -> null   -> firstRun true    correct
 *   file VALID                          -> object -> firstRun false   correct
 *   file TRUNCATED (crash mid-write)    -> null   -> firstRun true    WRONG
 *   file EMPTY (disk full)              -> null   -> firstRun true    WRONG
 *   file of NUL bytes (fs corruption)   -> null   -> firstRun true    WRONG
 *
 * And `firstRun` does not make the guard fail — it makes it SILENT while still returning `ok: true`:
 * standing approvals are relabelled "inventory rather than an event", and
 * `if (known.counterparties.has(to) || firstRun) continue` skips judging EVERY counterparty, including an
 * address never before seen receiving money. One corrupt byte turns the monitor off.
 *
 * ⚠️ AND THE WRITER MANUFACTURED WHAT THE READER SWALLOWED. State was persisted with a direct
 * `writeFileSync`, which is not atomic: a crash, a kill, or the full volume this project has already lived
 * through leaves a half-written file on disk — precisely the truncated state above. Each half is harmless;
 * together they are a silent off-switch. The write is now temp-then-rename.
 *
 * ⚠️ WHAT IS NOT COVERED HERE, said plainly. `watchWallet` has no injection seam for its HTTP calls, so the
 * `stateLost` wiring (unavailable line, the honest `why`, counterparties still judged) cannot be exercised
 * offline — the same reason `judgeCounterparty` went untested here until a `lireJson` seam was added. The
 * READER is pinned below; the wiring is covered by reading, not by a test, and saying so is the point.
 *
 * Run: node test/wallet-watch.test.js
 */
const fs = require('node:fs');
const path = require('node:path');
const { readState, STATE_DIR } = require('../lib/wallet-watch');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};

/* A fake owner, so this never reads or writes the real wallets this repo watches. */
const OWNER = '0x' + 'de'.repeat(20);
const P = path.join(STATE_DIR, 'base-' + OWNER + '.json');
const ETAT = { owner: OWNER, chain: 'base', approvals: ['0xtok|0xspender'], counterparties: ['0xabc'] };

const nettoie = () => { try { fs.rmSync(P, { recursive: true, force: true }); } catch {} };
/* Three outcomes, so the probe reports three: a value, `null`, or a throw. Collapsing the throw into
 * "falsy" here would reproduce in the TEST the very defect being fixed in the source. */
const lire = () => {
  try { const r = readState('base', OWNER); return r === null ? 'null' : 'objet'; }
  catch { return 'leve'; }
};
const message = () => { try { readState('base', OWNER); return ''; } catch (e) { return e.message; } };

fs.mkdirSync(STATE_DIR, { recursive: true });
try {
  process.stdout.write('readState — trois issues, jamais deux:\n');

  nettoie();
  check('★ BORNE: un fichier ABSENT reste null — c est un VRAI premier run', lire(), 'null');

  fs.writeFileSync(P, JSON.stringify(ETAT));
  check('★ BORNE: un fichier VALIDE se lit toujours', lire(), 'objet');
  check('   et il rend bien son contenu, pas un objet vide',
    readState('base', OWNER).approvals.join(','), '0xtok|0xspender');

  fs.writeFileSync(P, JSON.stringify(ETAT).slice(0, 24));
  check('★ un fichier TRONQUE (crash en pleine ecriture) LEVE au lieu de passer pour un premier run', lire(), 'leve');
  check('★ et le message DIT ce qu il refuse de faire',
    String(/refusing to treat it as a first run/.test(message())), 'true');
  check('★ il donne la taille lue, pour qu on voie que le fichier existait',
    String(/\(24 bytes\)/.test(message())), 'true');

  fs.writeFileSync(P, '');
  check('★ un fichier VIDE (disque plein) leve aussi', lire(), 'leve');

  fs.writeFileSync(P, '\0'.repeat(40));
  check('★ un fichier de NUL (corruption FS) leve aussi', lire(), 'leve');

  fs.writeFileSync(P, 'null');
  check('BORNE: le litteral JSON `null` est un fichier LISIBLE — il se lit, il ne leve pas', lire(), 'null');

  nettoie();
  fs.mkdirSync(P);
  check('★ un REPERTOIRE a la place du fichier leve (EISDIR n est pas ENOENT)', lire(), 'leve');
  check('   et ce message-la aussi refuse le premier run',
    String(/refusing to treat it as a first run/.test(message())), 'true');
  nettoie();

  /* ── l ecriture atomique: ce qui reste sur le disque quand on est interrompu ───────────────────── */
  process.stdout.write('\nl ecriture d etat est-elle atomique ?\n');
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'wallet-watch.js'), 'utf8');
  check('★ l etat n est plus ecrit directement a sa destination',
    String(/fs\.writeFileSync\(statePath\(/.test(src)), 'false');
  check('★ il passe par un temporaire puis un rename (atomique sur le meme volume)',
    String(/fs\.renameSync\(tmp, dest\)/.test(src)), 'true');
  check('★ le temporaire porte le PID, pour que deux processus ne se marchent pas dessus',
    String(/dest \+ '\.' \+ process\.pid \+ '\.tmp'/.test(src)), 'true');

  /* ── le cablage dans watchWallet: lu, pas teste — et c est ecrit ──────────────────────────────── */
  process.stdout.write('\ncablage dans watchWallet (verifie par lecture de source, faute de joint reseau):\n');
  check('un etat perdu n est PAS traite comme un premier run',
    String(/const firstRun = !prev && !stateLost;/.test(src)), 'true');
  check('il ressort dans `unavailable`, la ou le module declare ce qu il n a pas pu faire',
    String(/unavailable\.push\('the stored state for this wallet could not be read/.test(src)), 'true');
  check('★ et le `why` cesse d affirmer « someone granted it since » sans memoire pour l etayer',
    String(/NOT as "someone granted it since", which we have no basis for/.test(src)), 'true');
} finally {
  nettoie();
}

process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
process.exit(failed ? 1 : 0);
