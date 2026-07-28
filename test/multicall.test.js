#!/usr/bin/env node
'use strict';
/**
 * multicall — the ABI decoder that read its input as if the input were already trusted.
 * ======================================================================================
 * ⚠️ THE THREE DEFECTS THESE CASES PIN, measured 2026-07-29 on hand-built responses.
 *
 * `decodeAggregate3` sliced words and handed them straight to `BigInt`, with no check that a word was
 * present, that it was hex, or that a declared byte length was actually there. Three ways of not being
 * ABI data produced three different wrong outcomes:
 *
 *   a word that is not hex          -> SyntaxError THROWN out of multiCall — the whole batch dies,
 *                                      including the calls that would have decoded perfectly
 *   truncated just before the data  -> { data: '0x' }, which allowancesBatch reads as a REVERT,
 *                                      i.e. "answered definitively: no allowance"
 *   dataLen says 32, 8 bytes remain -> allowance 123456789 decoded as 0        <- A WRONG NUMBER
 *
 * ⚠️ WHY THE THIRD IS THE ONE THAT MATTERS. It is neither an error nor a null: it is a plausible answer,
 * and it does not stay local. An allowance read as 0 lets `approvals` declare the sweep `complete`, which
 * lets `wallet-watch` replace its stored reference, so the NEXT run sees the real allowance appear from
 * nowhere and reports "NEW approval — someone granted it since". A missing byte becomes a published
 * accusation that a third party signed something. That chain is documented in the twin's own test header.
 *
 * And the file already knew: its module docstring says "a response is not a correct response: the first
 * hand-rolled attempt returned 770 bytes of plausible-looking data, which proves only that the node
 * answered something." The decoder simply never applied its own lesson to itself.
 *
 * ⚠️ THE BOUND THAT MAKES THESE CASES REAL. Every fix here is satisfied by a decoder that returns `null`
 * for everything, so the refusals are worthless without the acceptances beside them: a valid response must
 * still decode to the exact value, a genuinely EMPTY return (dataLen 0) must stay `'0x'` — that is a real
 * answer, not a failure — a genuine revert must stay `success: false`, and input order must survive.
 *
 * Run: node test/multicall.test.js
 */
const { decodeAggregate3, allowancesBatch, encodeAggregate3, MULTICALL3 } = require('../lib/multicall');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};

const w = (n) => BigInt(n).toString(16).padStart(64, '0');
const VALEUR = 123456789n;

/* One call, success = true, 32 bytes of return data. Word layout, which the decoder must walk:
 *   0: offset to array (32)   1: array length   2: offset of struct 0   3: success   4: offset to bytes
 *   5: byte length            6: the data                                                              */
const un = (mots) => '0x' + mots.join('');
const VALIDE = un([w(32), w(1), w(32), w(1), w(64), w(32), w(VALEUR)]);
/* Two calls, so "preserves input order" is testable at all — one element cannot show an ordering. */
const DEUX = un([w(32), w(2), w(64), w(224), w(1), w(64), w(32), w(11), w(1), w(64), w(32), w(22)]);

const d1 = (hex, n = 1) => decodeAggregate3(hex, n);
const lire = (hex) => { const r = d1(hex); return r === null ? 'null' : BigInt(r[0].data).toString(); };

/* ── the acceptances: without these, "return null always" would pass every refusal below ──────────── */
process.stdout.write('decodeAggregate3 — ce qui DOIT continuer a se decoder:\n');
check('★ BORNE: une reponse valide rend la valeur EXACTE', lire(VALIDE), String(VALEUR));
check('★ BORNE: un retour reellement VIDE reste une reponse ("0x"), pas un non-lu',
  (d1(un([w(32), w(1), w(32), w(1), w(64), w(0)])) || [{}])[0].data, '0x');
check('★ BORNE: un revert reel garde success=false',
  String((d1(un([w(32), w(1), w(32), w(0), w(64), w(0)])) || [{}])[0].success), 'false');
check('★ BORNE: deux appels sortent DANS L ORDRE (un seul element ne prouverait rien)',
  (d1(DEUX, 2) || []).map((x) => BigInt(x.data).toString()).join(','), '11,22');
check('la garde de forme existante tient toujours (longueur != attendu)', String(d1(VALIDE, 2)), 'null');
check('une reponse trop courte reste un non-lu', String(d1('0x' + w(32))), 'null');

/* ── ★ the refusals: each one used to be a throw, a false revert, or a wrong number ───────────────── */
process.stdout.write('\ndecodeAggregate3 — ce qui doit devenir un NON-LU au lieu d une reponse:\n');
check('★ un mot non hexadecimal ne JETTE plus (il tuait le lot entier)',
  String(d1(un([w(32), w(1), 'z'.repeat(64), w(1), w(64), w(32), w(VALEUR)]))), 'null');
check('★ une reponse tronquee apres la longueur du tableau ne jette plus',
  String(d1(VALIDE.slice(0, 2 + 64 * 3))), 'null');
check('★ une reponse tronquee juste avant la donnee n est plus un revert definitif',
  String(d1(VALIDE.slice(0, 2 + 64 * 6))), 'null');
check('★ LE CAS QUI COMPTE: dataLen annonce 32 octets, il n en reste que 8',
  lire(un([w(32), w(1), w(32), w(1), w(64), w(32), w(VALEUR).slice(0, 16)])), 'null');
check('★ et il rendait un NOMBRE FAUX, pas une erreur — 0 au lieu de 123456789 (voir en-tete)',
  String(lire(un([w(32), w(1), w(32), w(1), w(64), w(32), w(VALEUR).slice(0, 16)])) === '0'), 'false');
check('un decalage qui pointe hors du tampon est refuse',
  String(d1(un([w(32), w(1), w(1e6), w(1), w(64), w(32), w(VALEUR)]))), 'null');

/* ⚠️ CES TROIS CAS SONT VERTS, ET LA MUTATION QUI LES VISE SURVIT QUAND MEME. C'est ecrit ici parce que
 * cacher une mutation survivante est exactement ce qui transforme une suite en decoration.
 *
 * Chronologie honnete, 2026-07-29: retirer le controle "multiple de 32" ne cassait rien. J'ai d'abord
 * suppose que mon test etait faible — un seul cas, sur le decalage du TABLEAU, ou la garde
 * `len !== expected` tire de toute facon — et j'ai ajoute la STRUCT et la DONNEE. Toujours vert. Mesure
 * faite ensuite, en retirant reellement la garde: les trois rendent `null` PAREIL.
 *
 * Diagnostic: le controle d'alignement est domine par le controle hexadecimal. Un indice fractionnaire
 * fait lire une tranche a cheval, qui finit hors du tampon ou plus courte que 64 caracteres, et `at()` la
 * refuse avant que l'alignement n'ait son mot a dire. La garde est une PRECONDITION EXPLICITE, pas une
 * protection prouvee — aucun test ne la tient, et le fichier source le dit au meme endroit.
 *
 * Les trois cas restent: ils epinglent le COMPORTEMENT (un decalage desaligne ne doit jamais rendre de
 * donnee), qui doit tenir quelle que soit la garde qui l'assure. */
check('★ un decalage de STRUCT desaligne est refuse (aucune autre garde ne le couvre)',
  String(d1(un([w(32), w(1), w(33), w(1), w(64), w(32), w(VALEUR)]))), 'null');
check('★ un decalage de DONNEE desaligne est refuse',
  String(d1(un([w(32), w(1), w(32), w(1), w(65), w(32), w(VALEUR)]))), 'null');
check('★ et le decalage de tableau desaligne reste refuse lui aussi',
  String(d1(un([w(33), w(1), w(32), w(1), w(64), w(32), w(VALEUR)]))), 'null');

/* ── allowancesBatch: the three-state contract the whole approval sweep rests on ───────────────────── */
process.stdout.write('\nallowancesBatch — trois etats, et un non-lu ne doit jamais devenir un zero:\n');
const faux = (hex) => async () => ({ result: hex });
/* No network: multiCall's RPC table has no entry for this chain, so it returns nulls for every call.
 * That is itself the contract under test — an unknown chain is UNREAD, never "no allowance". */
(async () => {
  const r = await allowancesBatch('chaine-inconnue', '0x' + '11'.repeat(20),
    [{ token: '0x' + '22'.repeat(20), spender: '0x' + '33'.repeat(20) }]);
  check('★ une chaine sans RPC rend null (non-lu), jamais false ni 0', String(r[0]), 'null');
  check('   et elle rend UNE entree par paire demandee, pas un tableau court', String(r.length), '1');

  check('encodeAggregate3 vise bien Multicall3', String(MULTICALL3), '0xcA11bde05977b3631167028862bE2a173976CA11');
  check('encodeAggregate3 commence par le selecteur aggregate3',
    encodeAggregate3([{ target: '0x' + '22'.repeat(20), allowFailure: true, callData: '0xdd62ed3e' }]).slice(0, 10),
    '0x82ad56cb'.slice(0, 10));

  process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
  process.exit(failed ? 1 : 0);
})();
