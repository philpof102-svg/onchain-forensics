#!/usr/bin/env node
'use strict';
/**
 * The truth table for seed detection, and the false positive it produced on its first real run.
 *
 * Every phrase below is the canonical BIP-39 all-zeros test vector, published in the standard itself. It holds
 * nothing and never has. Using anything else in a test file would be the exact mistake this module exists to
 * find.
 *
 * The row that matters most is WORDLIST CARRIER. Pointed at a real machine, this tool reported `exposed` on a
 * paywall template that embeds a minified wallet library, which embeds all 2048 BIP-39 words: a 15-word window
 * inside that region passed the checksum by chance. The bounded offset search was meant to prevent that and
 * did — on the axis I had thought about. Minified code splits the region into thirty-odd runs, each of which
 * then gets its own bounded search, so about 600 checksum tests happen in one file at 1/16 each for a 12-word
 * window. A coincidental pass there is not a risk, it is arithmetic. The multiplicity had moved from offsets
 * inside a run to the NUMBER of runs, and the file carried its own refutation the whole time: a note holding a
 * seed has 12 to 24 wordlist words, a wallet library has hundreds.
 */
const { loadWordlist, checksumValid, scanText, judgeRun, VALID_LENGTHS } = require('../lib/seedscan');
const WORDS = require('../lib/bip39-english');

const index = loadWordlist();
let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       expected ${want}, got ${got}\n`);
};
const V12 = ('abandon '.repeat(11) + 'about').trim();
const V24 = ('abandon '.repeat(23) + 'art').trim();
const verdictOf = (text) => { const f = scanText(text, index); return f.length ? f[0].verdict : 'none'; };
const wordsOf = (text) => { const f = scanText(text, index); return f.length ? f[0].words : 0; };

process.stdout.write('the wordlist itself:\n');
check('exactly 2048 words', WORDS.length, 2048);
check('4-letter prefixes unique (a real property of the standard)', new Set(WORDS.map((w) => w.slice(0, 4))).size, 2048);
check('index loads', index.size, 2048);

process.stdout.write('\nthe checksum, against the published vectors:\n');
check('12-word all-zeros vector validates', checksumValid(V12.split(' '), index), true);
check('24-word all-zeros vector validates', checksumValid(V24.split(' '), index), true);
check('same 12 words with a wrong last word does NOT', checksumValid(('abandon '.repeat(12)).trim().split(' '), index), false);
check('13 words is not a valid length', checksumValid(('abandon '.repeat(13)).trim().split(' '), index), false);
check('a word outside the list fails closed', checksumValid((('abandon '.repeat(11)) + 'zzzz').split(' '), index), false);

process.stdout.write('\nthe formats people actually write a phrase in:\n');
check('inline in a note', verdictOf('backup for later: ' + V12), 'confirmed');
check('numbered vertical list (the commonest one)', verdictOf(V12.split(' ').map((w, i) => `${i + 1}. ${w}`).join('\n')), 'confirmed');
check('24-word vertical list reports 24, not 12', wordsOf(V24.split(' ').map((w, i) => `${i + 1}. ${w}`).join('\n')), 24);
check('comma separated', verdictOf(V12.split(' ').join(', ')), 'confirmed');
check('a markdown table row', verdictOf('| ' + V12.split(' ').join(' | ') + ' |'), 'confirmed');
check('inside JSON', verdictOf(JSON.stringify({ label: 'backup', mnemonic: V12 })), 'confirmed');

process.stdout.write('\nfalse positives:\n');
check('ordinary English full of wordlist words',
  verdictOf('I am able to abandon this absurd idea about access and accident, above all absent any abuse.'), 'none');
check('11 wordlist words is below the standard floor',
  verdictOf('abandon '.repeat(11)), 'none');
check('12 wordlist words, checksum fails -> run, never a seed',
  verdictOf('abandon '.repeat(12)), 'wordlist_run');

// THE one that came from a real machine, not from imagination.
check('WORDLIST CARRIER: a file embedding all 2048 words claims nothing',
  verdictOf(WORDS.join(' ')), 'wordlist_file');
check('carrier detection survives minification-style splitting',
  verdictOf(WORDS.map((w, i) => (i % 7 === 0 ? '","' + w : w)).join(' ')), 'wordlist_file');

// And the guard must not blind the tool: a real file with a real phrase in it still confirms.
check('a long document that ALSO contains a phrase still confirms',
  verdictOf('lorem ipsum dolor sit amet '.repeat(400) + '\nseed: ' + V12), 'confirmed');

/* ═══ LA LOCALISATION — le seul produit de ce module ═══
 * Il n'imprime JAMAIS la phrase, par doctrine: il dit ou aller regarder. Le numero de ligne EST donc le
 * livrable, et rien ici ne l'assertait — la suite sortait verte pendant que `line`/`endLine` decrivaient le
 * RUN au lieu de la PHRASE. Mesure du 2026-07-29: une phrase de 12 mots aux lignes 2-13 suivie de 40
 * mots-liste etait annoncee « spanning lines 1-53 », avec `words: 12` juste a cote pour la contredire.
 * Le champ ne variait pas avec la position de la phrase, donc il n'observait pas la phrase.
 */
process.stdout.write('\nla localisation (le seul produit: la phrase n\'est jamais imprimee):\n');
const finding = (text) => scanText(text, index)[0];
const vertical = (mots) => mots.join('\n');
const QUEUE = Array.from({ length: 40 }, () => 'zoo');

const seule = finding(vertical(V12.split(' ')));
check('phrase seule: la portee est celle de la phrase', seule.line + '-' + seule.endLine, '1-12');

const avecSlack = finding(vertical(['seed', 'zoo', 'zoo'].concat(V12.split(' '))));
check('3 mots de slack avant: la portee COMMENCE a la phrase, pas au run',
  avecSlack.line + '-' + avecSlack.endLine, '4-15');

const avecQueue = finding(vertical(['seed'].concat(V12.split(' '), QUEUE)));
check('40 mots-liste apres: la portee FINIT a la phrase, pas au run',
  avecQueue.line + '-' + avecQueue.endLine, '2-13');

/* Controle d'instrument: les trois cas ci-dessus ont des runs qui commencent tous ligne 1. Si le code
 * repartait decrire le run, les trois rendraient la meme chose et les trois cas passeraient d'un bloc.
 * On exige donc TROIS portees DISTINCTES — un chiffre constant n'est pas une mesure. */
check('les trois portees sont distinctes (sinon le champ ne mesure rien)',
  new Set([seule, avecSlack, avecQueue].map((f) => f.line + '-' + f.endLine)).size, 3);

// La portee doit rester COHERENTE avec le nombre de mots annonce a cote d'elle.
check('la portee annoncee tient dans le nombre de mots annonce',
  avecQueue.endLine - avecQueue.line + 1 <= avecQueue.words, true);

/* LES DEUX BORNES du debordement. La recherche s'arrete au premier checksum valide, donc une seconde
 * phrase dans le MEME run n'est pas rapportee — mesure: deux phrases collees ne donnent qu'un constat.
 * Un plafond muet se lit comme une absence, donc il se DIT quand il mord, et se TAIT quand il ne mord pas. */
check('un run plus large que la phrase DIT que la recherche s\'est arretee',
  /SECOND phrase/.test(avecQueue.note), true);
check('un run exactement de la taille de la phrase ne le dit PAS',
  /SECOND phrase/.test(seule.note), false);
check('deux phrases collees ne forment qu\'un run et ne donnent qu\'un constat',
  scanText(vertical(V12.split(' ').concat(V12.split(' '))), index).length, 1);
check('...et ce constat renvoie vers le run entier',
  scanText(vertical(V12.split(' ').concat(V12.split(' '))), index)[0].runEndLine, 24);

// Un run sans checksum valide EST le constat: sa portee reste celle du run, et c'est correct.
const runSeul = finding(vertical(Array.from({ length: 14 }, () => 'abandon')));
check('wordlist_run: la portee reste celle du run', runSeul.line + '-' + runSeul.endLine, '1-14');
check('wordlist_run: les 14 mots sont annonces', runSeul.words, 14);

/* judgeRun est EXPORTE. Un run vide n'a aucune localisation: il doit refuser, pas rendre un constat dont
 * `line` vaut undefined — un constat qui ne pointe nulle part est pire que pas de constat. */
let refus = 'AUCUN REFUS';
try { judgeRun([], index); } catch (e) { refus = e.message; }
check('judgeRun refuse un run vide au lieu de pointer nulle part',
  refus, 'judgeRun requires a non-empty run of tokens');

process.stdout.write('\nthe rule this module is built around:\n');
const out = JSON.stringify(scanText(V12, index));
check('output contains no word of the phrase', /abandon|about/.test(out), false);
const out24 = JSON.stringify(scanText(V24.split(' ').map((w, i) => `${i + 1}. ${w}`).join('\n'), index));
check('nor for a 24-word vertical list', /abandon|art\b/.test(out24), false);
check('valid lengths are the five the standard defines', VALID_LENGTHS.join(','), '12,15,18,21,24');

process.stdout.write('\n' + (failed ? `${failed} case(s) failed\n` : 'all cases hold\n'));
process.exit(failed ? 1 : 0);
