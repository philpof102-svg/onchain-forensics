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
const { loadWordlist, checksumValid, scanText, VALID_LENGTHS } = require('../lib/seedscan');
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

process.stdout.write('\nthe rule this module is built around:\n');
const out = JSON.stringify(scanText(V12, index));
check('output contains no word of the phrase', /abandon|about/.test(out), false);
const out24 = JSON.stringify(scanText(V24.split(' ').map((w, i) => `${i + 1}. ${w}`).join('\n'), index));
check('nor for a 24-word vertical list', /abandon|art\b/.test(out24), false);
check('valid lengths are the five the standard defines', VALID_LENGTHS.join(','), '12,15,18,21,24');

process.stdout.write('\n' + (failed ? `${failed} case(s) failed\n` : 'all cases hold\n'));
process.exit(failed ? 1 : 0);
