'use strict';
/**
 * seedscan — is a recovery phrase sitting in cleartext on this machine?
 * =====================================================================
 * "Self custody if you know how to keep your seedphrase safe." The condition is the whole sentence, and
 * nobody ships the tool that checks it. An antivirus answers "do you have a known virus"; the question a
 * person holding crypto actually has is "is my seed phrase readable by anything that runs on this machine".
 *
 * That question is DECIDABLE, which is why this is worth building rather than guessing at. A keyword scan
 * would drown: `abandon`, `able`, `about`, `absent` are ordinary English and all four are BIP-39 words. But a
 * mnemonic is not a bag of words, it is a RUN of 12/15/18/21/24 consecutive words all drawn from a 2048-word
 * list, and BIP-39 puts a CHECKSUM in the last word. So a candidate can be proven, not scored:
 *
 *   word indices (11 bits each) -> entropy bits + checksum bits
 *   checksum must equal the leading bits of SHA-256(entropy)
 *
 * A 12-word run of wordlist words has a 1-in-16 chance of passing that by accident; a 24-word run, 1 in 256.
 * Combine that with the improbability of 12 consecutive English words all being in the list and a confirmed
 * hit is a fact, not a suspicion.
 *
 * ═══ THE RULE THIS FILE IS BUILT AROUND ═══
 * It NEVER outputs the phrase. Not to stdout, not to a log, not to a report file, not in an error message.
 * It reports the FILE, the LINE and the WORD COUNT. A scanner that prints the seed it found is a stealer with
 * good intentions, and "good intentions" is not a security property — the output of this tool will end up in a
 * terminal buffer, a CI log, a screenshot or a pasted bug report, every one of which is a place a seed must
 * never be. Reporting the location is enough to act: the owner goes and looks.
 *
 * Read-only. No network. No key material ever leaves the function that read it.
 */
const crypto = require('node:crypto');
const WORDS = require('./bip39-english');

const VALID_LENGTHS = [12, 15, 18, 21, 24];

/** Build the index map once. Membership AND index are needed — the checksum needs the position in the list. */
function loadWordlist(text) {
  // No argument means the embedded list, which is the normal path. Passing text is for verifying this module
  // against a freshly downloaded copy of the BIP.
  const words = text === undefined || text === null
    ? WORDS.map((w) => String(w).trim().toLowerCase())
    : String(text).split(/\r?\n/).map((w) => w.trim().toLowerCase()).filter(Boolean);
  if (words.length !== 2048) throw new Error('BIP-39 wordlist must be exactly 2048 words, got ' + words.length);
  // The unique-4-letter-prefix property is real and load-bearing: it is what lets a wallet accept the
  // first four letters of each word. Checked here so a truncated or reordered copy fails loudly instead of
  // silently detecting less than it claims to.
  const p4 = new Set(words.map((w) => w.slice(0, 4)));
  if (p4.size !== words.length) throw new Error('BIP-39 wordlist is corrupt: 4-letter prefixes are not unique');
  const index = new Map();
  words.forEach((w, i) => index.set(w, i));
  return index;
}

/**
 * Is this exact sequence a valid BIP-39 mnemonic? Returns true/false — the one place where being certain
 * matters, so it computes the standard rather than approximating it.
 */
function checksumValid(words, index) {
  const n = words.length;
  if (!VALID_LENGTHS.includes(n)) return false;

  // Each word contributes 11 bits. Built as a bit string rather than with bit arithmetic because 264 bits
  // does not fit in a JS number and the clarity is worth more than the microseconds here.
  let bits = '';
  for (const w of words) {
    const i = index.get(w);
    if (i === undefined) return false;
    bits += i.toString(2).padStart(11, '0');
  }

  const checksumBits = n / 3;            // 12 words -> 4, 24 words -> 8
  const entropyBits = bits.length - checksumBits;
  if (entropyBits % 8 !== 0) return false;

  const entropy = Buffer.alloc(entropyBits / 8);
  for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);

  const hash = crypto.createHash('sha256').update(entropy).digest();
  let hashBits = '';
  for (const b of hash) hashBits += b.toString(2).padStart(8, '0');

  return bits.slice(entropyBits) === hashBits.slice(0, checksumBits);
}

/**
 * Scan a block of text. Returns findings with LOCATIONS ONLY.
 *
 * Three outcomes rather than two, for the same reason every other check in this codebase has three:
 *   confirmed  - the checksum validates. This IS a recovery phrase.
 *   wordlist_run - 12+ consecutive wordlist words whose checksum does not validate. Reported because a
 *                  mis-transcribed or partial phrase still points at where someone keeps them, but never
 *                  called a seed: calling it one would train the reader to ignore the confirmed ones.
 * A run shorter than 12 is not reported at all. Twelve is the floor of the standard, and reporting below it
 * would fire on ordinary prose forever.
 */
const OFFSET_SLACK = 3;

/**
 * Above this many DISTINCT wordlist words in one file, the file is carrying the wordlist rather than a phrase.
 *
 * Found the hard way, on the first run against a real machine: this reported `exposed` on a paywall template
 * that embeds a minified wallet library, and the library embeds all 2048 BIP-39 words. A 15-word window inside
 * that region passed the checksum by chance and was reported as a confirmed recovery phrase.
 *
 * The bounded offset search was supposed to prevent exactly that, and it did — on the axis I had thought about.
 * Minified code splits the wordlist region into thirty-odd separate runs, and each run then gets its own
 * bounded search: roughly 30 runs x 4 offsets x 5 lengths is 600 checksum tests in one file, at 1/16 each for a
 * 12-word window. A coincidental pass is not a risk there, it is arithmetic. I had capped the multiplicity
 * inside a run and left the NUMBER OF RUNS unbounded, which is the same problem rotated ninety degrees.
 *
 * The discriminator is density, and the file carries its own refutation. A note holding a seed contains 12 to
 * 24 wordlist words in total. A wallet library contains hundreds. 200 sits far above any real phrase — even
 * four separate 24-word phrases in one file is 96 — and far below what any wordlist carrier looks like.
 */
const WORDLIST_CARRIER_THRESHOLD = 200;

function scanText(text, index, { minRun = 12 } = {}) {
  const findings = [];

  // Tokenised across the WHOLE text, not per line, because the commonest way a person writes a seed phrase
  // down is a numbered vertical list — one word per line. A per-line scan found the phrase inside a note, a
  // comma-separated line and a JSON blob, and missed the numbered list entirely: the format people actually
  // use. Digits and punctuation are not tokens at all rather than separators, which is what lets "1. abandon"
  // on twelve lines read as twelve consecutive words.
  const tokens = [];
  const lines = String(text).split(/\r?\n/);
  for (let ln = 0; ln < lines.length; ln++) {
    for (const w of lines[ln].toLowerCase().match(/[a-z]+/g) || []) tokens.push({ w, line: ln + 1 });
  }

  // Density first, before any checksum is computed. If this file is carrying the wordlist, no window inside it
  // can mean anything, and running the search anyway would only produce the coincidence described above.
  const distinct = new Set();
  for (const t of tokens) if (index.has(t.w)) distinct.add(t.w);
  if (distinct.size >= WORDLIST_CARRIER_THRESHOLD) {
    return [{ line: 1, endLine: lines.length, words: distinct.size, verdict: 'wordlist_file',
      note: distinct.size + ' distinct BIP-39 words in one file. This file CARRIES the wordlist — a wallet ' +
        'library, a language pack, or the list itself — so no phrase can be confirmed inside it and none is ' +
        'claimed. Not a finding about your keys.' }];
  }

  let run = [];
  const flush = () => {
    if (run.length >= minRun) findings.push(judgeRun(run, index));
    run = [];
  };
  for (const t of tokens) {
    if (index.has(t.w)) run.push(t);
    else flush();
  }
  flush();
  return findings;
}

/**
 * Decide what a run of consecutive wordlist words actually is.
 *
 * The window search is deliberately BOUNDED, and that bound is the whole correctness argument. A 12-word
 * checksum is 4 bits, so any 12 wordlist words pass it with probability 1/16. Searching every offset inside a
 * long run therefore MANUFACTURES hits: a run of 200 words contains 189 twelve-word windows, so a "confirmed"
 * phrase is not merely possible there, it is near-certain — and it would be pure coincidence reported as proof.
 * Run length would have become a false-positive multiplier, on a tool whose entire value is that a confirmed
 * hit is a fact.
 *
 * A real phrase in a file starts where it starts. So offsets are searched only up to OFFSET_SLACK, which
 * covers a stray wordlist word sitting just before the phrase ("backup: abandon abandon …") and nothing more.
 * That caps the expected coincidental pass at about 4/16 per run, and only for runs that are already anomalous
 * — twelve consecutive words drawn from a 2048-word list does not happen in prose.
 */
function judgeRun(run, index) {
  const words = run.map((t) => t.w);
  const line = run[0].line;
  const endLine = run[run.length - 1].line;
  const span = endLine > line ? ' spanning lines ' + line + '-' + endLine : '';

  let best = null;
  for (const len of [...VALID_LENGTHS].reverse()) {          // longest first: a 24 must not report as a 12
    if (len > words.length) continue;
    const maxStart = Math.min(OFFSET_SLACK, words.length - len);
    for (let start = 0; start <= maxStart; start++) {
      if (checksumValid(words.slice(start, start + len), index)) { best = { len, start }; break; }
    }
    if (best) break;
  }

  if (best) {
    return { line, endLine, words: best.len, verdict: 'confirmed',
      note: 'A valid BIP-39 checksum' + span + '. This is a recovery phrase, in cleartext, at this location.' };
  }
  return { line, endLine, words: words.length, verdict: 'wordlist_run',
    note: words.length + ' consecutive BIP-39 words' + span + ' with no valid checksum at the start of the run. ' +
      'Not a phrase as written — a partial, a transcription error, or a document dense in ordinary words that ' +
      'happen to be on the list. Worth a human look; never treated as a seed.' };
}

/**
 * scanPaths — walk the places a person actually leaves a phrase, and report LOCATIONS.
 *
 * The defaults are where people put things they mean to keep: notes, a desktop file, a downloads folder they
 * never emptied. Not the whole disk — a scan that takes an hour does not get run, and this one has to be
 * runnable on a bad afternoon.
 *
 * Every limit reports itself. Caps that stay quiet are how a partial scan gets read as a clean bill of health,
 * which on this particular question is the worst possible failure: "no phrase found" would mean "I did not
 * look there" and be indistinguishable from safety. So `skipped` carries a count per reason, and `complete`
 * is false the moment anything was left out.
 */
const TEXTUAL = new Set(['.txt', '.md', '.rtf', '.csv', '.json', '.log', '.note', '.text', '.yml', '.yaml',
  '.html', '.htm', '.xml', '.ini', '.cfg', '.conf', '.env', '.bak', '.js', '.ts', '.py', '.sh', '.ps1']);
const MAX_BYTES = 8 * 1024 * 1024;

function scanPaths(paths, index, { maxFiles = 20000 } = {}) {
  const fs = require('node:fs');
  const path = require('node:path');
  const findings = [];
  const skipped = { tooBig: 0, unreadable: 0, notTextual: 0, overFileCap: 0 };
  let scanned = 0, bytes = 0;

  const walk = (dir, depth) => {
    if (depth > 6) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { skipped.unreadable++; return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === '.git' || e.name === 'AppData') continue;
        walk(p, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      if (scanned >= maxFiles) { skipped.overFileCap++; continue; }
      if (!TEXTUAL.has(path.extname(e.name).toLowerCase())) { skipped.notTextual++; continue; }
      let st;
      try { st = fs.statSync(p); } catch { skipped.unreadable++; continue; }
      if (st.size > MAX_BYTES) { skipped.tooBig++; continue; }
      let text;
      try { text = fs.readFileSync(p, 'utf8'); } catch { skipped.unreadable++; continue; }
      scanned++; bytes += text.length;
      for (const f of scanText(text, index)) findings.push({ file: p, ...f });
    }
  };

  for (const root of paths) {
    try { if (!fs.existsSync(root)) { skipped.unreadable++; continue; } } catch { skipped.unreadable++; continue; }
    walk(root, 0);
  }

  const confirmed = findings.filter((f) => f.verdict === 'confirmed');
  // A wordlist_file is explicitly "not a finding about your keys", so it must not drag the verdict to
  // inconclusive. On a developer's machine there are dozens of wallet libraries, and letting them decide the
  // headline made the first real run read as "we are not sure about your seed" when the honest answer was
  // "nothing found, and 26 of those files were libraries". Only a real ambiguity — a wordlist run with no
  // valid checksum — is inconclusive.
  const ambiguous = findings.filter((f) => f.verdict === 'wordlist_run');
  const totalSkipped = Object.values(skipped).reduce((a, b) => a + b, 0);
  return {
    scanned, bytes, findings, confirmed: confirmed.length, skipped,
    complete: totalSkipped === 0,
    verdict: confirmed.length ? 'exposed' : ambiguous.length ? 'inconclusive' : 'nothing_found',
    disclosure: 'This never says "safe". A confirmed hit is a FACT — the BIP-39 checksum validated — and the ' +
      'phrase is not printed here on purpose: this output ends up in terminal buffers, logs and screenshots, ' +
      'which is not where a seed belongs. Go and look at the file. "nothing_found" means nothing was found IN ' +
      'WHAT WAS READ: it cannot see images, PDFs, password managers, browser storage, encrypted archives, ' +
      'deleted-but-recoverable files, or anything outside the paths given. Check `skipped` and `complete`.',
  };
}

/** Where people actually keep notes, per platform. Deliberately not the whole home directory. */
function defaultPaths() {
  const path = require('node:path');
  const home = process.env.USERPROFILE || process.env.HOME || '.';
  return [
    path.join(home, 'Documents'), path.join(home, 'Desktop'), path.join(home, 'Downloads'),
    path.join(home, 'OneDrive', 'Documents'), path.join(home, 'OneDrive', 'Desktop'),
    path.join(home, 'Notes'),
  ];
}

module.exports = { loadWordlist, checksumValid, scanText, judgeRun, scanPaths, defaultPaths, VALID_LENGTHS };
