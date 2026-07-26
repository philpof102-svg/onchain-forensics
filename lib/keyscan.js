'use strict';
/**
 * keyscan — the key material that is actually findable on a machine, and where it is.
 * ==================================================================================
 * `seedscan` answers "is a recovery phrase written down in cleartext". This answers the question that came
 * after it, and it came from a real theft: the stolen key was never in a text file. It was exfiltrated. So the
 * useful question is not only "did you write it down" but "what key material exists on this disk at all, and
 * which of it is readable without a password".
 *
 * The trap here is the same one the wordlist scan walked into, wearing different clothes. A secp256k1 private
 * key is 64 hex characters — and so is every SHA-256 hash, every git commit id in a long-form log, every
 * transaction hash in a saved API response. Searching for 64 hex characters does not find keys, it finds
 * hashes, by the thousand. The VALUE SHAPE carries almost no information.
 *
 * Two things do:
 *
 *   1. STRUCTURE. A Web3 Secret Storage keystore is a JSON object with `version: 3` and a `crypto` member
 *      holding `ciphertext`, `kdf` and `mac`. Nothing else looks like that. It is a certainty, not a score —
 *      and it is also GOOD news when found, because a keystore is encrypted: the finding is "this is your
 *      wallet file, and it is only as strong as its password", not "you are exposed".
 *
 *   2. THE LABEL. Cleartext keys are almost always named by the thing that needs them: `PRIVATE_KEY=`,
 *      `"privateKey":`, `DEPLOYER_KEY`, `--private-key`. The label is what separates a key from a hash, so
 *      this matches on the label and then checks the value's shape — never the other way round.
 *
 * ═══ SAME RULE AS seedscan ═══
 * It NEVER outputs key material. Not a prefix, not a suffix, not a truncated preview. File and line only.
 * A four-byte prefix narrows a brute force and there is no version of "just the first few characters" that is
 * safe to put in a log. Reporting the location is enough: the owner goes and looks.
 *
 * Read-only. No network. It never decrypts anything and never derives an address from a key it found — doing
 * that would mean holding the key in memory for longer than it takes to decide the value is key-shaped.
 */

// secp256k1 group order. A valid private key is 0 < k < n. This rejects all-zeros, all-ffs, and anything at or
// above the order — a weak filter on its own, since n is within a hair of 2^256, but free and it costs nothing
// to refuse to call a mathematically impossible value a key.
const SECP256K1_N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

const HEX64 = /(?:0x)?([0-9a-fA-F]{64})/;

// Labels that mean "the thing after this is used to sign". `pk` is deliberately absent: it collides with
// primary-key columns in every SQL dump on earth, and one false positive on a database schema would be enough
// for someone to stop running this.
const KEY_LABEL = /(private[_\s-]?key|privatekey|priv[_\s-]?key|secret[_\s-]?key|signer[_\s-]?key|deployer[_\s-]?key|wallet[_\s-]?key|owner[_\s-]?key|keeper[_\s-]?key|eth[_\s-]?key|account[_\s-]?key)/i;

// Labels that mean "the thing after this is a digest, not a secret". Checked FIRST, because a line reading
// `PRIVATE_KEY_HASH=...` is a hash and calling it a key would be exactly the confident-wrong-answer this
// codebase keeps refusing to produce.
const DIGEST_LABEL = /(hash|digest|sha|checksum|commit|txid|tx[_\s-]?id|merkle|nonce|salt|fingerprint|etag)/i;

function isPlausibleScalar(hex) {
  let v;
  try { v = BigInt('0x' + hex); } catch { return false; }
  return v > 0n && v < SECP256K1_N;
}

/**
 * Is this JSON text a Web3 Secret Storage keystore? Structural, so it is a yes/no rather than a guess.
 * Returns null when it is not, or { version, kdf, cipher } when it is — never any part of the ciphertext.
 */
function readKeystore(text) {
  if (text.length > 200000) return null;               // a keystore is small; anything huge is something else
  let j;
  try { j = JSON.parse(text); } catch { return null; }
  if (!j || typeof j !== 'object') return null;
  const c = j.crypto || j.Crypto;
  if (!c || typeof c !== 'object') return null;
  if (typeof c.ciphertext !== 'string' || typeof c.kdf !== 'string' || typeof c.mac !== 'string') return null;
  return {
    version: j.version === undefined ? null : j.version,
    kdf: c.kdf,
    cipher: typeof c.cipher === 'string' ? c.cipher : null,
    // The address is in the file in cleartext by design and is public information, so reporting it is safe and
    // it is the one thing that makes the finding actionable: it tells you WHICH wallet this file is.
    address: typeof j.address === 'string' && /^(0x)?[0-9a-fA-F]{40}$/.test(j.address) ? j.address : null,
  };
}

/**
 * Scan one file's text. Returns findings with LOCATIONS ONLY.
 *   keystore_file  - a wallet file. Encrypted. Not an exposure, but it is key material and worth knowing about.
 *   cleartext_key  - a key-shaped value next to a key label. This is the bad one.
 *   labelled_only  - a key label whose value is NOT key-shaped (a placeholder, an env var reference, a
 *                    redaction). Reported low, because `PRIVATE_KEY=${SECRET}` is fine and saying otherwise
 *                    would train the reader to skim.
 */
/**
 * Paths that hold RETAINED COPIES: editor undo history, session caches, backup folders. A finding here is a
 * different fact from a finding in a live file, and the difference is the one people get wrong.
 *
 * ROTATING A SECRET DOES NOT REMOVE IT FROM THE DISK. Found on a real machine: one `.env` held three named
 * private keys, and an editor's file-history cache held eighteen previous versions of that same file — v3
 * through v20 — so every key the owner had ever rotated was still readable. 3481 retained versions, 104 MB, and
 * the folder had been copied into a "keep this across the reformat" backup, which would have carried every
 * historical secret forward into the clean machine.
 *
 * It also inverted the analysis that found it. Grouping key values by how many files they appear in looked like
 * a clean way to separate documented public test keys, which appear everywhere, from real secrets, which appear
 * once. The three values appearing in NINETEEN files were the real secrets — nineteen because eighteen of them
 * were versions of one file. Frequency measured how many copies existed, not how public the value was, and it
 * gave the confidently-wrong answer on the only case that mattered. Distinct logical files is the question;
 * versions of one file are one file.
 */
const RETAINED_PATH = /([\\/]\.claude[\\/]|file-history|[\\/]\.history[\\/]|[\\/]Local History[\\/]|BACKUP|[\\/]\.Trash[\\/]|[\\/]\$RECYCLE|[\\/]Recovery[\\/]|\.bak$|~$|@v\d+$)/i;

function scanKeyText(text, { filename = '' } = {}) {
  const findings = [];
  const retained = RETAINED_PATH.test(String(filename));

  const ks = readKeystore(text);
  if (ks) {
    findings.push({ line: 1, verdict: 'keystore_file',
      keystore: ks,
      note: 'A Web3 Secret Storage keystore (version ' + ks.version + ', kdf ' + ks.kdf + '). This is an ' +
        'ENCRYPTED wallet file, so finding it is not an exposure — but it is key material, and its strength is ' +
        'entirely its password. Anything that reads this disk now owns an offline cracking target' +
        (ks.address ? ' for ' + ks.address : '') + '.' });
    return findings;   // a keystore is one whole file; do not also line-scan its ciphertext
  }

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4000) continue;                  // minified bundle line: nothing readable is in there
    if (!KEY_LABEL.test(line)) continue;
    if (DIGEST_LABEL.test(line)) continue;             // "PRIVATE_KEY_HASH" is a digest, not a key

    const m = HEX64.exec(line);
    if (m && isPlausibleScalar(m[1])) {
      findings.push({ line: i + 1, verdict: retained ? 'retained_copy' : 'cleartext_key', retained,
        note: retained
          ? 'A cleartext key inside a RETAINED COPY — editor history, a session cache, a backup or a trash ' +
            'folder. Rotating the live secret does not remove this one: it is a snapshot of what the file used ' +
            'to say, and it is readable now. Delete the retained copies as well as rotating the key, and check ' +
            'that no backup folder is carrying them into a reinstalled machine.'
          : 'A key label and, on the same line, 64 hex characters that are a valid secp256k1 scalar. ' +
            'Treat the corresponding account as compromised from the moment anything untrusted read this disk. ' +
            'The value is deliberately not reproduced here.' });
    } else {
      findings.push({ line: i + 1, verdict: 'labelled_only',
        note: 'A key label whose value is not key-shaped — a placeholder, a variable reference, or a redaction. ' +
          'Almost always fine. Listed so the sweep is honest about what it looked at, not as a warning.' });
    }
  }
  return findings;
}

/**
 * Wallet vaults that live on disk as a matter of course. Their PRESENCE is the finding — nothing is opened,
 * nothing is parsed, nothing is copied. A browser-extension wallet keeps an encrypted vault in its LevelDB
 * store, and an infostealer's whole job is to take that directory and crack it later at leisure.
 *
 * This is here because it is the honest answer to "how was I robbed if my seed was never in a text file".
 * Nothing in `seedscan` could ever have found it, and reporting only what seedscan can see would have implied
 * a coverage this pair does not have.
 */
const EXTENSION_VAULTS = [
  { id: 'nkbihfbeogaeaoehlefnkodbefgpgknn', wallet: 'MetaMask' },
  { id: 'acmacodkjbdgmoleebolmdjonilkdbch', wallet: 'Rabby' },
  { id: 'bfnaelmomeimhlpmgjnjophhpkkoljpa', wallet: 'Phantom' },
  { id: 'hnfanknocfeofbddgcijnmhnfnkdnaad', wallet: 'Coinbase Wallet' },
  { id: 'ejbalbakoplchlghecdalmeeeajnimhm', wallet: 'MetaMask (Edge)' },
  { id: 'jnlgamecbpmbajjfhmmmlhejkemejdma', wallet: 'Braavos' },
  { id: 'aholpfdialjgjfhomihkjbmgjidlcdno', wallet: 'Exodus' },
  { id: 'fhbohimaelbohpjbbldcngcnapndodjp', wallet: 'Binance Wallet' },
];

function findVaults() {
  const fs = require('node:fs');
  const path = require('node:path');
  const home = process.env.USERPROFILE || process.env.HOME || '.';
  const browsers = [
    ['Chrome', path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data')],
    ['Edge', path.join(home, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data')],
    ['Brave', path.join(home, 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data')],
    ['Chrome (mac)', path.join(home, 'Library', 'Application Support', 'Google', 'Chrome')],
    ['Chrome (linux)', path.join(home, '.config', 'google-chrome')],
  ];
  const out = [];
  for (const [browser, base] of browsers) {
    let profiles;
    try { if (!fs.existsSync(base)) continue; profiles = fs.readdirSync(base, { withFileTypes: true }); } catch { continue; }
    for (const p of profiles) {
      if (!p.isDirectory()) continue;
      if (!/^(Default|Profile \d+)$/.test(p.name)) continue;
      for (const v of EXTENSION_VAULTS) {
        const dir = path.join(base, p.name, 'Local Extension Settings', v.id);
        let size = null;
        try {
          if (!fs.existsSync(dir)) continue;
          size = fs.readdirSync(dir).reduce((a, f) => {
            try { return a + fs.statSync(path.join(dir, f)).size; } catch { return a; }
          }, 0);
        } catch { continue; }
        out.push({ browser, profile: p.name, wallet: v.wallet, path: dir, bytes: size });
      }
    }
  }
  return out;
}

/**
 * scanKeyPaths — walk directories, group findings by the VALUE they contain without ever holding the value.
 *
 * Grouping is by a truncated SHA-256 of the key, which is what makes the report readable: one secret repeated
 * across nineteen files is one row, not nineteen. That grouping is also what exposed the retained-copy problem
 * — and the reason `distinctFiles` counts logical files rather than paths is that eighteen of those nineteen
 * were versions of a single `.env`, and counting paths made the real secrets look like published test keys.
 */
function scanKeyPaths(paths, { maxFiles = 40000 } = {}) {
  const fs = require('node:fs');
  const path = require('node:path');
  const crypto = require('node:crypto');
  const EXT = new Set(['.json', '.txt', '.md', '.js', '.ts', '.py', '.sh', '.ps1', '.yml', '.yaml',
    '.cfg', '.ini', '.bak', '.log', '.toml', '']);
  const skipped = { tooBig: 0, unreadable: 0, notTextual: 0, overFileCap: 0 };
  const findings = [];
  let scanned = 0, bytes = 0;

  const walk = (dir, depth) => {
    if (depth > 7) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { skipped.unreadable++; return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'out', 'build', '.next'].includes(e.name)) continue;
        walk(p, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      if (scanned >= maxFiles) { skipped.overFileCap++; continue; }
      const isEnv = /^\.env/.test(e.name);
      if (!isEnv && !EXT.has(path.extname(e.name).toLowerCase())) { skipped.notTextual++; continue; }
      let st;
      try { st = fs.statSync(p); } catch { skipped.unreadable++; continue; }
      if (st.size > 4 * 1024 * 1024) { skipped.tooBig++; continue; }
      let text;
      try { text = fs.readFileSync(p, 'utf8'); } catch { skipped.unreadable++; continue; }
      scanned++; bytes += text.length;
      for (const f of scanKeyText(text, { filename: p })) {
        if (f.verdict === 'labelled_only') continue;                  // placeholders are not a report
        findings.push({ file: p, ...f });
      }
    }
  };
  for (const root of paths) {
    try { if (!fs.existsSync(root)) { skipped.unreadable++; continue; } } catch { skipped.unreadable++; continue; }
    walk(root, 0);
  }

  // Fingerprint each finding's value so identical secrets collapse into one row. Re-read per finding rather
  // than kept from the first pass, so no key value is ever held in a structure that outlives the loop.
  const groups = new Map();
  for (const f of findings) {
    if (f.verdict !== 'cleartext_key' && f.verdict !== 'retained_copy') continue;
    let fp = 'unknown';
    try {
      const line = fs.readFileSync(f.file, 'utf8').split(/\r?\n/)[f.line - 1] || '';
      const m = HEX64.exec(line);
      if (m) fp = crypto.createHash('sha256').update(m[1].toLowerCase()).digest('hex').slice(0, 12);
    } catch { /* unreadable now: leave it ungrouped rather than guess */ }
    if (!groups.has(fp)) groups.set(fp, { fingerprint: fp, live: [], retained: [] });
    groups.get(fp)[f.verdict === 'retained_copy' ? 'retained' : 'live'].push(f.file + ':' + f.line);
  }

  const secrets = [...groups.values()].map((g) => ({
    fingerprint: g.fingerprint,
    liveLocations: g.live,
    retainedCopies: g.retained.length,
    // Logical files, not paths: retained copies of one file are one file. Counting paths is what made three
    // real secrets look like published test keys.
    distinctFiles: new Set([...g.live, ...g.retained].map((s) => s.replace(/@v\d+.*$/, '').replace(/:\d+$/, ''))).size,
  })).sort((a, b) => b.liveLocations.length - a.liveLocations.length);

  const keystores = findings.filter((f) => f.verdict === 'keystore_file');
  const liveKeys = secrets.filter((s) => s.liveLocations.length).length;
  const totalSkipped = Object.values(skipped).reduce((a, b) => a + b, 0);
  return {
    scanned, bytes, skipped, complete: totalSkipped === 0,
    secrets, keystores, vaults: findVaults(),
    verdict: liveKeys ? 'cleartext_keys_present' : secrets.length ? 'only_retained_copies' : 'no_cleartext_key',
    disclosure: 'No key material appears in this output, by design — fingerprints are truncated hashes and ' +
      'locations are paths. `retainedCopies` is the count that people miss: rotating a live secret does not ' +
      'remove the editor-history and backup snapshots of what the file used to say. Wallet vaults are reported ' +
      'by PRESENCE only; nothing is opened, parsed or copied. This cannot see encrypted archives, password ' +
      'managers, or anything outside the paths given, so a clean result is not a clean machine.',
  };
}

module.exports = { scanKeyText, scanKeyPaths, readKeystore, findVaults, isPlausibleScalar,
  KEY_LABEL, DIGEST_LABEL, RETAINED_PATH, EXTENSION_VAULTS };
