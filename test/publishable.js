#!/usr/bin/env node
'use strict';
/**
 * The gate this repo has to pass before it is published.
 *
 * It exists because of a specific failure, not as a formality. `lib/wallet-watch.js` was copied in from the
 * private repo it was written in, carrying `require('./screen')` for a file that was never copied with it.
 * The whole MCP server then died on load — every tool gone, not just that one. The smoke test I had run
 * passed, because I ran it BEFORE adding the dependency and then copied the changed file over without
 * re-running it. A stale test feels exactly like a passing one, which is why "be more careful" is not a fix
 * and this file is.
 *
 * Three checks, in order of how early they catch the fault:
 *   1. STATIC  — every relative `require` in the package resolves to a file that is actually here.
 *   2. LOAD    — the module index really exposes every entry point it claims.
 *   3. BOOT    — the MCP server starts and lists every tool, over the same stdio a client would use.
 *
 * Check 1 is the one that would have caught the fault above, and it needs no network and no server. Checks 2
 * and 3 are still here because a require can resolve and the export still be missing, and a module can load
 * and the server still fail to register it — each check has caught something the others could not.
 *
 * Zero dependencies and zero network, so it runs anywhere, including in a hook.
 */
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const fail = [];
const note = (s) => process.stdout.write(s + '\n');

// ---------------------------------------------------------------- 1. STATIC
// Read the source and resolve every relative require by hand. Deliberately NOT by requiring the files: a
// require executes the module, so a file that crashes for an unrelated reason would hide the missing-file
// answer behind its own error. Text is enough to answer "is the target present".
function sources(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === 'node_modules' || e.name === '.git' ? [] : sources(p);
    return e.name.endsWith('.js') ? [p] : [];
  });
}
// Line by line, and comment lines are skipped. The first version of this scan matched the whole file text and
// so flagged the word `require('./screen')` sitting inside the comment that EXPLAINS the bug — a scanner that
// reads prose as code reports faults that do not exist, which is the same disease as reporting doors closed
// that were never checked, pointed the other way.
const isComment = (line) => /^\s*(\/\/|\*|\/\*)/.test(line);

// A require is allowed to resolve to nothing ONLY if the source says so on that line. An absence has to be
// claimed to be tolerated: silence means broken. That asymmetry is the whole value — it is what makes the next
// file copied in from another repo fail loudly instead of taking the server down on load.
const OPTIONAL = 'optional-require';

const files = sources(ROOT);
let requires = 0, optional = 0;
for (const f of files) {
  const lines = fs.readFileSync(f, 'utf8').split('\n');
  for (const line of lines) {
    if (isComment(line)) continue;
    for (const m of line.matchAll(/require\(\s*['"](\.[^'"]+)['"]\s*\)/g)) {
      requires++;
      const target = path.resolve(path.dirname(f), m[1]);
      const found = ['', '.js', '.json', '/index.js'].some((ext) => fs.existsSync(target + ext));
      if (found) continue;
      if (line.includes(OPTIONAL)) { optional++; continue; }
      fail.push(`${path.relative(ROOT, f)} requires '${m[1]}' — NOT IN THIS REPO (and not marked ${OPTIONAL})`);
    }
  }
}
note(`static: ${requires} relative requires across ${files.length} files -> ${fail.length ? `${fail.length} BROKEN` : 'all resolve'}` +
  (optional ? ` (${optional} declared ${OPTIONAL}, absent by design)` : ''));

// A marked-optional require is only safe if it is actually guarded. The marker is a claim; this checks it.
for (const f of files) {
  const src = fs.readFileSync(f, 'utf8');
  if (!src.includes(OPTIONAL)) continue;
  for (const [i, line] of src.split('\n').entries()) {
    if (isComment(line) || !line.includes(OPTIONAL) || !line.includes('require(')) continue;
    // Walk back for the `try {` that must enclose it. Cheap and good enough: an optional require is a one-line
    // idiom at the top of a file, never buried twenty lines inside a function.
    const before = src.split('\n').slice(Math.max(0, i - 6), i).join('\n');
    if (!/\btry\s*{/.test(before)) {
      fail.push(`${path.relative(ROOT, f)}:${i + 1} is marked ${OPTIONAL} but is not inside a try — the marker is a lie and the module will still crash on load`);
    }
  }
}

// Bare requires must be either node builtins or declared dependencies. This package advertises zero deps, so
// an undeclared import would install fine from git and explode from npm.
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const declared = new Set(Object.keys(pkg.dependencies || {}));
const builtin = new Set(require('node:module').builtinModules);
for (const f of files) {
  for (const m of fs.readFileSync(f, 'utf8').matchAll(/require\(\s*['"]([^.'"][^'"]*)['"]\s*\)/g)) {
    const base = m[1].replace(/^node:/, '').split('/')[0];
    if (!builtin.has(base) && !declared.has(m[1]) && !declared.has(base)) {
      fail.push(`${path.relative(ROOT, f)} requires '${m[1]}' which is neither a node builtin nor a declared dependency`);
    }
  }
}

// ---------------------------------------------------------------- 2. LOAD
const ENTRY = ['vetMeme', 'scanRugOne', 'classifyB20', 'traceFeeder', 'followTron', 'hexToTron',
  'assessRecoveryOffer', 'vetApproach', 'checkApprovals', 'allowancesBatch', 'watchWallet', 'vetAgent', 'scanPaths', 'checksumValid', 'scanKeyPaths', 'findVaults'];
let mod = null;
try {
  mod = require(path.join(ROOT, 'lib', 'index.js'));
  const missing = ENTRY.filter((f) => typeof mod[f] !== 'function');
  if (missing.length) fail.push(`lib/index.js does not export: ${missing.join(', ')}`);
  note(`load:   lib/index.js -> ${missing.length ? 'MISSING ' + missing.length : `all ${ENTRY.length} entry points`}`);
} catch (e) {
  fail.push(`lib/index.js will not load: ${e.message}`);
  note(`load:   lib/index.js -> THROWS ${e.message}`);
}

// ---------------------------------------------------------------- 3. BOOT
// Over real stdio, because that is the only interface a client has. A server whose module loads and whose
// tools/list is empty is still a dead server, and only this check can tell the difference.
const TOOLS = ['vet_meme', 'rug_powers', 'b20_authentic', 'launch_funder', 'trace_theft',
  'recovery_offer', 'vet_approach', 'open_approvals', 'watch_wallet', 'vet_agent', 'seed_exposure', 'key_exposure'];

const p = spawn(process.execPath, [path.join(ROOT, 'bin', 'onchain-forensics-mcp.js')], { stdio: ['pipe', 'pipe', 'pipe'] });
let buf = '', stderr = '';
const got = [];
p.stdout.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (line.trim()) try { got.push(JSON.parse(line)); } catch { /* not a frame */ }
  }
});
p.stderr.on('data', (c) => { stderr += c; });
const send = (o) => p.stdin.write(JSON.stringify(o) + '\n');
send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'publishable', version: '1' } } });
send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });

setTimeout(() => {
  p.kill();
  const listed = ((got.find((m) => m.id === 2) || {}).result || {}).tools || [];
  const names = listed.map((t) => t.name);
  const absent = TOOLS.filter((t) => !names.includes(t));
  if (absent.length) fail.push(`server does not expose: ${absent.join(', ')}${stderr ? ` (stderr: ${stderr.split('\n')[0]})` : ''}`);

  // Every listed tool must carry a schema. A tool with no inputSchema cannot be called by a strict client,
  // so an entry in tools/list is not by itself proof the tool is usable.
  for (const t of listed) {
    if (!t.inputSchema || t.inputSchema.type !== 'object') fail.push(`tool ${t.name} has no usable inputSchema`);
    if (!t.description || t.description.length < 40) fail.push(`tool ${t.name} has no real description`);
  }
  note(`boot:   tools/list -> ${names.length} tools${absent.length ? `, MISSING ${absent.join(', ')}` : ''}`);

  // ---------------------------------------------------------------- 4. DOCS
  // The README described "Seven checks" while the server exposed ten, and earlier it described seven while the
  // server exposed seven and the repo contained ten — the count drifted in both directions. Documentation
  // drift is not cosmetic on a security tool: someone deciding whether to trust this reads the README, and a
  // README that overstates the surface is the same category of error as a scanner that overstates a check.
  // So the count and the table are derived from the running server, by a machine, every run.
  if (names.length) {
    const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
    const WORD = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
      'eleven', 'twelve'][names.length];
    if (WORD && !new RegExp(`\\b${WORD}\\s+checks\\b`, 'i').test(readme)) {
      const claimed = (readme.match(/\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+checks\b/i) || [])[1];
      fail.push(`README says "${claimed || '(no count at all)'} checks" but the server exposes ${names.length} — say "${WORD} checks"`);
    }
    const undocumented = names.filter((n) => !readme.includes('`' + n + '`'));
    if (undocumented.length) fail.push(`README does not document: ${undocumented.join(', ')}`);
    // And the reverse: a tool the README promises but the server does not have is the worse direction.
    for (const m of readme.matchAll(/^\| `([a-z_]+)` \|/gm)) {
      if (!names.includes(m[1])) fail.push(`README's tool table promises \`${m[1]}\`, which the server does not expose`);
    }
    note(`docs:   README -> ${fail.some((f) => f.startsWith('README')) ? 'DRIFTED' : `"${WORD} checks", all ${names.length} documented`}`);
  }

  note('');
  if (fail.length) {
    note(`NOT PUBLISHABLE — ${fail.length} problem${fail.length > 1 ? 's' : ''}:`);
    for (const f of fail) note('  - ' + f);
    process.exit(1);
  }
  // Counted, not asserted. This line said 'all 10 tools' while the gate below it was checking eleven — a
  // hardcoded count drifting away from what it summarises, in the file whose fourth check exists to catch
  // exactly that. The lesson keeps having to be relearned in each new place a number is written by hand.
  note('PUBLISHABLE: requires resolve, index exports, server boots and lists all ' + names.length + ' tools.');
}, 8000);
