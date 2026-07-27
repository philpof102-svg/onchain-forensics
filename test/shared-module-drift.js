#!/usr/bin/env node
'use strict';
/**
 * DERIVE DES MODULES PARTAGES AVEC biii.
 *
 * Ce depot embarque des COPIES A LA MAIN de plusieurs modules de `biii/lib/` — feeder, holders-health,
 * meme, multicall, wallet-watch, approvals, agent-vet… Il n'existe aucun script de synchronisation, et
 * rien ne signalait la divergence.
 *
 * CE QUE CA A COUTE, le 2026-07-27: cinq defauts ont ete trouves et corriges dans biii pendant la
 * journee. `onchain-forensics@0.1.1`, publie le matin meme, portait toujours les anciennes copies. Un
 * `npm install onchain-forensics` rendait donc une concentration de porteurs CONSTANTE et un ecart
 * financement-deploiement TOUJOURS NUL — les deux mesures verifiees ici, sur ce depot, avant correction.
 *
 * C'est la lecon de `b20.js` qui se rejoue: le meme code a deux endroits, et un seul repare. Ce matin-la
 * le marqueur B20 avait justement ete corrige DANS LES DEUX; le reste de la journee ne l'a pas ete.
 *
 * ⚠️ CE FICHIER NE COMPARE PAS LES OCTETS. Les copies sont legitimement adaptees (le paquet forensique
 * n'expose pas la meme surface). Il verifie les PROPRIETES que les correctifs ont etablies: si une copie
 * regresse vers l'ancienne forme, un cas rougit ici, meme si le fichier a diverge par ailleurs.
 *
 * Aucun reseau: tout est injecte.
 */
const assert = require('node:assert');

let pass = 0, fail = 0;
const files = [];
const t = (nom, fn) => files.push([nom, fn]);

const ZERO = '0x' + '0'.repeat(40);
const adr = (n) => '0x' + String(n).padStart(40, '0');

console.log('derive des modules partages avec biii — proprietes, pas octets');

/* ── holders-health ──────────────────────────────────────────────────────────────────────────────── */

t('la concentration des porteurs VARIE selon la distribution', () => {
  /* Valait 100 pour tout: numerateur et denominateur etaient la meme somme (celle du top 10). Comme
   * rugScore ajoute 50 au-dessus de 80, il valait au moins 80 partout et `healthy` etait toujours faux —
   * un echec dans le bon sens, qui n'observait rien. Deux cas OPPOSES: un seul passerait aussi contre
   * une constante. */
  const { computeHealthMetrics } = require('../lib/holders-health.js');
  const mint = (to, v) => ({ from: ZERO, to, value: BigInt(v), blockNumber: 1 });
  const baleine = computeHealthMetrics([mint(adr(1), 1000000)]).top10Concentration;
  const plat = computeHealthMetrics(Array.from({ length: 200 }, (_, i) => mint(adr(i + 1), 100))).top10Concentration;
  assert.strictEqual(baleine, 100, 'un porteur unique EST le top 10');
  assert.ok(plat < 20, '200 porteurs a parts egales: le top 10 en detient ~5 %, vu ' + plat);
  assert.notStrictEqual(baleine, plat, 'deux distributions opposees DOIVENT donner deux valeurs');
});

/* ── feeder ──────────────────────────────────────────────────────────────────────────────────────── */

const faussesReponses = (creation) => async (url) => {
  if (/\/transactions\/0x/.test(url)) return creation;
  if (url.includes('/transactions?filter=to')) {
    return { items: [{ from: { hash: '0xFINANCEUR' }, value: '1000000000000000000', timestamp: '2026-01-01T10:00:00Z' }] };
  }
  if (url.includes('/transactions?filter=from')) return { items: [] };
  if (url.includes('/addresses/')) return { creator_address_hash: '0xDEPLOYEUR', creation_transaction_hash: '0xcreation' };
  return null;
};

t('deployedAt est la date de DEPLOIEMENT, pas une copie de fundedAt', async () => {
  /* `deployedAt = first.timestamp` — et `first` est le transfert ENTRANT. Les deux champs sortaient
   * identiques sur toute entree, donc l'ecart valait ZERO partout: « finance et deploye dans la meme
   * seconde », la lecture la plus incriminante possible, servie indistinctement. */
  const { traceFeeder } = require('../lib/feeder.js');
  const r = await traceFeeder('base', '0xTOKEN', { fetchImpl: faussesReponses({ timestamp: '2026-01-01T12:30:00Z' }) });
  assert.notStrictEqual(r.deployedAt, r.fundedAt, 'les deux champs identiques = le bug d origine');
  assert.strictEqual(r.fundingToDeployMs, 2.5 * 3600 * 1000);
});

t('l ecart financement->deploiement VARIE, et l absence de date donne null', async () => {
  const { traceFeeder } = require('../lib/feeder.js');
  const proche = await traceFeeder('base', '0xT', { fetchImpl: faussesReponses({ timestamp: '2026-01-01T12:30:00Z' }) });
  const loin = await traceFeeder('base', '0xT', { fetchImpl: faussesReponses({ timestamp: '2026-01-05T10:00:00Z' }) });
  const sans = await traceFeeder('base', '0xT', { fetchImpl: faussesReponses(null) });
  assert.strictEqual(proche.freshlyFunded, true, 'moins de 6 h');
  assert.strictEqual(loin.freshlyFunded, false, 'quatre jours');
  assert.strictEqual(sans.freshlyFunded, null, 'indeterminable — null, jamais false');
  assert.strictEqual(sans.fundingToDeployMs, null);
});

/* ── multicall ───────────────────────────────────────────────────────────────────────────────────── */

t('une reponse REUSSIE mais illisible est NON LUE, pas un revert', () => {
  /* `success` vrai + donnee non decodable = l'appel a abouti et son retour est illisible. Le classer en
   * `false` (« repondu definitivement: aucune allocation ») laisse le balayage se declarer complet, ce
   * qui autorise wallet-watch a effacer de sa memoire une allocation jamais lue. */
  const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'lib', 'multicall.js'), 'utf8');
  assert.match(src, /catch \{ return null; \}/, 'le decodage rate doit rendre null (non lu)');
  assert.ok(!/try \{ return BigInt\(r\.data\); \} catch \{ return false; \}/.test(src),
    'l ancienne forme ne doit pas revenir');
  /* La borne INVERSE: un vrai revert reste une reponse definitive, sinon le balayage n est jamais
   * complet et la reference n est jamais rafraichie. */
  assert.match(src, /if \(!r\.success \|\| r\.data === '0x'\) return false;/,
    'un revert reel reste `false`');
  assert.match(src, /if \(!r\) return null;/, 'aucune reponse reste NON LU');
});

/* ── wallet-watch ────────────────────────────────────────────────────────────────────────────────── */

t('la reference n est remplacee que sur un balayage COMPLET', () => {
  /* Sur un balayage partiel, garder seulement ce qui a pu etre lu fait disparaitre les allocations non
   * lues — qui ressortent au run suivant en « Someone granted it since », une affirmation fausse sur la
   * date d octroi. */
  const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'lib', 'wallet-watch.js'), 'utf8');
  assert.match(src, /ap\.ok === true && ap\.complete === true/,
    '`complete` absent doit compter comme incomplet (=== true, pas !== false)');
  /* ⚠️ ON CHERCHE LA FORME EXACTE DU CODE, pas un fragment. Le premier jet cherchait
   * `approvals: liveKeys.length || ap.ok ? liveKeys :` — et le COMMENTAIRE du module cite justement
   * cette ligne pour expliquer ce qui a ete retire. Le test rougissait donc sur sa propre documentation.
   * Une assertion sur du texte source ne distingue pas le code de ce qui le decrit; il faut viser une
   * chaine que seul le code porte — ici la fin `[...known.approvals],`, que le commentaire abrege. */
  assert.ok(!/approvals: liveKeys\.length \|\| ap\.ok \? liveKeys : \[\.\.\.known\.approvals\],/.test(src),
    'l ancienne ligne de precedence ne doit pas revenir');
});

t('le plafond de contreparties garde les RECENTES', () => {
  /* `[...known, ...seenNow].slice(0, 500)` coupe la fin, donc seenNow: passe 500 contreparties, une
   * nouvelle etait alertee, jamais enregistree, et realertait a chaque run indefiniment. */
  const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'lib', 'wallet-watch.js'), 'utf8');
  assert.match(src, /\[\.\.\.new Set\(\[\.\.\.seenNow, \.\.\.known\.counterparties\]\)\]/,
    'ce qui vient d etre vu passe en tete');
  assert.match(src, /capped at/i, 'une troncature silencieuse se lit « tout est memorise »');
});

/* ── meme ────────────────────────────────────────────────────────────────────────────────────────── */

t('le filtre de chaine accepte slug ET identifiant, et refuse ce qu il ne sait pas traduire', () => {
  /* ⚠️ Ici c'etait un DURCISSEMENT, pas un verdict repare: rien ne coerce chainId dans ce depot, donc
   * l ancienne comparaison exacte marchait pour un slug. Ce qu on gagne est la tolerance d entree et un
   * refus EXPLICITE au lieu d un vide accidentel. Dit tel quel pour ne pas surclamer. */
  const { candidatesFrom } = require('../lib/meme.js');
  const paires = [
    { chainId: 'solana', baseToken: { address: '0xS', symbol: 'X' }, liquidity: { usd: 9e6 } },
    { chainId: 'base', baseToken: { address: '0xB', symbol: 'X' }, liquidity: { usd: 1e3 } },
  ];
  for (const forme of ['base', 'BASE', 8453, '8453']) {
    const c = candidatesFrom(paires, 'X', forme);
    assert.strictEqual(c.length, 1, 'forme ' + JSON.stringify(forme));
    assert.strictEqual(c[0].chain, 'base', 'demander Base ne rend jamais une autre chaine');
  }
  assert.deepStrictEqual(candidatesFrom(paires, 'X', 'chaine-inexistante'), [],
    'une chaine non traduisible rend ZERO candidat, jamais toutes les chaines');
  assert.strictEqual(candidatesFrom(paires, 'X').length, 2, 'sans filtre, toutes concourent');
});

(async () => {
  for (const [nom, fn] of files) {
    try { await fn(); pass++; console.log('  ok   ' + nom); }
    catch (e) { fail++; console.log('  FAIL ' + nom + '\n       ' + e.message); }
  }
  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  if (pass + fail !== files.length) {
    console.log('✗ ' + files.length + ' cas empiles mais ' + (pass + fail) + ' deroules');
    process.exit(1);
  }
  process.exit(fail ? 1 : 0);
})();
