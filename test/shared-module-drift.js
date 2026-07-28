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

/* ── UNE GARDE QUI DECOUVRE, AU LIEU DE VERIFIER UNE LISTE ───────────────────────────────────────────
 * Le 2026-07-28, ce fichier est passe 7/7 pendant que la copie d'agent-vet portait exactement le defaut
 * qui venait d'etre corrige dans biii (le crible known-bad aplati sur un booleen). Il ne pouvait pas le
 * voir: chaque cas ci-dessus epingle une propriete ECRITE A LA MAIN, donc la garde ne connait que les
 * derives auxquelles quelqu'un a deja pense. C'est un inventaire, pas un detecteur.
 *
 * Ce cas-ci compare les ENSEMBLES DE CLES que les deux copies produisent pour une entree identique. Un
 * champ ajoute d'un seul cote rougit sans que personne ne l'ait prevu — y compris les champs qui
 * n'existent pas encore.
 *
 * Trois etats, pas deux: `compare`, `derive`, et `saute` quand le depot biii n'est pas a cote. Un saut
 * SILENCIEUX serait la faute meme que ce fichier traque — une lecture non faite qui ressemble a une
 * lecture propre. Il s'annonce donc, et dit pourquoi. */
const fs = require('node:fs');
const path = require('node:path');
const VOISIN = path.join(__dirname, '..', '..', 'biii', 'lib', 'agent-vet.js');

t('les deux copies produisent LES MEMES CLES (garde structurelle, pas un inventaire)', async () => {
  if (!fs.existsSync(VOISIN)) {
    /* Pas un echec: hors de la machine de dev, biii n'est pas un voisin, et rougir ici bloquerait la
     * publication pour une raison qui n'est pas le code. Mais ca se DIT. */
    console.log('       ⚠ SAUTE — ' + VOISIN + ' absent: la comparaison inter-depots n\'a PAS eu lieu.');
    return;
  }
  const ici = require('../lib/agent-vet');
  const la = require(VOISIN);
  /* Pas d'url: l'introspection reseau est sautee des deux cotes, la comparaison reste deterministe. */
  const opts = { payTo: '0x' + '1'.repeat(40) };
  const [a, b] = [await ici.vetAgent(opts), await la.vetAgent(opts)];

  const cles = (o) => (o && typeof o === 'object' ? Object.keys(o).sort() : []);
  assert.deepStrictEqual(cles(a.payment), cles(b.payment),
    'payment a derive entre les deux copies — ici: ' + cles(a.payment).join(',')
    + ' | biii: ' + cles(b.payment).join(','));

  /* Au premier niveau, une difference peut etre LEGITIME (le paquet forensique n'expose pas la meme
   * surface). Chaque ecart tolere doit donc etre nomme ici, avec sa raison — une liste vide veut dire
   * qu'aucun ecart n'est justifie a ce jour. */
  const TOLERE = new Set([]);
  const ecart = [...new Set([...cles(a), ...cles(b)])]
    .filter((k) => (k in a) !== (k in b) && !TOLERE.has(k));
  assert.deepStrictEqual(ecart, [],
    'cle(s) presente(s) d\'un seul cote et non justifiee(s): ' + ecart.join(', '));
});

/* Meme principe applique a une FONCTION plutot qu'a un objet: on fait passer les deux copies par les memes
 * reponses RPC bouchonnees et on compare les sorties. Une divergence de semantique — un revert lu comme
 * « non verifie » d'un cote et « rien ici » de l'autre — rougit sans qu'on ait eu a l'anticiper. */
t('liveAllowance rend LES MEMES verdicts des deux cotes (comportement, pas propriete)', async () => {
  if (!fs.existsSync(path.join(__dirname, '..', '..', 'biii', 'lib', 'approvals.js'))) {
    console.log('       ⚠ SAUTE — biii/lib/approvals.js absent: la comparaison n\'a PAS eu lieu.');
    return;
  }
  const ici = require('../lib/approvals');
  const la = require(path.join(__dirname, '..', '..', 'biii', 'lib', 'approvals'));
  const REPONSES = [
    ['allowance vivante', { result: '0x' + '0'.repeat(63) + '5' }],
    ['zero', { result: '0x' + '0'.repeat(64) }],
    ['reponse vide', { result: '0x' }],
    ['revert', { error: { message: 'execution reverted' } }],
    ['forme illisible', { result: '0xzz' }],
    ['pas de reponse', null],
  ];
  const etiquette = (v) => (typeof v) + ':' + String(v);
  for (const [nom, rep] of REPONSES) {
    const opts = { attempts: 1, postImpl: async () => rep };
    const [a, b] = [await ici.liveAllowance('base', adr(2), adr(1), adr(3), opts),
      await la.liveAllowance('base', adr(2), adr(1), adr(3), opts)];
    assert.strictEqual(etiquette(a), etiquette(b),
      nom + ': ici=' + etiquette(a) + ' | biii=' + etiquette(b));
  }
  /* Sanity: la comparaison ne serait pas concluante si TOUTES les reponses donnaient la meme sortie —
   * deux copies egalement cassees passeraient. On exige que les six cas produisent plusieurs verdicts. */
  const sorties = new Set();
  for (const [, rep] of REPONSES) {
    sorties.add(etiquette(await ici.liveAllowance('base', adr(2), adr(1), adr(3), { attempts: 1, postImpl: async () => rep })));
  }
  assert.ok(sorties.size >= 3, 'six entrees opposees doivent donner au moins trois verdicts distincts, sinon ce cas ne mesure rien');
});

/* Troisieme garde par COMPARAISON DE COMPORTEMENT. Les deux copies jugent la meme contrepartie a partir
 * des memes reponses d'explorateur bouchonnees, et on compare les phrases rendues. Une divergence de
 * semantique rougit sans qu'on ait eu a nommer le champ concerne a l'avance. */
t('judgeCounterparty rend LES MEMES phrases des deux cotes', async () => {
  if (!fs.existsSync(path.join(__dirname, '..', '..', 'biii', 'lib', 'wallet-watch.js'))) {
    console.log('       ⚠ SAUTE — biii/lib/wallet-watch.js absent: la comparaison n\'a PAS eu lieu.');
    return;
  }
  const ici = require('../lib/wallet-watch');
  const la = require(path.join(__dirname, '..', '..', 'biii', 'lib', 'wallet-watch'));
  const REPONSES = [
    ['reponse vide', {}],
    ['contrat sans is_verified', { is_contract: true }],
    ['contrat non verifie', { is_contract: true, is_verified: false }],
    ['contrat verifie', { is_contract: true, is_verified: true, name: 'USDC' }],
    ['portefeuille explicite', { is_contract: false }],
    ['explorateur muet', null],
  ];
  /* Le crible known-bad depend du plancher local de chaque depot: on ne compare que la nature. */
  const nature = (r) => r.notes.filter((n) => !/known-bad/.test(n)).join(' | ');
  const sorties = new Set();
  for (const [nom, rep] of REPONSES) {
    const [a, b] = [await ici.judgeCounterparty('http://x', adr(1), async () => rep),
      await la.judgeCounterparty('http://x', adr(1), async () => rep)];
    assert.strictEqual(nature(a), nature(b), nom + ' a derive');
    assert.strictEqual(String(a.severity), String(b.severity), nom + ': severite divergente');
    sorties.add(nature(a));
  }
  /* Sanity: si les six reponses donnaient la meme phrase, deux copies egalement cassees passeraient et ce
   * cas ne mesurerait rien. */
  assert.ok(sorties.size >= 4, 'six entrees opposees doivent donner au moins quatre phrases distinctes');
});

/* Quatrieme garde par comparaison de comportement. Les deux copies balaient le MEME dossier temporaire et
 * doivent rendre le meme drapeau de couverture et les memes compteurs. Le dossier est cree puis supprime:
 * on ne balaie jamais un vrai repertoire de l'utilisateur depuis un test. */
t('scanPaths rend la MEME couverture des deux cotes', async () => {
  const voisin = path.join(__dirname, '..', '..', 'biii', 'lib', 'seedscan.js');
  if (!fs.existsSync(voisin)) {
    console.log('       ⚠ SAUTE — biii/lib/seedscan.js absent: la comparaison n\'a PAS eu lieu.');
    return;
  }
  const os = require('node:os');
  const ici = require('../lib/seedscan');
  const la = require(voisin);
  const bac = path.join(os.tmpdir(), 'drift-seedscan-' + process.pid);
  fs.mkdirSync(bac, { recursive: true });
  fs.writeFileSync(path.join(bac, 'n.txt'), 'texte ordinaire');
  fs.writeFileSync(path.join(bac, 'a.png'), 'x');
  try {
    const idxA = ici.loadWordlist(), idxB = la.loadWordlist();
    const cas = [
      ['portee voulue', [bac], {}],
      ['chemin absent', [bac, path.join(bac, 'nope')], {}],
      ['lecture bloquee', [bac], { maxFiles: 0 }],
    ];
    const vus = new Set();
    for (const [nom, chemins, opts] of cas) {
      const a = ici.scanPaths(chemins, idxA, opts);
      const b = la.scanPaths(chemins, idxB, opts);
      assert.strictEqual(a.complete, b.complete, nom + ': `complete` a derive');
      assert.deepStrictEqual(a.skipped, b.skipped, nom + ': les compteurs ont derive');
      vus.add(String(a.complete) + JSON.stringify(a.skipped));
    }
    /* Sanity: trois entrees opposees doivent donner trois etats distincts, sinon deux copies egalement
     * cassees s'accorderaient et ce cas ne mesurerait rien. */
    assert.strictEqual(vus.size, 3, 'trois cas opposes doivent produire trois etats distincts');
  } finally {
    fs.rmSync(bac, { recursive: true, force: true });
    assert.strictEqual(fs.existsSync(bac), false, 'la fixture doit etre supprimee');
  }
});

/* Cinquieme garde par comparaison de comportement — la plus sensible: `whatMoved` repond a « qu'est-ce
 * qui a bouge ? » et sa sortie finit dans un document qu'une personne lit sur sa propre perte. Une
 * divergence entre les deux copies y produirait deux recits differents du meme vol. */
t('whatMoved rend LES MEMES mouvements des deux cotes', async () => {
  const voisin = path.join(__dirname, '..', '..', 'biii', 'lib', 'trace.js');
  if (!fs.existsSync(voisin)) {
    console.log('       ⚠ SAUTE — biii/lib/trace.js absent: la comparaison n\'a PAS eu lieu.');
    return;
  }
  const ici = require('../lib/trace');
  const la = require(voisin);
  const TX = '0x' + 'ab'.repeat(32);
  const SIGNEUR = adr(1);
  const tx = { hash: TX, from: { hash: SIGNEUR }, to: { hash: adr(2) }, value: '0' };
  const tr = (from, dec, val) => ({ items: [{ from: { hash: from }, to: { hash: adr(3) },
    token: { symbol: 'T' }, total: { decimals: dec, value: val } }] });
  const rpc = (second) => async (u) => (u.includes('token-transfers') ? second : tx);

  const CAS = [
    ['USDC 6 decimales', rpc(tr(SIGNEUR, 6, '1000000'))],
    ['decimale absente', rpc(tr(SIGNEUR, undefined, '1000000'))],
    ['jeton 0 decimale', rpc(tr(SIGNEUR, 0, '5'))],
    ['transfert forge', rpc(tr(adr(9), 6, '1000000'))],
    ['liste vide', rpc({ items: [] })],
    ['liste non lue', rpc(null)],
  ];
  const vus = new Set();
  for (const [nom, impl] of CAS) {
    const a = await ici.whatMoved('base', TX, impl);
    const b = await la.whatMoved('base', TX, impl);
    /* Le montant ET le drapeau d'authenticite: un ecart sur l'un ou l'autre change le recit. */
    assert.deepStrictEqual(a.transfers.map((m) => [m.amount, m.decimals, m.authentic]),
      b.transfers.map((m) => [m.amount, m.decimals, m.authentic]), nom + ': les mouvements ont derive');
    assert.strictEqual(a.transfersRead, b.transfersRead, nom + ': `transfersRead` a derive');
    assert.strictEqual(a.forgedTransfers, b.forgedTransfers, nom + ': le compte de forges a derive');
    vus.add(JSON.stringify([a.transfersRead, a.forgedTransfers, a.transfers.map((m) => m.amount)]));
  }
  assert.ok(vus.size >= 4, 'six cas opposes doivent produire au moins quatre etats distincts');
});

/* ── LE CAS LE PLUS BETE, ET CELUI QUI MANQUAIT ─────────────────────────────────────────────────────
 * Le 2026-07-28 un port fait en shell a remplace `getJSON(api` PARTOUT dans ce fichier alors que la
 * variable de remplacement n'etait declaree que dans une seule fonction. `readBridgeExit` referencait
 * donc un `lire` inexistant et jetait un ReferenceError DES LE PREMIER APPEL — et `npm test` sortait
 * vert a 28/28, parce qu'aucun test n'appelait cette fonction. `node --check` ne pouvait rien voir: une
 * variable non definie est une erreur d'EXECUTION, pas de syntaxe.
 *
 * Ce cas n'assertit presque rien sur le fond: il APPELLE chaque export asynchrone avec un bouchon, et
 * exige qu'aucun ne jette. C'est le filet minimal qu'un export sans test dedie merite, et il aurait
 * suffi a attraper la casse. */
t('chaque export asynchrone de trace repond sans jeter (filet anti-ReferenceError)', async () => {
  const T = require('../lib/trace');
  const TX = '0x' + 'ab'.repeat(32);
  const bouchon = async () => ({ hash: TX, from: { hash: adr(1) }, to: { hash: adr(2) }, value: '0' });
  const appels = [
    ['whatMoved', () => T.whatMoved('base', TX, bouchon)],
    ['readBridgeExit', () => T.readBridgeExit('base', TX, bouchon)],
    ['followTron', () => T.followTron('T' + 'A'.repeat(33), { maxHops: 1, lireJson: async () => ({ data: [] }) })],
  ];
  for (const [nom, appel] of appels) {
    let r;
    try { r = await appel(); } catch (e) { assert.fail(nom + ' a JETE: ' + e.constructor.name + ': ' + e.message); }
    assert.strictEqual(typeof r, 'object', nom + ' doit rendre un objet');
    assert.notStrictEqual(r, null, nom + ' ne doit pas rendre null');
  }
});

/* Sixieme et septieme gardes par comparaison de comportement, pour les deux fonctions portees. */
t('readBridgeExit et followTron rendent LA MEME chose des deux cotes', async () => {
  const voisin = path.join(__dirname, '..', '..', 'biii', 'lib', 'trace.js');
  if (!fs.existsSync(voisin)) {
    console.log('       ⚠ SAUTE — biii/lib/trace.js absent: la comparaison n\'a PAS eu lieu.');
    return;
  }
  const ici = require('../lib/trace');
  const la = require(voisin);
  const TX = '0x' + 'ab'.repeat(32);
  const ADR = 'T' + 'A'.repeat(33);
  const COMPTE = { data: [{ balance: 5000000, create_time: 1700000000000 }] };

  const PONTS = [
    ['non decode', async () => ({ hash: TX })],
    ['decode, sans id', async () => ({ hash: TX, decoded_input: { parameters: [] } })],
  ];
  for (const [nom, impl] of PONTS) {
    const [a, b] = [await ici.readBridgeExit('base', TX, impl), await la.readBridgeExit('base', TX, impl)];
    assert.strictEqual(a.calldataDecoded, b.calldataDecoded, nom + ': calldataDecoded a derive');
    assert.strictEqual(a.note, b.note, nom + ': la note a derive');
  }

  const PISTES = [
    ['liste non lue', async (u) => (u.includes('/transactions') ? null : COMPTE)],
    ['vraie fin', async (u) => (u.includes('/transactions') ? { data: [] } : COMPTE)],
    ['compte non lu', async (u) => (u.includes('/transactions') ? { data: [] } : null)],
  ];
  const vus = new Set();
  for (const [nom, impl] of PISTES) {
    const [a, b] = [await ici.followTron(ADR, { maxHops: 2, lireJson: impl }),
      await la.followTron(ADR, { maxHops: 2, lireJson: impl })];
    assert.strictEqual(a.stoppedBecause, b.stoppedBecause, nom + ': la raison d\'arret a derive');
    assert.strictEqual(a.complete, b.complete, nom + ': `complete` a derive');
    assert.strictEqual(a.hops[0].balanceTrx, b.hops[0].balanceTrx, nom + ': le solde a derive');
    vus.add(String(a.stoppedBecause) + ':' + String(a.hops[0].balanceTrx));
  }
  /* Sanity: trois situations opposees doivent donner trois etats distincts, sinon deux copies egalement
   * cassees s'accorderaient et ce cas ne mesurerait rien. */
  assert.strictEqual(vus.size, 3, 'trois situations opposees doivent produire trois etats distincts');
});

/* Huitieme garde par comparaison de comportement: le plafond de scanRug. Un plafond qui differe entre les
 * deux copies signifie que le meme appel couvre un nombre different d'adresses selon le paquet utilise —
 * et c'est precisement la sorte d'ecart qui se remarque des mois plus tard, dans un chiffre. */
t('scanRug decoupe et plafonne PAREIL des deux cotes', async () => {
  const voisin = path.join(__dirname, '..', '..', 'biii', 'lib', 'rugsignals.js');
  if (!fs.existsSync(voisin)) {
    console.log('       ⚠ SAUTE — biii/lib/rugsignals.js absent: la comparaison n\'a PAS eu lieu.');
    return;
  }
  const ici = require('../lib/rugsignals');
  const la = require(voisin);
  const bouchon = async () => ({ ok: true, json: async () => ({ result: {} }) });
  const vus = new Set();
  for (const n of [20, 40, 120]) {
    const liste = Array.from({ length: n }, (_, i) => adr(i + 1));
    const [a, b] = [await ici.scanRug('base', liste, { fetchImpl: bouchon }),
      await la.scanRug('base', liste, { fetchImpl: bouchon })];
    assert.strictEqual(Object.keys(a).length, Object.keys(b).length, n + ' adresses: le nombre de cles a derive');
    const ns = (r) => Object.values(r).filter((x) => x.verdict === 'not_scanned').length;
    assert.strictEqual(ns(a), ns(b), n + ' adresses: le compte `not_scanned` a derive');
    vus.add(Object.keys(a).length + ':' + ns(a));
  }
  /* Sanity: si les trois tailles donnaient le meme etat, deux copies egalement cassees s'accorderaient. */
  assert.strictEqual(vus.size, 3, 'trois tailles opposees doivent produire trois etats distincts');
});

/* Neuvieme garde: findVaults. Un ecart ici veut dire que le meme disque produit deux comptes de coffres
 * differents selon le paquet utilise — sur une question de materiel de cle, c'est le pire endroit ou
 * diverger. Le bouchon ne touche AUCUN fichier reel. */
t('findVaults compte et signale PAREIL des deux cotes', async () => {
  const voisin = path.join(__dirname, '..', '..', 'biii', 'lib', 'keyscan.js');
  if (!fs.existsSync(voisin)) {
    console.log('       ⚠ SAUTE — biii/lib/keyscan.js absent: la comparaison n\'a PAS eu lieu.');
    return;
  }
  const ici = require('../lib/keyscan');
  const la = require(voisin);
  const EST_COFFRE = /Local Extension Settings/;
  const disque = (mode) => ({
    home: '/faux',
    fs: {
      existsSync: () => true,
      readdirSync: (p) => {
        if (EST_COFFRE.test(p)) {
          if (mode === 'coffre-verrouille') { const e = new Error('x'); e.code = 'EACCES'; throw e; }
          return ['000001.log', 'MANIFEST'];
        }
        if (mode === 'base-verrouillee') { const e = new Error('x'); e.code = 'EPERM'; throw e; }
        return [{ name: 'Default', isDirectory: () => true }];
      },
      statSync: (p) => { if (mode === 'stat-rate' && /000001/.test(p)) throw new Error('EBUSY'); return { size: 1000 }; },
    },
  });
  const vus = new Set();
  for (const mode of ['ok', 'base-verrouillee', 'coffre-verrouille', 'stat-rate']) {
    const [a, b] = [ici.findVaults({ deps: disque(mode) }), la.findVaults({ deps: disque(mode) })];
    const sig = (r) => r.length + ':' + r.filter((x) => x.unreadable).length + ':'
      + JSON.stringify([...new Set(r.map((x) => x.bytes))].sort());
    assert.strictEqual(sig(a), sig(b), mode + ': findVaults a derive — ici=' + sig(a) + ' biii=' + sig(b));
    vus.add(sig(a));
  }
  /* Sanity: quatre situations opposees doivent produire au moins trois etats distincts. */
  assert.ok(vus.size >= 3, 'quatre situations opposees doivent produire au moins trois etats distincts');
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
