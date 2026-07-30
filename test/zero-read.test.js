#!/usr/bin/env node
'use strict';
/**
 * « Rien trouve » exige d'avoir lu — le bulletin de sante rendu par zero lecture.
 * ==============================================================================
 * ⚠️ LE DEFAUT, mesure le 2026-07-30 sur les deux outils d'exposition.
 *
 * `defaultPaths()` commencait par:
 *
 *     const home = process.env.USERPROFILE || process.env.HOME || '.';
 *
 * Sans HOME ni USERPROFILE — un service, un conteneur, un hote MCP qui n'exporte pas l'environnement — ce
 * `|| '.'` rendait six chemins RELATIFS: ["Documents","Desktop","Downloads","OneDrive\\Documents",
 * "OneDrive\\Desktop","Notes"]. Aucune racine n'avait ete resolue, et pourtant la liste avait exactement la
 * forme d'une liste resolue. C'est la forme n°2 du motif: une valeur ABSENTE coalescee en une mesure.
 *
 * Et l'aval transformait ce refus de regarder en affirmation. Mesure avant correctif, les six chemins
 * absents de la machine:
 *
 *     { scanned: 0, verdict: 'nothing_found', complete: true,
 *       coverage: 'as_intended — nothing blocked a read. ... 6 path(s) are not on this machine at all.' }
 *
 * soit le bulletin le PLUS rassurant que le module sache produire, pour un balayage qui a ouvert ZERO
 * fichier. Le compteur `absent: 6` etait la, mais la phrase a cote le contredisait: « nothing blocked a
 * read » n'etait vrai que parce qu'il n'y avait rien a bloquer. Un dossier reel vide, un chemin inexistant
 * et une liste vide rendaient tous les trois le meme mot — sur la question « ma phrase de recuperation
 * est-elle en clair sur ce disque ? », qui est la pire question pour un faux feu vert.
 *
 * ⚠️ ET LE PIEGE DU CORRECTIF: `scanKeyPaths` partage `defaultPaths()`. Rendre `[]` en amont sans apprendre
 * a l'aval a le LIRE aurait fabrique `{ scanned: 0, complete: true, verdict: 'no_cleartext_key' }` — une
 * affirmation plus forte que celle qu'on venait de retirer. Les deux copies sont donc corrigees ensemble,
 * et les deux sont epinglees ici.
 *
 * ⚠️ LES BORNES. Tout ceci serait satisfait par un module qui ne dit plus jamais rien de rassurant, ce qui
 * cesserait d'informer. Les cas ★ BORNE exigent l'inverse: des qu'UN fichier est reellement lu, un disque
 * propre doit toujours rendre `nothing_found` / `no_cleartext_key` avec `complete: true`, et une vraie
 * phrase comme une vraie cle doivent toujours ressortir.
 *
 * Run: node test/zero-read.test.js
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const SEED = require('../lib/seedscan');
const KEY = require('../lib/keyscan');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${JSON.stringify(want)}, obtenu ${JSON.stringify(got)}\n`);
};

/* Vecteur de test BIP-39 public, publie dans la suite de reference du standard. Ce n'est le portefeuille de
 * personne, et le module n'imprime de toute facon jamais la phrase. */
const PHRASE = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const CLE = '0x' + 'a1'.repeat(31) + 'b2';

const bac = fs.mkdtempSync(path.join(os.tmpdir(), 'zero-read-'));
const vide = path.join(bac, 'vide');
const propre = path.join(bac, 'propre');
const avecPhrase = path.join(bac, 'avec-phrase');
const avecCle = path.join(bac, 'avec-cle');
const absent = path.join(bac, 'jamais-cree');

try {
  for (const d of [vide, propre, avecPhrase, avecCle]) fs.mkdirSync(d);
  fs.writeFileSync(path.join(propre, 'n.txt'), 'du texte parfaitement ordinaire\n');
  fs.writeFileSync(path.join(avecPhrase, 'n.txt'), PHRASE + '\n');
  fs.writeFileSync(path.join(avecCle, '.env'), 'PRIVATE_KEY=' + CLE + '\n');

  const index = SEED.loadWordlist();
  /* Sanity de l'instrument AVANT tout jugement: une liste de mots vide ferait echouer chaque checksum et
   * rendrait `nothing_found` partout — la sonde produirait alors le resultat au lieu de le mesurer. */
  check("SANITY sonde: la liste BIP-39 est chargee (sinon tout ce fichier ne mesure rien)",
    index && (index.size || Object.keys(index).length), 2048);

  /* ── defaultPaths: le refus de deviner ───────────────────────────────────────────────────────────── */
  process.stdout.write('\ndefaultPaths — une racine inconnue ne se devine pas:\n');
  const sauveU = process.env.USERPROFILE, sauveH = process.env.HOME;
  let depouille;
  try {
    delete process.env.USERPROFILE; delete process.env.HOME;
    depouille = SEED.defaultPaths();
  } finally {
    if (sauveU !== undefined) process.env.USERPROFILE = sauveU;
    if (sauveH !== undefined) process.env.HOME = sauveH;
  }
  check('sans USERPROFILE ni HOME, la liste est VIDE (avant: 6 chemins relatifs)', depouille.length, 0);
  check("SANITY: l'environnement a bien ete restaure",
    Boolean(process.env.USERPROFILE || process.env.HOME), Boolean(sauveU || sauveH));

  const normal = SEED.defaultPaths();
  check('★ BORNE: avec une racine, les six chemins sont toujours rendus', normal.length, 6);
  check('★ BORNE: et ils sont tous ABSOLUS (un chemin relatif designe le dossier de travail de l hote)',
    normal.every((p) => path.isAbsolute(p)), true);

  /* ── scanPaths: zero lecture n'est pas une absence de phrase ─────────────────────────────────────── */
  process.stdout.write('\nscanPaths — ce qui n a pas ete lu ne se publie pas comme « rien trouve »:\n');
  const s = (chemins, opts) => SEED.scanPaths(chemins, index, opts || {});

  for (const [nom, chemins] of [
    ['aucun chemin du tout (ce que rend defaultPaths sans racine)', []],
    ['un chemin qui n existe pas sur cette machine', [absent]],
    ['un dossier reel mais sans aucun fichier', [vide]],
    ['les six chemins par defaut tous absents (LE cas mesure)',
      [1, 2, 3, 4, 5, 6].map((n) => path.join(bac, 'nope' + n))],
  ]) {
    const r = s(chemins);
    check(nom + ' → verdict', r.verdict, 'not_scanned');
    check('   et `complete` est faux (avant: vrai)', r.complete, false);
    check('   et `coverage` ne dit PAS que la portee etait celle voulue',
      /as_intended/.test(r.coverage), false);
    check('   et `coverage` ne dit PAS que rien n a bloque une lecture',
      /nothing blocked a read/.test(r.coverage), false);
    check('   et il DIT qu aucun fichier n a ete ouvert', /NOT ONE FILE WAS OPENED/.test(r.coverage), true);
    check('   SANITY: zero fichier lu', r.scanned, 0);
  }

  const propreR = s([propre]);
  check('★ BORNE: un fichier reellement lu et sain rend toujours `nothing_found`', propreR.verdict, 'nothing_found');
  check('★ BORNE: et `complete` y est toujours vrai (le durcissement n a pas tue le cas rassurant)',
    propreR.complete, true);
  check('   SANITY: ce cas a bien lu un fichier', propreR.scanned, 1);

  const phraseR = s([avecPhrase]);
  check('★ BORNE: une vraie phrase ressort toujours', phraseR.verdict, 'exposed');
  check('★ BORNE: un chemin absent A COTE d un dossier lisible ne masque pas la trouvaille',
    s([absent, avecPhrase]).verdict, 'exposed');
  check('   et ce cas-la reste incomplet: le chemin absent est signale',
    s([absent, avecPhrase]).skipped.absent, 1);

  /* Une lecture BLOQUEE sur un dossier reel reste distincte des deux autres etats. */
  const bloqueR = s([propre], { maxFiles: 0 });
  check('une lecture bloquee (plafond de fichiers) rend `not_scanned`, pas `nothing_found`',
    bloqueR.verdict, 'not_scanned');
  check('   et le compteur dit POURQUOI', bloqueR.skipped.overFileCap, 1);

  /* Sanity de variance: si tous ces cas rendaient le meme mot, ce fichier n observerait rien. */
  const motsVus = new Set([propreR.verdict, phraseR.verdict, s([vide]).verdict]);
  check('SANITY variance: trois cas opposes rendent trois verdicts distincts', motsVus.size, 3);

  /* ── la composition reelle: defaultPaths() alimente scanPaths, comme dans bin/ ────────────────────── */
  process.stdout.write('\nseed_exposure sans argument, environnement depouille (le chemin de bout en bout):\n');
  let compose;
  try {
    delete process.env.USERPROFILE; delete process.env.HOME;
    compose = SEED.scanPaths(SEED.defaultPaths(), index);   // exactement ce que fait bin/, ligne a ligne
  } finally {
    if (sauveU !== undefined) process.env.USERPROFILE = sauveU;
    if (sauveH !== undefined) process.env.HOME = sauveH;
  }
  check('le verdict publie est `not_scanned` (avant: `nothing_found`)', compose.verdict, 'not_scanned');
  check('et `complete` est faux (avant: vrai)', compose.complete, false);

  /* ── scanKeyPaths: le meme defaut, le meme chemin d appel ────────────────────────────────────────── */
  process.stdout.write('\nscanKeyPaths — le jumeau qui partage defaultPaths():\n');
  for (const [nom, chemins] of [
    ['aucun chemin du tout', []],
    ['un chemin qui n existe pas', [absent]],
  ]) {
    const r = KEY.scanKeyPaths(chemins);
    check(nom + ' → verdict', r.verdict, 'not_scanned');
    check('   et `complete` est faux', r.complete, false);
    check('   et il DIT qu aucun fichier n a ete ouvert', /NOT ONE FILE WAS OPENED/.test(r.coverage), true);
    check('   SANITY: zero fichier lu', r.scanned, 0);
  }

  const kPropre = KEY.scanKeyPaths([propre]);
  check('★ BORNE: un fichier lu et sain rend toujours `no_cleartext_key`', kPropre.verdict, 'no_cleartext_key');
  check('★ BORNE: et `complete` y est toujours vrai', kPropre.complete, true);
  check('   SANITY: ce cas a bien lu un fichier', kPropre.scanned, 1);
  check('★ BORNE: une vraie cle en clair ressort toujours',
    KEY.scanKeyPaths([avecCle]).verdict, 'cleartext_keys_present');
} finally {
  fs.rmSync(bac, { recursive: true, force: true });
  check('la fixture a bien ete supprimee', fs.existsSync(bac), false);
}

process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
process.exit(failed ? 1 : 0);
