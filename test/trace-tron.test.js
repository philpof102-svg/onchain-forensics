#!/usr/bin/env node
'use strict';
/**
 * trace — l'adresse TRON dont la somme de controle etait jetee sans etre lue.
 * ============================================================================
 * ⚠️ LE DEFAUT, mesure le 2026-07-29. `tronToHex` finissait par `h.slice(0, -8)`: les quatre octets dont
 * le SEUL role est d'attraper une adresse mal tapee etaient jetes sans etre verifies. En changeant UN
 * caractere d'une adresse valide:
 *
 *   original          41a614f803b6fd780986a42c78ec9c7f77e6ded13c
 *   char  5 change    41a614f813fa29ceaab4a35d0a72d87d6117cfaac7   <- UN AUTRE portefeuille, rendu sans un mot
 *   char 15 change    41a614f803b6fd780986a42f3144dd7b955126dc24   <- UN AUTRE portefeuille, rendu sans un mot
 *   char 33 change    41a614f803b6fd780986a42c78ec9c7f77e6ded13c   <- MEME corps: la preuve que les 4
 *                                                                     derniers octets n'etaient pas regardes
 *
 * Sur un module dont la sortie NOMME UN PORTEFEUILLE dans une trace de vol, une faute de frappe, un OCR
 * approximatif ou un copier-coller tronque devenaient une adresse hexadecimale sure d'elle appartenant a
 * quelqu'un d'autre. C'est la version la plus grave de la regle permanente de ce depot: une adresse se
 * copie, jamais ne se recite, et surtout ne se reconstruit pas depuis une valeur qui n'a pas verifie.
 *
 * ⚠️ ET LE CORRECTIF A FAILLI ROUVRIR UN AUTRE TROU. `tronToHex` peut desormais rendre `null` la ou il
 * rendait toujours quelque chose. Laisse tel quel, `(ownHex || '')` dans `followTron` comparait chaque
 * transfert a la chaine vide: rien ne correspond, tout se classe `in`, `outs` est vide, la boucle s'arrete
 * — LE FAUX TERMINUS que ce fichier documente vingt lignes plus haut, reconstruit par une autre porte. Un
 * `null` neuf que le consommateur ne sait pas lire, c'est un correctif qui devient un defaut. D'ou les cas
 * de bout en bout ci-dessous: ils valent plus que ceux sur la fonction pure.
 *
 * Run: node test/trace-tron.test.js
 */
const { tronToHex, hexToTron, followTron } = require('../lib/trace');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};

/* On ne RECITE aucune adresse: on la fabrique avec l'inverse, dont la somme de controle est calculee. */
const CORPS_A = '41a614f803b6fd780986a42c78ec9c7f77e6ded13c';
const CORPS_B = '41' + 'b7'.repeat(20);
const A = hexToTron(CORPS_A);
const B = hexToTron(CORPS_B);

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const muter = (s, i) => s.slice(0, i) + B58[(B58.indexOf(s[i]) + 1) % 58] + s.slice(i + 1);

/* ── les acceptations: sans elles, « rendre null partout » passerait tous les refus ────────────────── */
process.stdout.write('tronToHex — ce qui doit continuer a se convertir:\n');
check('★ BORNE: une adresse valide rend son corps exact', tronToHex(A), CORPS_A);
check('★ BORNE: une SECONDE adresse valide rend le SIEN (pas une constante)', tronToHex(B), CORPS_B);
check('★ BORNE: les deux ne se confondent pas', String(tronToHex(A) === tronToHex(B)), 'false');
check('l aller-retour tient dans les deux sens', hexToTron(tronToHex(A)), A);
check('l adresse fabriquee a bien 34 caracteres', String(A.length), '34');

/* ── ★ les refus: chacun rendait AUPARAVANT une adresse plausible et fausse ────────────────────────── */
process.stdout.write('\ntronToHex — une faute de frappe n est pas une autre adresse, c est aucune adresse:\n');
for (const i of [1, 5, 15, 25]) {
  check('★ un caractere change en position ' + String(i).padStart(2) + ' est REFUSE',
    String(tronToHex(muter(A, i))), 'null');
}
check('★ LA PREUVE que la somme de controle est lue: muter le 33e caractere (zone de controle) est refuse',
  String(tronToHex(muter(A, 33))), 'null');
check('★ et ce caractere-la rendait AVANT le meme corps que l original — donc rien ne le voyait',
  String(muter(A, 33) !== A), 'true');

process.stdout.write('\ntronToHex — formes qui ne sont pas des adresses TRON:\n');
for (const [nom, v] of [['chaine vide', ''], ['null', null], ['undefined', undefined],
  ['une adresse EVM 0x…', '0x' + CORPS_A.slice(2)], ['33 caracteres', A.slice(0, 33)],
  ['35 caracteres', A + '1'], ['t minuscule', 't' + A.slice(1)], ['un objet', {}]]) {
  check(nom + ' est refuse', String(tronToHex(v)), 'null');
}

/* ── ★ de bout en bout: le null neuf ne doit pas fabriquer un terminus ─────────────────────────────── */
process.stdout.write('\nfollowTron — un null neuf ne doit pas devenir une conclusion:\n');
/* Un compte qui a envoye des fonds: si la direction se calcule, il y a une sortie et la piste continue. */
const stub = async (url) => url.includes('/transactions')
  ? { data: [{ block_timestamp: 1750000000000, raw_data: { contract: [{ type: 'TransferContract',
      parameter: { value: { amount: 5000000, owner_address: CORPS_A, to_address: CORPS_B } } } ] } }] }
  : { data: [{ balance: 1000000, create_time: 1740000000000 }] };

(async () => {
  const bon = await followTron(A, { maxHops: 2, lireJson: stub });
  check('★ BORNE: une adresse VALIDE suit toujours sa piste', String(bon.hops[0].addressDecoded), 'true');
  check('★ BORNE: et elle classe bien la sortie (sinon tout serait "in")',
    bon.hops[0].recent[0].direction, 'out');
  check('   la piste avance vers la destination', bon.hops[0].largestOut ? bon.hops[0].largestOut.to : 'aucune', B);

  const faute = await followTron(muter(A, 5), { maxHops: 2, lireJson: stub });
  check('★ une adresse mal tapee ARRETE la piste explicitement',
    faute.stoppedBecause, 'address_unreadable');
  check('★ et elle n est PAS declaree terminus (c est tout l enjeu)', String(faute.complete), 'false');
  check('★ le hop declare que l adresse n a pas decode', String(faute.hops[0].addressDecoded), 'false');
  check('★ aucun mouvement n est classe out ou in sur une adresse non decodee',
    (faute.hops[0].recent || []).every((f) => f.direction === 'unknown') ? 'aucun' : 'IL Y EN A', 'aucun');
  check('★ et la note DIT que c est la somme de controle, pas la fin des fonds',
    String(/failed its base58check checksum/.test(faute.stopNote || '')), 'true');
  check('   elle avertit que l adresse voisine appartient a quelqu un d autre',
    String(/belongs to someone else/.test(faute.stopNote || '')), 'true');

  process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
  process.exit(failed ? 1 : 0);
})();
