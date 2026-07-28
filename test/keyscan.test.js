#!/usr/bin/env node
'use strict';
/**
 * keyscan — le scanner de CLES PRIVEES EXPOSEES, publie sur npm, et sans un seul test qui le nomme.
 * ==================================================================================================
 * ⚠️ LE DEFAUT QUE CES CAS EPINGLENT, mesure le 2026-07-28.
 * `scanKeyText` exigeait l'etiquette ET les 64 hex sur LA MEME LIGNE. Un JSON INDENTE — la facon la plus
 * banale qu'a une cle de trainer sur un disque (config hardhat, wallet exporte, n'importe quel secret
 * `.json`) — met l'etiquette sur une ligne et la valeur sur la suivante:
 *
 *   PRIVATE_KEY=0x…                    -> cleartext_key   ✓
 *   {"privateKey":"0x…"}               -> cleartext_key   ✓
 *   {\n  "privateKey":\n    "0x…"\n}   -> labelled_only   ✗
 *   private_key:\n  0x…                -> labelled_only   ✗
 *
 * Et `labelled_only` annonce « a placeholder, a variable reference, or a redaction. Almost always fine. »
 * — l'outil RASSURE activement sur le fichier qu'il vient de rater. Sur un scanner de cles exposees,
 * c'est le pire endroit possible pour un faux negatif: la cle reste dehors pendant qu'on dit « propre ».
 *
 * ⚠️ POURQUOI PAS UN FILET PLUS LARGE. 64 hex, c'est AUSSI tout hash de transaction, de bloc, tout
 * digest. Scanner les lignes sans etiquette noierait un depot blockchain sous les faux positifs, et un
 * garde qui crie au loup se fait desinstaller — la lecon que `lure.js` porte deja trois fois. D'ou une
 * ANTICIPATION BORNEE: l'etiquette reste obligatoire, on regarde 2 lignes, et on s'arrete des qu'une
 * autre etiquette ou un libelle de digest apparait.
 *
 * Run: node test/keyscan.test.js
 */
const { scanKeyText, isPlausibleScalar } = require('../lib/keyscan');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};
const K = '0x' + 'a1'.repeat(31) + 'b2';                 // 64 hex, scalaire secp256k1 valide
const verdicts = (texte, filename = 'secrets.json') =>
  scanKeyText(texte, { filename }).map((f) => f.verdict).join(',') || '(rien)';

process.stdout.write('keyscan — une cle ratee ne doit jamais se lire « almost always fine »:\n');

/* ── les formes qui marchaient deja: elles ne doivent pas bouger ─────────────────────────────────── */
check('.env sur une ligne reste une cle en clair', verdicts('PRIVATE_KEY=' + K, 'a.env'), 'cleartext_key');
check('JSON compact reste une cle en clair', verdicts('{"privateKey":"' + K + '"}'), 'cleartext_key');

/* ── LA PRISE: etiquette et valeur sur deux lignes ───────────────────────────────────────────────── */
check('★ JSON INDENTE est attrape', verdicts('{\n  "privateKey":\n    "' + K + '"\n}'), 'cleartext_key');
check('★ YAML sur deux lignes est attrape', verdicts('private_key:\n  ' + K, 'a.yaml'), 'cleartext_key');
check('★ la trouvaille multiligne se DECLARE comme telle',
  String(scanKeyText('{\n  "privateKey":\n    "' + K + '"\n}', { filename: 'a.json' })[0].multiline), 'true');
check('★ et elle NOMME la ligne de la valeur',
  String(scanKeyText('{\n  "privateKey":\n    "' + K + '"\n}', { filename: 'a.json' })[0].valueLine), '3');

/* ── un chemin RETENU garde sa gravite propre sur la forme multiligne aussi ──────────────────────── */
check('★ une copie RETENUE reste une copie retenue en multiligne',
  verdicts('{\n  "privateKey":\n    "' + K + '"\n}', 'C:/BACKUP/x.json'), 'retained_copy');

/* ── LES BORNES: rien ne doit devenir un faux positif ────────────────────────────────────────────── */
check('BORNE: un placeholder reste labelled_only',
  verdicts('{\n  "privateKey":\n    "REDACTED"\n}'), 'labelled_only');
check('BORNE: un hash de tx sous une etiquette de cle n est PAS attribue a la cle',
  verdicts('# PRIVATE_KEY retire\ntxHash: ' + K, 'notes.md'), 'labelled_only');
check('BORNE: une AUTRE etiquette coupe l anticipation',
  verdicts('privateKey:\nsecret_key: ' + K, 'a.yaml'), 'labelled_only,cleartext_key');
check('BORNE: au-dela de deux lignes, on ne relie plus',
  verdicts('privateKey:\n\n\n\n  ' + K, 'a.yaml'), 'labelled_only');
check('BORNE: un hex nu SANS etiquette reste ignore (sinon tout hash de tx crie)',
  verdicts(K, 'chain.log'), '(rien)');

/* ── le scalaire: la validite secp256k1 est ce qui separe une cle d un hash quelconque ───────────── */
check('un hex de 64 qui n est PAS un scalaire valide ne passe pas',
  verdicts('privateKey:\n  ' + '0x' + 'f'.repeat(64), 'a.yaml'), 'labelled_only');
check('zero n est pas un scalaire valide', String(isPlausibleScalar('0'.repeat(64))), 'false');
check('un scalaire au-dessus de N est refuse',
  String(isPlausibleScalar('f'.repeat(64))), 'false');

/* ── la note doit dire ce qui a ete regarde, sinon « almost always fine » ment par omission ──────── */
check('★ labelled_only DIT que les lignes suivantes ont ete verifiees',
  String(/following lines were checked/i.test(
    scanKeyText('{\n  "privateKey":\n    "REDACTED"\n}', { filename: 'a.json' })[0].note)), 'true');

process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
process.exit(failed ? 1 : 0);
