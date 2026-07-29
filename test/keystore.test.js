#!/usr/bin/env node
'use strict';
/**
 * readKeystore — le refus de regarder qui se publiait comme « ce fichier est propre ».
 * ====================================================================================
 * ⚠️ LE DEFAUT, mesure le 2026-07-29. La fonction commencait par:
 *
 *     if (text.length > 200000) return null;   // "a keystore is small; anything huge is something else"
 *
 * `null` veut dire « ce n'est pas un keystore ». Mais ce plafond-la ne dit pas ca: il dit « je n'ai pas
 * regarde ». Le MEME keystore valide, place dans un fichier de 200 458 octets, rendait `null` — et
 * `scanKeyText` sur ce fichier rendait AUCUNE TROUVAILLE. Pas une trouvaille faible: zero. Sur un outil
 * dont la sortie EST un rapport d'exposition, un fichier jamais ouvert sortait identique a un fichier
 * examine et sain.
 *
 * Un keystore est petit; un fichier QUI EN CONTIENT UN ne l'est pas forcement — un dump, un export de
 * portefeuille colle a la fin d'un log, un JSON d'application qui embarque le coffre.
 *
 * ⚠️ ET LE MODULE SAVAIT DEJA FAIRE. 270 lignes plus bas: `if (st.size > 4 Mo) { skipped.tooBig++; }` —
 * il COMPTE ce qu'il saute, et ce compte remonte a l'appelant. Le meme probleme, resolu proprement d'un
 * cote et perdu en silence de l'autre. Le plafond est desormais le meme, et il se DECLARE
 * (`keystore_unchecked`), tandis que le vrai tri se fait sur une recherche de sous-chaine qui ne perd rien.
 *
 * ⚠️ LES BORNES: tout ceci serait satisfait par une fonction qui rend un keystore pour n'importe quoi.
 * Les cas ★ REFUS exigent l'inverse — un JSON sans `crypto`, un keystore tronque et un fichier ordinaire
 * doivent rester `null`, sinon le scanner crie sur tout et se fait desinstaller.
 *
 * Run: node test/keystore.test.js
 */
const { readKeystore, scanKeyText } = require('../lib/keyscan');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};

/* Un keystore conforme. Rien de secret ici: le ciphertext est du remplissage, et un keystore est de
 * toute facon chiffre — ce module ne rapporte jamais aucune partie du ciphertext. */
const KS = {
  version: 3,
  address: 'a614f803b6fd780986a42c78ec9c7f77e6ded13c',
  crypto: { ciphertext: 'ab'.repeat(32), kdf: 'scrypt', mac: 'cd'.repeat(32), cipher: 'aes-128-ctr' },
};
const valide = JSON.stringify(KS);
const verdicts = (t, f) => scanKeyText(t, { filename: f || 'wallet.json' }).map((x) => x.verdict).join(',') || '(rien)';
/* Lecture SANS DEREFERENCEMENT NU. `readKeystore(x).kdf` meurt sur un TypeError des que le resultat est
 * null — et un crash est un signal plus pauvre qu'une assertion: on perd le nom du cas et les cas
 * suivants. Trois issues (objet / non-examine / null) donc trois lectures possibles, jamais un point. */
const champ = (t, k) => { const r = readKeystore(t); return r ? String(r[k]) : 'null'; };

/* ── les acceptations ─────────────────────────────────────────────────────────────────────────────── */
process.stdout.write('readKeystore — ce qui doit etre reconnu:\n');
check('★ BORNE: un keystore valide est reconnu', champ(valide, 'kdf'), 'scrypt');
check('   et il nomme le portefeuille (public par construction, c est ce qui rend la trouvaille agissable)',
  champ(valide, 'address'), KS.address);
check('   `Crypto` avec une majuscule est accepte aussi',
  champ(JSON.stringify({ version: 3, Crypto: KS.crypto }), 'kdf'), 'scrypt');

/* ── ★ LA PRISE: le meme keystore, dans un fichier au-dela de l ancien plafond ────────────────────── */
const gros = JSON.stringify({ ...KS, note: 'x'.repeat(200001) });
check('★ le MEME keystore dans un fichier > 200 Ko est TROUVE', champ(gros, 'kdf'), 'scrypt');
check('★ et le scan complet le rapporte au lieu de ne rien dire', verdicts(gros), 'keystore_file');
check('   le fichier depasse bien l ancien plafond (sinon ce cas ne prouverait rien)',
  String(gros.length > 200000), 'true');

/* ── ★ au-dela du plafond REEL, le refus se DECLARE au lieu de se taire ───────────────────────────── */
const enorme = '{"crypto":{"ciphertext":"' + 'ab'.repeat(32) + '","kdf":"scrypt","mac":"cd"},"pad":"'
  + 'y'.repeat(4 * 1024 * 1024) + '"}';
check('★ au-dela de 4 Mo, readKeystore DIT qu il n a pas examine',
  String(champ(enorme, 'unchecked') !== 'null' && champ(enorme, 'unchecked') !== 'undefined'), 'true');
check('★ et le scan rend un verdict DISTINCT, ni `keystore_file` ni le silence',
  verdicts(enorme), 'keystore_unchecked');
check('★ la note interdit de le lire comme un resultat propre',
  String(/This is not a clean result/.test(scanKeyText(enorme, { filename: 'w.json' })[0].note)), 'true');
check('   et elle donne la taille, pour qu on puisse aller voir',
  String(scanKeyText(enorme, { filename: 'w.json' })[0].bytes > 4 * 1024 * 1024), 'true');

/* ── ★ les refus: un scanner qui crie sur tout se fait desinstaller ───────────────────────────────── */
process.stdout.write('\nreadKeystore — ce qui doit rester un NON:\n');
for (const [nom, t] of [
  ['un keystore tronque (mac manquant)', JSON.stringify({ version: 3, crypto: { ciphertext: 'ab', kdf: 'scrypt' } })],
  ['un JSON sans crypto', JSON.stringify({ hello: 'world', ciphertext: 'leurre' })],
  ['du texte qui n est pas du JSON', 'ciphertext mais pas du json'],
  ['un tableau JSON', '[1,2,3]'],
  ['le litteral null', 'null'],
  ['un fichier ordinaire sans le mot ciphertext', 'const a = 1;\nmodule.exports = a;\n'],
]) {
  check(nom + ' reste null', String(readKeystore(t)), 'null');
}
check('★ BORNE: un fichier ordinaire ne produit AUCUNE trouvaille de keystore',
  verdicts('const a = 1;\n', 'a.js'), '(rien)');
check('★ BORNE: une vraie cle en clair est toujours vue (le pre-filtre n aveugle pas le reste)',
  verdicts('PRIVATE_KEY=0x' + 'a1'.repeat(31) + 'b2', 'a.env'), 'cleartext_key');

process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
process.exit(failed ? 1 : 0);
