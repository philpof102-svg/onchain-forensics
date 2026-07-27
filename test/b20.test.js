#!/usr/bin/env node
'use strict';
/**
 * b20 — the classifier that ships in production with no test until today.
 *
 * WHY THIS FILE EXISTS
 * `classifyB20` is live on the hosted MCP as `till_b20_authentic` (one of 29 tools), re-exported by the
 * `onchain-forensics` npm package as `b20_authentic`, and wired into the hourly radar where it can lift a
 * token straight to `rug_ready`. Sixty-four test files in this repo, and not one exercised it.
 *
 * WHAT IT DECIDES, and why the stakes are asymmetric
 * B20 is Base-native and precompile-backed: the token's logic is NOT in EVM bytecode, so a genuine one
 * carries almost none. An ordinary ERC-20 can grind a vanity address onto the same `0xb200` prefix and
 * look like the standard while carrying none of its issuer controls. Two opposite errors:
 *   - calling an impostor native   -> a buyer trusts standard-level guarantees that do not exist
 *   - calling a native an impostor -> a buyer misses that the ISSUER can freeze and burn their balance
 * A genuine B20 is not the safe outcome; it is a DIFFERENT risk. The module says so in its own reason
 * strings, and these tests hold it to that.
 *
 * NO NETWORK. The one RPC call is injected via `rpcImpl`, so the whole decision tree is exercised
 * offline and deterministically. The live-chain check lives in the separate `npm run test:chain`.
 */
const assert = require('node:assert');
const { classifyB20, zeroRunAfterPrefix, B20_PREFIX, NATIVE_CODE_MAX } = require('../lib/b20.js');

let pass = 0, fail = 0;
const t = (name, fn) => fn().then(() => { pass++; console.log('  ok   ' + name); })
  .catch((e) => { fail++; console.log('  FAIL ' + name + '\n       ' + e.message); });

/* Adresses temoins MESUREES sur Base mainnet le 2026-07-27, pas inventees:
 *   MECHACOIN 0xb200000000000000000000602c95f70b5d3aea2d -> eth_getCode = 1 octet,   zeroRun 18
 *   DAISYCAT  0xb200fb5839afa4d7761981143617c5799f063b7f -> eth_getCode = 4509 octets, zeroRun 0
 * La seconde est le premier impostor reel trouve dans notre base (331 tokens), et l'outil EN PRODUCTION
 * la classe prefix_impostor — verifie par appel au MCP heberge. */
const NATIF = '0xb200000000000000000000602c95f70b5d3aea2d';
const IMPOSTOR = '0xb200fb5839afa4d7761981143617c5799f063b7f';
const ORDINAIRE = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';   // USDC Base

const code = (bytes) => async () => '0x' + 'ab'.repeat(bytes);   // du code ORDINAIRE, jamais le marqueur
const MARQUEUR = async () => '0xef';                              // le marqueur natif, exact
const muet = async () => null;                                    // le RPC n'a pas repondu

(async () => {
  console.log('b20: le prefixe est une revendication, le bytecode est la preuve');

  await t('un vrai natif — 1 octet de code — est reconnu, avec ses chiffres', async () => {
    const r = await classifyB20('base', NATIF, { rpcImpl: MARQUEUR });
    assert.equal(r.verdict, 'native_b20');
    assert.equal(r.isNativeB20, true);
    assert.equal(r.impostor, false);
    assert.equal(r.codeBytes, 1);
    assert.equal(r.marker, '0xef', 'le marqueur exact doit etre rapporte');
    assert.equal(r.zeroRun, 18, 'la course de zeros du vrai layout doit etre rapportee');
  });

  await t('UN NATIF N EST PAS LE CAS SUR — sa raison doit nommer le pouvoir de l emetteur', async () => {
    /* C est le piege du module: un lecteur presse lit "native_b20" comme "authentique donc bon". Or
     * l emetteur d un B20 peut GELER et BRULER le solde d un detenteur au niveau du standard — une
     * capacite qu aucun ERC-20 n a et qu aucun scanner ERC-20 ne cherche. */
    const r = await classifyB20('base', NATIF, { rpcImpl: MARQUEUR });
    assert.match(r.reason, /freeze and burn/i, 'le pouvoir de gel/brulure doit etre dit');
    assert.match(r.reason, /no ERC-20 scanner looks for/i, 'et le fait qu un scanner ordinaire l ignore');
    assert.match(r.reason, /NOT the safe outcome/i, 'natif ne doit jamais se lire comme rassurant');
    assert.match(r.reason, /EIP-3541/, 'la raison doit citer la regle qui rend le marqueur infalsifiable');
  });

  await t('un impostor — du vrai bytecode sous le prefixe — est demasque', async () => {
    const r = await classifyB20('base', IMPOSTOR, { rpcImpl: code(4509) });
    assert.equal(r.verdict, 'prefix_impostor');
    assert.equal(r.impostor, true);
    assert.equal(r.isNativeB20, false);
    assert.equal(r.codeBytes, 4509);
    assert.equal(r.zeroRun, 0, 'une adresse vanity n a pas de course de zeros');
    assert.match(r.reason, /does NOT carry the issuer controls/i,
      'la raison doit dire ce que l impostor N A PAS, pas seulement qu il ment');
  });

  console.log('\nle marqueur est EXACT — la faille que le seuil laissait ouverte');

  await t('UN OCTET QUI N EST PAS 0xef est un impostor, pas un natif', async () => {
    /* LA FAILLE CORRIGEE. Le test etait `codeBytes <= 32`, donc tout contrat de 32 octets ou moins a une
     * adresse 0xb200 obtenue par force brute passait pour authentique. Demontre le 2026-07-27 contre le
     * classifieur LIVRE: 0x00, 0xff et 32 octets de vrai code rendaient TOUS LES TROIS native_b20.
     * Trois faux positifs sur quatre cas. */
    for (const octet of ['0x00', '0xff', '0x60', '0xab']) {
      const r = await classifyB20('base', NATIF, { rpcImpl: async () => octet });
      assert.equal(r.verdict, 'prefix_impostor', octet + ' fait UN octet mais n est pas le marqueur');
      assert.equal(r.isNativeB20, false);
    }
  });

  await t('32 octets de code ne peuvent plus passer pour natifs', async () => {
    /* Trente-deux octets suffisent largement a un proxy minimal qui delegue vers de la logique arbitraire:
     * l attaquant n a jamais eu besoin de contrefaire 0xEF, seulement de rester sous le seuil. */
    const r = await classifyB20('base', NATIF, { rpcImpl: code(32) });
    assert.equal(r.verdict, 'prefix_impostor');
    assert.equal(r.codeBytes, 32);
  });

  await t('EIP-7702: un EOA DELEGUE porte du code prefixe 0xef et n est PAS un B20', async () => {
    /* LA CORRECTION DU 2026-07-27, quelques heures apres le premier correctif.
     *
     * J'avais justifie l'egalite exacte par « EIP-3541 interdit de deployer du code commencant par 0xEF,
     * donc le marqueur est infalsifiable ». C'est FAUX: EIP-3541 ne contraint que le chemin de CREATION.
     * EIP-7702 pose couramment du code prefixe 0xEF sur des EOA ordinaires — un indicateur de delegation
     * vaut exactement `0xef0100 || <20 octets d'adresse>`, soit 23 octets.
     *
     * Corrobore sur Base en lisant le bytecode de 0xdfac5e91fd27451123133da9f71d68c0b247b4de, qui contient
     * un validateur explicite de cette forme: longueur 0x17, puis les octets ef, 01, 00, puis l'adresse a
     * l'offset 0x23. Un contrat qui valide le motif existe parce que le motif est courant.
     *
     * Ce qui garantit reellement, c'est l'EGALITE EXACTE et rien d'autre: un natif fait UN octet, une
     * delegation en fait VINGT-TROIS. Ce test existe pour que personne ne relache en startsWith. */
    const DELEGATION = '0xef0100dfac5e91fd27451123133da9f71d68c0b247b4de';
    assert.equal((DELEGATION.length - 2) / 2, 23, "un indicateur 7702 fait 23 octets");
    assert.equal(DELEGATION.startsWith('0xef'), true,
      'le piege est reel: un startsWith passerait');

    const r = await classifyB20('base', NATIF, { rpcImpl: async () => DELEGATION });
    assert.equal(r.verdict, 'prefix_impostor',
      'un EOA delegue a un b200 vanity ne doit JAMAIS lire comme un B20 authentique');
    assert.equal(r.isNativeB20, false);
    assert.equal(r.codeBytes, 23);
  });
  await t('le marqueur est insensible a la casse — pas d echappatoire par 0xEF majuscule', async () => {
    const maj = await classifyB20('base', NATIF, { rpcImpl: async () => '0xEF' });
    assert.equal(maj.verdict, 'native_b20');
  });

  await t('un compte VIDE (0x) n est pas un natif — c est une adresse sans contrat', async () => {
    /* Avant, 0 octet passait le seuil et rendait native_b20. Une adresse sans code n est pas un B20:
     * c est une EOA, ou un contrat pas encore deploye. */
    const r = await classifyB20('base', NATIF, { rpcImpl: async () => '0x' });
    assert.equal(r.codeBytes, 0);
    assert.equal(r.verdict, 'prefix_impostor', 'aucun code n est pas le marqueur');
  });

  console.log('\nfail-closed: ne pas avoir lu n est pas un verdict');

  await t('un RPC MUET rend unknown, jamais natif ni impostor', async () => {
    /* La faute la plus chere possible ici: lire une non-reponse comme "0 octet" donc "natif". Un token
     * usurpateur passerait pour authentique parce que le RPC a hoquete. */
    const r = await classifyB20('base', IMPOSTOR, { rpcImpl: muet });
    assert.equal(r.verdict, 'unknown');
    assert.match(r.reason, /could not read/i);
    assert.notEqual(r.verdict, 'native_b20', 'un silence ne doit JAMAIS produire un verdict rassurant');
    assert.equal(r.isNativeB20, undefined, 'aucune affirmation sur la nature du contrat');
  });

  await t('une chaine non cablee refuse, sans appeler personne', async () => {
    let appele = false;
    const r = await classifyB20('dogecoin', NATIF, { rpcImpl: async () => { appele = true; return '0x'; } });
    assert.equal(r.verdict, 'unknown');
    assert.match(r.reason, /no RPC wired/i);
    assert.equal(appele, false, 'ne pas appeler un RPC pour une chaine inconnue');
  });

  await t('une adresse mal formee est refusee AVANT tout appel reseau', async () => {
    for (const mauvaise of ['0xb200', 'pas une adresse', '', null, '0xZZ00000000000000000000000000000000000000']) {
      let appele = false;
      const r = await classifyB20('base', mauvaise, { rpcImpl: async () => { appele = true; return '0x'; } });
      assert.equal(r.verdict, 'unknown', JSON.stringify(mauvaise));
      assert.match(r.reason, /well-formed/i);
      assert.equal(appele, false, 'aucun appel reseau sur une entree invalide: ' + JSON.stringify(mauvaise));
    }
  });

  console.log('\nce qui ne porte pas le prefixe n est pas juge');

  await t('une adresse ordinaire rend not_b20 et ne revendique RIEN', async () => {
    const r = await classifyB20('base', ORDINAIRE, { rpcImpl: code(20000) });
    assert.equal(r.verdict, 'not_b20');
    assert.equal(r.presentsAsB20, false);
    assert.equal(r.impostor, false, 'ne pas revendiquer le standard n est pas usurper');
    assert.match(r.reason, /nothing claimed about the B20 standard/i);
  });

  await t('la casse de l adresse ne change pas le verdict', async () => {
    const bas = await classifyB20('base', IMPOSTOR, { rpcImpl: code(4509) });
    const haut = await classifyB20('base', IMPOSTOR.toUpperCase().replace('0X', '0x'), { rpcImpl: code(4509) });
    assert.equal(bas.verdict, haut.verdict, 'un attaquant ne doit pas s echapper par la casse');
  });

  console.log('\nla course de zeros, le second discriminant');

  await t('zeroRunAfterPrefix compte apres b200, pas depuis le debut', async () => {
    assert.equal(zeroRunAfterPrefix(NATIF), 18);
    assert.equal(zeroRunAfterPrefix(IMPOSTOR), 0);
    assert.equal(zeroRunAfterPrefix('0xb200' + '0'.repeat(36)), 36, 'tout en zeros apres le prefixe');
    assert.equal(zeroRunAfterPrefix('0xB200000000ff' + '0'.repeat(28)), 6, 'la course s arrete au premier non-zero (000000 puis ff)');
  });

  await t('les deux discriminants concordent sur les deux temoins reels', async () => {
    /* Ils sont independants: la taille du code peut changer si le standard evolue, la forme de l adresse
     * non. Qu ils concordent sur les cas mesures est ce qui rend le verdict defendable. */
    const n = await classifyB20('base', NATIF, { rpcImpl: MARQUEUR });
    assert.ok(n.marker === '0xef' && n.zeroRun > 10, 'natif: marqueur exact ET longue course de zeros');
    const i = await classifyB20('base', IMPOSTOR, { rpcImpl: code(4509) });
    assert.ok(i.marker !== '0xef' && i.zeroRun === 0, 'impostor: pas le marqueur ET aucune course de zeros');
  });

  await t('le prefixe attendu est bien 0xb200', async () => {
    assert.equal(B20_PREFIX, '0xb200');
    assert.ok(NATIVE_CODE_MAX > 0 && NATIVE_CODE_MAX < 100, 'un seuil hors de cet ordre serait une erreur de saisie');
  });

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
