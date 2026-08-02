#!/usr/bin/env node
'use strict';
/**
 * feeder — "who paid for this launch", answered for reads that never happened.
 * ============================================================================
 * `traceFeeder` walks token -> deployer -> funder -> siblings. Two of those three hops were read with
 * `(response && response.items) || []`, which flattens a network failure, an HTTP error body and a
 * genuinely empty list onto the same value. `getJSON` resolves `null` on a network error AND on any
 * non-JSON body, and reads no HTTP status, so a rate-limited 429 arrives looking like an answer.
 *
 * ⚠️ THE DEFECT, measured 2026-08-02 through the `fetchImpl` seam — six inputs, THREE outputs, and the
 * collisions landed on exactly the two questions this tool exists to answer:
 *
 *   deployer read, genuinely unfunded ............ ok:true, "no incoming value transfer found"
 *   the INCOMING read never answered ............. the same answer                            ⛔
 *   the INCOMING read returned an error body ..... the same answer                            ⛔
 *   the SIBLING read never answered .............. siblingCount 0, "no repeated pattern"      ⛔
 *   siblings genuinely absent .................... the same answer                            ⛔
 *   a real funder with 9 siblings (witness) ...... "scripted launch factory"                  ✓
 *
 * Why it matters more here than the shape suggests: `siblingCount: 0` and "single funder, no repeated
 * pattern" are half of the two-condition rule that covers most rugs (a funder spraying 20+ wallets). A
 * mute explorer produced the most reassuring bulletin this module can write.
 *
 * THE TWO LEGS ARE NOT SYMMETRIC, deliberately. Without the incoming list there is no funder at all, so
 * that is `ok:false` — the shape this module already uses for "I cannot answer". With the funder read but
 * its outgoing list missing, `ok:true` still carries real information; only the pattern claim is withheld.
 *
 * NOT COVERED, plainly: the live `getJSON` path. Cases enter through `fetchImpl`, so the HTTP status code
 * this module still never reads would not be caught here.
 */
const assert = require('node:assert');
const { traceFeeder, SIBLING_ALERT } = require('../lib/feeder');

let pass = 0, fail = 0;
const files = [];
const t = (nom, fn) => files.push([nom, fn]);

const DEPLOYER = '0xdead' + 'b'.repeat(36);
const FUNDER = '0xfeed' + 'c'.repeat(36);
const UNE_ENTREE = { items: [{ value: '2000000000000000000', from: { hash: FUNDER }, timestamp: '2026-07-01T00:00:00Z' }] };
const NEUF_FRERES = { items: Array.from({ length: 9 }, (_, i) => ({ value: '1000000000000000000', to: { hash: '0x' + String(i).repeat(40) } })) };

/** un explorateur bouchonne: `inc` pour la jambe entrante, `out` pour la jambe des freres */
const rig = (inc, out) => async (url) => {
  if (url.includes('filter=to')) return inc;
  if (url.includes('filter=from')) return out;
  if (url.includes('/transactions/')) return { timestamp: '2026-07-01T01:00:00Z' };
  return { creator_address_hash: DEPLOYER, creation_transaction_hash: '0xcreation' };
};
const juge = (inc, out) => traceFeeder('base', '0xTOKEN', { fetchImpl: rig(inc, out) });

t('★ la jambe ENTRANTE: rater la lecture n est pas « aucun financeur »', async () => {
  const vide = await juge({ items: [] }, NEUF_FRERES);
  const mort = await juge(null, NEUF_FRERES);
  const erreur = await juge({ message: 'rate limited' }, NEUF_FRERES);

  assert.strictEqual(vide.ok, true, 'un deployeur reellement non finance reste une reponse');
  assert.match(vide.note, /no incoming value transfer found/);

  assert.strictEqual(mort.ok, false, 'explorateur muet: on ne repond pas');
  assert.match(mort.reason, /NOT read/);
  assert.match(mort.reason, /NOT "no funder was found"/,
    'le refus doit dire ce qu il n est PAS, sinon il sera relu comme un resultat vide');
  assert.strictEqual(mort.funder, undefined, 'aucun financeur affirme');

  assert.strictEqual(erreur.ok, false, 'un corps d erreur HTTP n est pas une liste vide');
  assert.strictEqual(mort.deployer, DEPLOYER, 'ce qui A ete lu est conserve');
});

t('★ la jambe des FRERES: siblingCount null, jamais 0', async () => {
  const mort = await juge(UNE_ENTREE, null);
  const vide = await juge(UNE_ENTREE, { items: [] });

  assert.strictEqual(mort.ok, true, 'le financeur, lui, a bien ete lu');
  assert.strictEqual(mort.funder, FUNDER);
  assert.strictEqual(mort.siblingsRead, false);
  assert.strictEqual(mort.chainRead, 'partial');
  assert.strictEqual(mort.siblingCount, null, '0 voulait dire « ce financeur n a arrose personne »');
  assert.strictEqual(mort.pattern, null, 'une phrase sur quelqu un sans sujet ne doit pas etre servie');
  assert.strictEqual(mort.morePages, null, 'un curseur non lu devenait « il n y a pas d autre page »');
  assert.strictEqual(mort.identicalAmountSiblings, null);
  assert.match(mort.siblingsNote, /NOT read/);

  assert.strictEqual(vide.siblingsRead, true);
  assert.strictEqual(vide.siblingCount, 0, 'lu et vide reste 0 — un fait, pas un doute');
  assert.strictEqual(vide.pattern, 'single funder, no repeated pattern on this page');
  assert.strictEqual(vide.siblingsNote, null, 'pas de caveat sur une lecture reussie');
});

t('LA BORNE INVERSE — le motif reel est toujours detecte', async () => {
  const r = await juge(UNE_ENTREE, NEUF_FRERES);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.chainRead, 'ok');
  assert.strictEqual(r.siblingsRead, true);
  assert.strictEqual(r.siblingCount, 9);
  assert.ok(r.siblingCount >= SIBLING_ALERT, 'le rig doit depasser le seuil, sinon ce cas ne mesure rien');
  assert.match(r.pattern, /scripted launch factory/);
  assert.strictEqual(r.morePages, false, 'lu, et il n y avait pas d autre page');
});

t('LE CONTROLE DE LA SONDE — les six entrees ne rendent pas une seule sortie', async () => {
  const sorties = [];
  for (const [inc, out] of [[{ items: [] }, NEUF_FRERES], [null, NEUF_FRERES],
    [{ message: 'x' }, NEUF_FRERES], [UNE_ENTREE, null], [UNE_ENTREE, { items: [] }], [UNE_ENTREE, NEUF_FRERES]]) {
    sorties.push(JSON.stringify(await juge(inc, out)));
  }
  /* 5 et non 6: les deux facons de rater la jambe entrante (muet, corps d erreur) convergent a dessein. */
  assert.strictEqual(new Set(sorties).size, 5,
    'si toutes les entrees donnaient la meme sortie, ce fichier mesurerait sa propre fixture');
});

t('le deployeur non resolu reste un refus, pas un vide', async () => {
  const r = await traceFeeder('base', '0xTOKEN', { fetchImpl: async () => ({}) });
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /could not resolve the deploying wallet/);
});

t('une chaine sans explorateur ne pretend pas avoir regarde', async () => {
  let appele = false;
  const r = await traceFeeder('solana', '0xTOKEN', { fetchImpl: async () => { appele = true; return null; } });
  assert.strictEqual(appele, false, 'aucune requete pour une chaine non cablee');
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /no public explorer wired/);
});

(async () => {
  for (const [nom, fn] of files) {
    try { await fn(); pass++; console.log('  ok   ' + nom); }
    catch (e) { fail++; console.log('  FAIL ' + nom + '\n       ' + e.message); }
  }
  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  if (!pass) { console.log('AUCUN cas execute — un fichier de test vide est un echec, pas un vert.'); process.exit(1); }
  process.exit(fail ? 1 : 0);
})();
