#!/usr/bin/env node
'use strict';
/**
 * recovery — the module that warns about reassuring emptiness, and served it for reads that never happened.
 * =========================================================================================================
 * `assessRecoveryOffer` judges the address a freshly drained victim is being asked to pay. Its header
 * already states the doctrine: "a fresh address has nothing to find and its emptiness must never read as
 * reassurance". That sentence is true of an absence that was READ. It was being served for an absence that
 * was never looked at.
 *
 * ⚠️ THE DEFECT, measured 2026-08-02 offline through the `fetchImpl` seam — four situations, TWO distinct
 * outputs, the first three identical BYTE FOR BYTE across verdict, chainEvidence and reason:
 *
 *   explorer READ, address genuinely empty ..... distinctSenders 0, flaggedByExplorer false
 *   explorer NEVER ANSWERED .................... the same answer                              ⛔
 *   explorer returned an ERROR BODY (500 JSON) . the same answer                              ⛔
 *   a real collection funnel (opposite witness)  high_risk, 9 senders                         ✓
 *
 * The fourth case is what makes the first three mean something: if every input produced one output, the
 * probe would be measuring its own fixture and not the module.
 *
 * `getJSON` resolves `null` on a network error AND on any non-JSON body (an HTML error page, a 429), and
 * reads no HTTP status at all — so a 500 whose body is `{"message":"..."}` arrives as a truthy object.
 * `(inTx && inTx.items) || []` flattened all three onto the empty list, and `!!(info && info.is_scam)`
 * turned "the explorer did not answer" into "the explorer has not flagged this address".
 *
 * WHAT THIS FILE PINS. Both bounds, deliberately: a read that succeeded must still report `false`/`0`
 * plainly (a guard that hedges everything informs no one), and a read that failed must be distinguishable
 * from it in the payload, not only in prose. Every case drives the real `assessRecoveryOffer`; nothing here
 * asserts on a value that depends on the network.
 *
 * NOT COVERED, said plainly: the live `getJSON` path is not exercised — these cases enter through
 * `fetchImpl`, so an HTTP status code that this module still never reads would not be caught here.
 */
const assert = require('node:assert');
const { assessRecoveryOffer, MANY_SENDERS } = require('../lib/recovery');

let pass = 0, fail = 0;
const files = [];
const t = (nom, fn) => files.push([nom, fn]);

const ADDR = '0x1111111111111111111111111111111111111111';

/** explorer answers, and the address really has nothing */
const luVide = async (url) => (url.includes('filter=')
  ? { items: [] }
  : { hash: ADDR, is_contract: false, is_scam: false });
/** the explorer never answered: getJSON resolves null */
const jamaisRepondu = async () => null;
/** the explorer answered with an error object: truthy, no items, no flags */
const corpsErreur = async () => ({ message: 'Internal server error' });
/** only the transaction lists came back; the address record did not */
const partiel = async (url) => (url.includes('filter=') ? { items: [] } : null);
/** a real one-way funnel — the opposite witness */
const entonnoir = async (url) => {
  if (url.includes('filter=to')) {
    return { items: Array.from({ length: MANY_SENDERS + 4 }, (_, i) => ({
      value: '1000000000000000000', from: { hash: '0x' + String(i % 10).repeat(40) } })) };
  }
  if (url.includes('filter=from')) return { items: [] };
  return { hash: ADDR, is_contract: false, is_scam: false };
};

const juge = (fetchImpl, extra = {}) => assessRecoveryOffer({ address: ADDR, chain: 'base', fetchImpl, ...extra });

t('★ une lecture ratee n est PAS la meme reponse qu une lecture vide', async () => {
  const [vide, mort, erreur, funnel] = await Promise.all(
    [luVide, jamaisRepondu, corpsErreur, entonnoir].map((f) => juge(f)));
  const empreinte = (r) => JSON.stringify({ v: r.verdict, e: r.chainEvidence, r: r.reason });
  assert.notStrictEqual(empreinte(vide), empreinte(mort),
    'explorateur muet et adresse vide rendaient la meme reponse octet pour octet');
  assert.notStrictEqual(empreinte(vide), empreinte(erreur),
    'un corps d erreur HTTP passait pour une lecture reussie');
  /* LE CONTROLE DE LA SONDE: sans une entree qui produit AUTRE CHOSE, deux copies egalement cassees
   * s accorderaient et ce fichier ne mesurerait rien. */
  assert.strictEqual(new Set([vide, mort, erreur, funnel].map(empreinte)).size, 3,
    'les 4 entrees doivent rendre 3 sorties distinctes (muet et corps d erreur convergent a dessein)');
});

t('un explorateur muet n affirme rien: aucun champ ne vaut false ni 0', async () => {
  const r = await juge(jamaisRepondu);
  assert.strictEqual(r.chainRead, 'unavailable');
  assert.strictEqual(r.chainEvidence.flaggedByExplorer, null,
    'false voulait dire « l explorateur n a pas signale cette adresse » — il n a pas repondu');
  assert.strictEqual(r.chainEvidence.isContract, null);
  assert.strictEqual(r.chainEvidence.distinctSenders, null);
  assert.strictEqual(r.chainEvidence.inboundCount, null);
  assert.strictEqual(r.chainEvidence.outboundCount, null);
  assert.strictEqual(r.chainEvidence.inboundEth, null);
  assert.strictEqual(r.chainEvidence.outboundEth, null);
  assert.strictEqual(r.chainEvidence.oneWayFunnel, null);
  assert.strictEqual(r.chainEvidence.readsAsHarvesting, null);
  assert.deepStrictEqual(r.chainEvidence.unreadable,
    ['inbound transfers', 'outbound transfers', 'the address record']);
  assert.match(r.chainEvidence.note, /NOT read/);
  assert.match(r.reason, /NOT checked/);
});

t('LA BORNE INVERSE — une lecture REUSSIE affirme toujours, en clair', async () => {
  const r = await juge(luVide);
  assert.strictEqual(r.chainRead, 'ok');
  assert.deepStrictEqual(r.chainEvidence.unreadable, []);
  assert.strictEqual(r.chainEvidence.flaggedByExplorer, false, 'lu et non signale reste un fait, pas un doute');
  assert.strictEqual(r.chainEvidence.isContract, false);
  assert.strictEqual(r.chainEvidence.distinctSenders, 0);
  assert.strictEqual(r.chainEvidence.readsAsHarvesting, false);
  assert.doesNotMatch(r.reason, /NOT read|NOT checked|not read/,
    'tout avertir revient a n avertir de rien: une lecture reussie ne doit pas porter le caveat');
});

t('un corps d erreur HTTP ne passe pas pour une reponse', async () => {
  const r = await juge(corpsErreur);
  assert.strictEqual(r.chainRead, 'unavailable');
  assert.strictEqual(r.chainEvidence.flaggedByExplorer, null);
});

t('une lecture PARTIELLE le dit, et ne perd pas ce qui a ete lu', async () => {
  const r = await juge(partiel);
  assert.strictEqual(r.chainRead, 'partial');
  assert.deepStrictEqual(r.chainEvidence.unreadable, ['the address record']);
  assert.strictEqual(r.chainEvidence.inboundCount, 0, 'la jambe LUE garde sa mesure');
  assert.strictEqual(r.chainEvidence.readsAsHarvesting, false, 'le flux entier a ete lu: le verdict de flux tient');
  assert.strictEqual(r.chainEvidence.flaggedByExplorer, null, 'la fiche n a PAS ete lue');
  assert.match(r.reason, /Part of the chain could not be read/);
});

t('un flux a une seule jambe ne rend AUCUN ratio', async () => {
  const sortantsMuets = async (url) => {
    if (url.includes('filter=to')) return { items: [{ value: '1000000000000000000', from: { hash: '0x' + '9'.repeat(40) } }] };
    if (url.includes('filter=from')) return null;                      // la jambe de retour manque
    return { hash: ADDR, is_contract: false, is_scam: false };
  };
  const r = await juge(sortantsMuets);
  assert.strictEqual(r.chainRead, 'partial');
  assert.strictEqual(r.chainEvidence.inboundCount, 1);
  assert.strictEqual(r.chainEvidence.outboundCount, null);
  assert.strictEqual(r.chainEvidence.oneWayFunnel, null, 'un ratio calcule sur une seule jambe est invente');
  assert.strictEqual(r.chainEvidence.readsAsHarvesting, null);
});

t('l entonnoir reel reste detecte — le durcissement n a rien eteint', async () => {
  const r = await juge(entonnoir);
  assert.strictEqual(r.verdict, 'high_risk');
  assert.strictEqual(r.chainRead, 'ok');
  assert.strictEqual(r.chainEvidence.readsAsHarvesting, true);
  assert.strictEqual(r.chainEvidence.oneWayFunnel, true);
  assert.strictEqual(r.chainEvidence.distinctSenders, MANY_SENDERS + 4);
  assert.match(r.reason, /collection funnel/);
});

t('une regle fatale tranche meme quand la chaine est illisible', async () => {
  const r = await juge(jamaisRepondu, { asksForUpfrontPayment: true });
  assert.strictEqual(r.verdict, 'fraud', 'la regle ne depend d aucune lecture de chaine');
  assert.strictEqual(r.chainRead, 'unavailable');
});

t('sans adresse et sur une chaine inconnue, on ne dit pas « rien de concluant »', async () => {
  const sans = await assessRecoveryOffer({});
  assert.strictEqual(sans.chainRead, 'not_attempted_no_address');
  assert.strictEqual(sans.chainEvidence, null);
  assert.match(sans.reason, /No address was given/);

  let appele = false;
  const inconnue = await assessRecoveryOffer({ address: ADDR, chain: 'solana',
    fetchImpl: async () => { appele = true; return null; } });
  assert.strictEqual(appele, false, 'aucune requete ne doit partir pour une chaine que ce module ne lit pas');
  assert.strictEqual(inconnue.chainRead, 'not_attempted_unsupported_chain');
  assert.match(inconnue.reason, /not one this tool can query/);
  assert.doesNotMatch(inconnue.reason, /shows nothing conclusive/,
    'ne jamais rapporter comme un constat sur la chaine ce qui est un refus de la lire');
});

t('les valeurs de verdict n ont pas bouge pour les appelants existants', async () => {
  const vus = new Set();
  for (const f of [luVide, jamaisRepondu, corpsErreur, partiel, entonnoir]) vus.add((await juge(f)).verdict);
  vus.add((await juge(luVide, { asksForSeedOrKey: true })).verdict);
  assert.deepStrictEqual([...vus].sort(), ['fraud', 'high_risk', 'unverified']);
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
