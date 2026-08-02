'use strict';
/**
 * feeder.js — "who paid for this launch, and what else did they pay for?"
 * =======================================================================
 * `rugsignals` asks what the deployer CAN do. This asks who the deployer IS — by following the money
 * backwards. A token contract names its creator; a creator wallet minutes old names the wallet that funded
 * it; and that funder usually funded others. Three free queries and a cluster appears that no retail buyer
 * can see from a chart.
 *
 * Proven on a live launch while writing this: token -> creator (funded once, 15.02 ETH, seven minutes before
 * the pool existed) -> funder, which had sent the SAME 15.020 ETH to twenty-six other fresh wallets. Nobody
 * funds twenty-six wallets to the milli-ETH by hand; that is a machine running a launch factory.
 *
 * WHAT THIS DOES NOT CLAIM. A shared funder is not proof of fraud. The same signature fits a launchpad, a
 * market maker, or a serial rug operation, and we cannot tell which from the graph alone. So this reports
 * STRUCTURE, never intent: these tokens share a paymaster, therefore they share fate. That is decision-
 * relevant on its own — and calling it "scammer" without evidence would be the same unfounded certainty we
 * refuse everywhere else. Intent only gets asserted when a sibling has actually rugged, which token-radar
 * records over time.
 *
 * Source: Blockscout's public Base instance (no key, no quota registration).
 */
const https = require('node:https');

const BLOCKSCOUT = { base: 'https://base.blockscout.com/api/v2' };
const FRESH_FUNDING_WINDOW_MS = 6 * 60 * 60 * 1000;   // funded <6h before deploying = wallet made for the job
const SIBLING_ALERT = 5;                              // a funder this prolific is infrastructure, not a person

const getJSON = (url) => new Promise((resolve) => {
  https.get(url, { headers: { accept: 'application/json' } }, (res) => {
    let d = ''; res.on('data', (c) => (d += c));
    res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
  }).on('error', () => resolve(null));
});

/**
 * traceFeeder — token -> deployer -> funder -> siblings.
 * @returns { ok, deployer, funder, fundedEth, fundedAt, freshDeployer, siblings, siblingCount, morePages,
 *            identicalAmountSiblings, pattern, note }
 */
async function traceFeeder(chain, tokenAddress, { fetchImpl } = {}) {
  const api = BLOCKSCOUT[String(chain).toLowerCase()];
  const fetchJSON = fetchImpl || getJSON;
  if (!api) return { ok: false, reason: 'no public explorer wired for chain "' + chain + '"' };

  // 1. The contract names its creator.
  const tok = await fetchJSON(api + '/addresses/' + tokenAddress);
  const deployer = tok && tok.creator_address_hash;
  if (!deployer) return { ok: false, reason: 'could not resolve the deploying wallet' };

  // 2. The creator's incoming transfers name whoever paid for it. A wallet with exactly one incoming
  //    transfer was created for this launch and nothing else — which is itself the signal.
  const inc = await fetchJSON(api + '/addresses/' + deployer + '/transactions?filter=to');
  /* ⚠️ LES DEUX JAMBES DE LECTURE AFFIRMAIENT CE QU'ELLES N'AVAIENT PAS LU. Mesure du 2026-08-02 par le
   * joint `fetchImpl` — six entrees, TROIS sorties, et les collisions tombent exactement sur les deux
   * questions que cet outil existe pour repondre:
   *
   *   deployeur lu, reellement non finance ..... ok:true, « no incoming value transfer found »
   *   la lecture des ENTRANTS n'a jamais repondu  la MEME reponse                              ⛔
   *   la lecture des ENTRANTS rend un corps d'erreur  la MEME reponse                          ⛔
   *   la lecture des FRERES n'a jamais repondu ... siblingCount 0, « no repeated pattern »      ⛔
   *   freres reellement absents ................. la MEME reponse                              ⛔
   *   vrai financeur, 9 freres (temoin oppose) .. pattern « launch factory »                    ✓
   *
   * `(inc && inc.items) || []` aplatit panne, corps d'erreur et liste vide sur un seul objet. Et
   * `getJSON` resout `null` aussi bien sur une panne reseau que sur un corps non-JSON, sans lire aucun
   * code HTTP: un 429 arrive comme une reponse.
   *
   * Ce que ca produisait: `siblingCount: 0` et « single funder, no repeated pattern » sont la moitie de
   * la regle a deux conditions qui couvre l'essentiel des rugs (financeur qui arrose 20+ portefeuilles).
   * Un explorateur muet rendait donc le bulletin le plus rassurant que ce module sache ecrire.
   *
   * ABSENCE LUE et LECTURE RATEE sont deux etats. Sur la jambe ENTRANTE il n'y a pas de reponse partielle
   * possible — sans elle il n'y a pas de financeur du tout — donc c'est `ok:false`, la forme que ce module
   * emploie deja pour « je ne peux pas repondre ». Sur la jambe des FRERES on garde `ok:true` (le
   * financeur, lui, a bien ete lu) et on refuse seulement d'affirmer le motif. */
  const incoming = (inc && Array.isArray(inc.items)) ? inc.items : null;
  if (incoming === null) return { ok: false, deployer,
    reason: 'the explorer did not return a readable transaction list for the deployer, so its funding was '
      + 'NOT read. This is a failure to look, not a finding: it is NOT "no funder was found".' };
  const funders = incoming.filter((t) => parseFloat(t.value || 0) > 0);
  if (!funders.length) return { ok: true, deployer, funder: null, siblings: [], siblingCount: 0,
    siblingsRead: null, chainRead: 'ok',
    note: 'no incoming value transfer found for the deployer — it may be funded via a contract or bridged' };

  const first = funders[funders.length - 1];            // the explorer returns newest first
  const funder = first.from && first.from.hash;
  const fundedEth = parseFloat(first.value || 0) / 1e18;
  const fundedAt = first.timestamp || null;

  // 3. What else that funder paid for. One page is enough to see the shape; we say when there are more
  //    rather than paging forever, because an unbounded crawl on a free endpoint is how we lose it.
  const out = await fetchJSON(api + '/addresses/' + funder + '/transactions?filter=from');
  const sortants = (out && Array.isArray(out.items)) ? out.items : null;
  const siblingsRead = sortants !== null;
  const sent = (sortants || []).filter((t) => parseFloat(t.value || 0) > 0);
  const byTarget = {};
  for (const t of sent) {
    const to = t.to && t.to.hash;
    if (!to || to.toLowerCase() === String(funder).toLowerCase()) continue;
    byTarget[to] = (byTarget[to] || 0) + parseFloat(t.value || 0) / 1e18;
  }
  const siblings = Object.entries(byTarget).map(([addr, eth]) => ({ addr, eth: +eth.toFixed(4) }))
    .sort((a, b) => b.eth - a.eth);

  // An identical amount repeated across many fresh wallets is a script, not a person deciding each time.
  const rounded = siblings.map((s) => s.eth.toFixed(3));
  const counts = {};
  for (const r of rounded) counts[r] = (counts[r] || 0) + 1;
  const [topAmount, identical] = Object.entries(counts).sort((a, b) => b[1] - a[1])[0] || [null, 0];

  /* ⚠️ `deployedAt` PORTAIT LA DATE DE FINANCEMENT — defaut REEL, mesure ici le 2026-07-27: les deux
   * champs sortaient identiques sur toute entree. `first` est le transfert ENTRANT. Un appelant qui
   * calcule l'ecart obtenait ZERO a chaque fois, c'est-a-dire « finance et deploye dans la meme
   * seconde »: la lecture la plus incriminante possible, servie sur tous les tokens indistinctement.
   *
   * Et FRESH_FUNDING_WINDOW_MS — « finance <6h avant le deploiement » — etait defini, exporte, et
   * utilise NULLE PART: l'heuristique que son commentaire decrit n'avait jamais ete ecrite, faute d'une
   * vraie date de deploiement. On va donc chercher l'horodatage REEL de la transaction de creation
   * (un appel de plus, borne, sur un hash deja connu). Meme correction que dans biii le meme jour. */
  let deployedAt = null;
  if (tok.creation_transaction_hash) {
    const creation = await fetchJSON(api + '/transactions/' + tok.creation_transaction_hash);
    deployedAt = (creation && creation.timestamp) || null;
  }
  /* Trois etats: mesure / pas mesurable. `null` n'est PAS `false` — « je n'ai pas pu comparer » n'est pas
   * « le portefeuille n'a pas ete finance juste avant ». */
  let fundingToDeployMs = null;
  if (fundedAt && deployedAt) {
    const d = new Date(deployedAt).getTime() - new Date(fundedAt).getTime();
    if (Number.isFinite(d)) fundingToDeployMs = d;
  }
  const freshlyFunded = fundingToDeployMs == null
    ? null
    : (fundingToDeployMs >= 0 && fundingToDeployMs <= FRESH_FUNDING_WINDOW_MS);

  const freshDeployer = incoming.length === 1;
  /* `pattern` est une PHRASE sur quelqu'un. Sans la liste des freres elle n'a pas de sujet: `null`, et le
   * motif est dit non lu. « aucun motif repete » etait une affirmation, pas un constat. */
  let pattern = siblingsRead ? 'single funder, no repeated pattern on this page' : null;
  if (siblingsRead && identical >= SIBLING_ALERT) pattern = 'the funder sent an identical ' + topAmount + ' ETH to ' + identical +
    ' different wallets — a scripted launch factory, not a person funding launches one by one';
  else if (siblingsRead && siblings.length >= SIBLING_ALERT) pattern = 'the funder has bankrolled ' + siblings.length + ' distinct wallets';

  return { ok: true, deployer, funder, fundedEth: +fundedEth.toFixed(4), fundedAt, deployedAt,
    fundingToDeployMs, freshlyFunded, freshFundingWindowMs: FRESH_FUNDING_WINDOW_MS,
    freshDeployer,
    siblings: siblings.slice(0, 12),
    siblingCount: siblingsRead ? siblings.length : null,
    siblingsRead,
    chainRead: siblingsRead ? 'ok' : 'partial',
    /* un curseur de page non lu devenait « il n y a pas d autre page » */
    morePages: siblingsRead ? !!(out && out.next_page_params) : null,
    identicalAmountSiblings: siblingsRead ? identical : null,
    identicalAmount: siblingsRead ? topAmount : null,
    pattern,
    siblingsNote: siblingsRead ? null
      : 'The funder was identified, but the explorer did not return a readable outgoing list for it, so what '
        + 'else it bankrolled was NOT read. siblingCount is null, not 0 — this is not "the funder bankrolled nothing".',
    note: 'STRUCTURE ONLY. A shared funder proves shared control or shared infrastructure, never fraud — a launchpad and a rug factory look identical here. It means these tokens share fate: judge them together, not in isolation.' };
}

module.exports = { traceFeeder, SIBLING_ALERT, FRESH_FUNDING_WINDOW_MS };
