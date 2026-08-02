'use strict';
/**
 * recovery.js — the second theft: "we can recover your stolen funds".
 * ====================================================================
 * Everything else in this codebase tries to stop the first loss. This one exists because the first loss is
 * when a person becomes findable, and within hours of a public drain the victim is approached by people
 * offering to get the money back. They are almost never the same people who took it, and that is the point:
 * a drained wallet is a lead, and there is a market for leads.
 *
 * The reason this can be answered with certainty rather than a score is that the ask itself is the tell.
 * Recovering stolen funds means either the thief returns them, or a court, an exchange, or an issuer freezes
 * and reassigns them. None of those routes require anything from the victim's wallet. So a "recovery" that
 * needs your signature or an upfront fee is not a service that might be dishonest — it is structurally
 * impossible as described. That is a fact about how custody works, not a probability, and it holds no matter
 * how credible the person sounds or how much of your loss they can correctly describe back to you.
 *
 * Knowing details of the theft proves nothing: the theft is public. Anyone reading the chain can recite the
 * amounts, the timestamps, and the token names. Victims read that recitation as proof of insider knowledge,
 * which is exactly why the approach works.
 *
 * On top of the rule, this reads the chain for the harvesting signature: an address that collects small
 * payments from many distinct senders and returns nothing. Recovery operations never send funds back —
 * having nothing to return is the business model — so a one-way funnel is the shape to look for.
 */
const https = require('node:https');

const EXPLORER = {
  base: 'https://base.blockscout.com/api/v2',
  ethereum: 'https://eth.blockscout.com/api/v2',
  polygon: 'https://polygon.blockscout.com/api/v2',
  arbitrum: 'https://arbitrum.blockscout.com/api/v2',
  optimism: 'https://optimism.blockscout.com/api/v2',
};

const MANY_SENDERS = 5;        // a handful of unrelated payers is already a funnel, not a client relationship
const FUNNEL_RATIO = 0.15;     // outbound below this share of inbound = it collects and does not return

const getJSON = (url) => new Promise((resolve) => {
  https.get(url, { headers: { accept: 'application/json' } }, (res) => {
    let d = ''; res.on('data', (c) => (d += c));
    res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
  }).on('error', () => resolve(null));
});

/** The part that needs no chain data and admits no exception. */
const HARD_RULES = [
  'No recovery of stolen funds requires a signature from the victim. Signing is how you AUTHORISE a transfer, so a "recovery" transaction you sign moves what you have left — outward.',
  'No recovery requires an upfront fee. Recovery happens through the thief returning funds, or a court, exchange, or token issuer freezing and reassigning them. None of those routes charge the victim in advance.',
  'Knowing the details of your theft proves nothing. The amounts, timestamps, and token names are public on the chain — anyone can read them back to you, and that recitation is what makes the approach convincing.',
  'Never share a seed phrase, private key, or keystore file. Not to a recovery service, not to support, not to anyone. A recovery service that needs your key is asking for the same thing the thief already took.',
  'Never install software to "track" or "recover" funds. That is how many victims are compromised a second time, by a different operator.',
];

/**
 * assessRecoveryOffer — judge an approach offering to recover stolen funds.
 * @param {object} opts
 *   address              - the address the victim is asked to pay or interact with (optional)
 *   chain                - 'base' (default) | ethereum | polygon | arbitrum | optimism
 *   asksForSignature     - were they asked to sign a message or transaction?
 *   asksForUpfrontPayment- were they asked to pay a fee first?
 *   asksForSeedOrKey     - were they asked for a seed phrase, private key or keystore?
 *   asksToInstall        - were they asked to download or run anything?
 * @returns { verdict, reason, fatal[], chainEvidence, rules, disclosure }
 *   verdict: 'fraud' | 'high_risk' | 'unverified'
 */
async function assessRecoveryOffer({ address, chain = 'base', asksForSignature, asksForUpfrontPayment,
  asksForSeedOrKey, asksToInstall, fetchImpl } = {}) {
  const fatal = [];
  if (asksForSeedOrKey) fatal.push('They asked for a seed phrase or private key. That is the theft itself, restated as help.');
  if (asksForSignature) fatal.push('They asked you to sign. A signature authorises an outgoing transfer — it cannot pull funds back to you. There is no legitimate version of this request.');
  if (asksForUpfrontPayment) fatal.push('They asked for payment before delivering. No route to recovering stolen funds bills the victim in advance.');
  if (asksToInstall) fatal.push('They asked you to install something. This is how a victim is compromised a second time, often by a different operator than the first.');

  // Chain evidence is supporting material only. The rule above already decides the case when any fatal
  // element is present, and it decides it without needing the address to have any history at all — which
  // matters, because a fresh address has nothing to find and its emptiness must never read as reassurance.
  /* ⚠️ LA MOITIE DE CE BLOC AFFIRMAIT CE QU'ELLE N'AVAIT PAS LU. Mesure du 2026-08-02, hors ligne, par
   * `fetchImpl` — QUATRE situations, DEUX sorties distinctes, et les trois premieres identiques OCTET
   * POUR OCTET (verdict, chainEvidence et reason confondus):
   *
   *   explorateur LU, adresse reellement vide ..... distinctSenders 0, flaggedByExplorer false, note « rien de concluant »
   *   explorateur qui n'a JAMAIS repondu .......... la MEME reponse                       ⛔
   *   explorateur qui rend un CORPS D'ERREUR ...... la MEME reponse                       ⛔
   *   vrai entonnoir (temoin oppose) .............. high_risk, 9 senders                  ✓ (donc la sonde mesure)
   *
   * `getJSON` resout `null` sur panne reseau ET sur corps non-JSON (page d'erreur, 429), et ne lit aucun
   * code HTTP: un `{message:'...'}` de 500 passe pour une reponse. `(inTx && inTx.items) || []` aplatissait
   * les trois cas sur la liste vide, et `!!(info && info.is_scam)` transformait « l'explorateur n'a pas
   * repondu » en « l'explorateur n'a pas signale cette adresse ». Sur CE module, l'affirmation porte sur
   * l'adresse qu'une victime fraichement drainee s'apprete a payer.
   *
   * L'en-tete disait deja la bonne doctrine — « its emptiness must never read as reassurance » — et la
   * `note` la disait en toutes lettres pour l'adresse NEUVE. Elle etait vraie pour une absence LUE, et
   * elle etait servie pour une absence NON LUE. Bien resolu a un endroit, pas a l'autre.
   *
   * ABSENCE LUE, LECTURE RATEE et LECTURE NON TENTEE sont trois etats. `chainRead` les nomme; les champs
   * qu'aucune lecture n'appuie valent desormais `null` et non `false`/`0`. Les valeurs de `verdict` sont
   * inchangees, et `readsAsHarvesting: null` reste falsy: aucun appelant existant ne change de branche. */
  const listeLue = (r) => (r && Array.isArray(r.items)) ? r.items : null;
  const drapeauLu = (o, k) => (o && typeof o[k] === 'boolean') ? o[k] : null;

  let chainEvidence = null;
  let chainRead = !address ? 'not_attempted_no_address'
    : (EXPLORER[String(chain).toLowerCase()] ? null : 'not_attempted_unsupported_chain');
  if (chainRead === null) {
    const api = EXPLORER[String(chain).toLowerCase()];
    const [inTx, outTx, info] = await Promise.all([
      (fetchImpl || getJSON)(api + '/addresses/' + address + '/transactions?filter=to'),
      (fetchImpl || getJSON)(api + '/addresses/' + address + '/transactions?filter=from'),
      (fetchImpl || getJSON)(api + '/addresses/' + address),
    ]);
    const inItems = listeLue(inTx);
    const outItems = listeLue(outTx);
    const isContract = drapeauLu(info, 'is_contract');
    const flaggedByExplorer = drapeauLu(info, 'is_scam');

    const illisible = [];
    if (inItems === null) illisible.push('inbound transfers');
    if (outItems === null) illisible.push('outbound transfers');
    if (isContract === null && flaggedByExplorer === null) illisible.push('the address record');
    chainRead = !illisible.length ? 'ok' : (illisible.length === 3 ? 'unavailable' : 'partial');

    const ins = (inItems || []).filter((t) => parseFloat(t.value || 0) > 0);
    const outs = (outItems || []).filter((t) => parseFloat(t.value || 0) > 0);
    const senders = new Set(ins.map((t) => (t.from && t.from.hash || '').toLowerCase()).filter(Boolean));
    const inTotal = ins.reduce((s, t) => s + parseFloat(t.value || 0), 0) / 1e18;
    const outTotal = outs.reduce((s, t) => s + parseFloat(t.value || 0), 0) / 1e18;
    /* Le flux demande LES DEUX jambes: un entrant lu avec un sortant illisible ne dit rien du ratio. */
    const fluxLu = inItems !== null && outItems !== null;
    const oneWay = fluxLu ? (inTotal > 0 && (outTotal / inTotal) < FUNNEL_RATIO) : null;
    const harvesting = fluxLu ? (senders.size >= MANY_SENDERS && oneWay) : null;

    chainEvidence = {
      distinctSenders: inItems === null ? null : senders.size,
      inboundCount: inItems === null ? null : ins.length,
      outboundCount: outItems === null ? null : outs.length,
      inboundEth: inItems === null ? null : +inTotal.toFixed(6),
      outboundEth: outItems === null ? null : +outTotal.toFixed(6),
      isContract,
      flaggedByExplorer,
      oneWayFunnel: oneWay,
      readsAsHarvesting: harvesting,
      chainRead,
      unreadable: illisible,
      note: harvesting
        ? senders.size + ' unrelated addresses have paid this one, and it has returned almost nothing. That is a collection funnel, not a service with clients.'
        : illisible.length
          ? 'The explorer did not answer for ' + illisible.join(' and ') + ', so that part of the chain was NOT read. '
            + 'This is a failure to look, not a finding: nothing below is evidence that this address is clean.'
          : 'Nothing conclusive in the flow. Absence of a pattern is NOT evidence of legitimacy — a fresh address has no history to incriminate it, which is why operations use fresh addresses.',
    };
  }

  const verdict = fatal.length ? 'fraud'
    : (chainEvidence && chainEvidence.readsAsHarvesting) ? 'high_risk'
    : 'unverified';

  const RIEN_LU = {
    not_attempted_no_address: 'No address was given, so nothing on-chain was checked at all.',
    not_attempted_unsupported_chain: 'No chain was read: "' + chain + '" is not one this tool can query '
      + '(base, ethereum, polygon, arbitrum, optimism).',
    unavailable: 'The explorer answered none of the three reads, so the chain was NOT checked.',
    partial: 'Part of the chain could not be read, so the flow below is incomplete.',
  };
  const reason = fatal.length
    ? fatal[0]
    : (chainEvidence && chainEvidence.readsAsHarvesting)
      ? chainEvidence.note
      : (RIEN_LU[chainRead]
          ? RIEN_LU[chainRead] + ' No fatal request was reported either. This is NOT a clearance — and it is '
            + 'not an empty result: if at any point they ask you to sign, pay first, install something, or '
            + 'share a key, the answer is already no.'
          : 'No fatal request was reported and the chain shows nothing conclusive. This is NOT a clearance: if at any point they ask you to sign, pay first, install something, or share a key, the answer is already no.');

  return { verdict, reason, fatal, chainEvidence, chainRead, rules: HARD_RULES,
    disclosure: 'This tool never returns "safe". Recovery of stolen funds happens through the thief, a court, an exchange, or a token issuer — never through the victim\'s wallet. Any request directed at your wallet is the second theft, regardless of how much the person correctly knows about the first one.' };
}

module.exports = { assessRecoveryOffer, HARD_RULES, MANY_SENDERS, FUNNEL_RATIO };
