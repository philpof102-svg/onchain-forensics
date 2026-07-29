#!/usr/bin/env node
'use strict';
/**
 * holders-health — le module qui rendait le meme verdict qu'il ait lu la chaine ou non.
 * ======================================================================================
 * ⚠️ LES DEFAUTS QUE CES CAS EPINGLENT, mesures le 2026-07-29 sur un noeud bouchonne.
 *
 * `checkHoldersHealth` lisait la hauteur de bloc par `parseInt(headJson.result, 16)`. Un `result` absent
 * — un proxy qui repond 200 sans corps utile, un limiteur de debit, un `result: null` — donne NaN, et NaN
 * a traverse le module SANS RIEN CASSER: `Math.max(0, NaN - 10000).toString(16)` vaut la chaine 'NaN',
 * donc la plage envoyee au noeud etait `fromBlock: '0xNaN', toBlock: '0xNaN'`. Mesure des sorties:
 *
 *   head sans `result`        -> {healthy:false, score:20, holderCount:0, error:null}
 *   head `result: null`       -> {healthy:false, score:20, holderCount:0, error:null}
 *   getLogs sans `result`     -> {healthy:false, score:20, holderCount:0, error:null}
 *   jeton reellement CALME    -> {healthy:false, score:20, holderCount:0, error:null}   <- LE VRAI
 *
 * Les quatre chaines etaient IDENTIQUES octet pour octet. Trois pannes portaient `error: null`, qui n'est
 * pas un silence mais une AFFIRMATION: il dit que la lecture a eu lieu. Et ce verdict ne reste pas local —
 * `meme.js` l'attache sous `health` a ce qu'il rend a l'appelant, donc « la chaine n'a jamais ete lue »
 * etait publie comme « 0 porteur, score 20, aucune erreur ».
 *
 * Deuxieme defaut, meme famille: `toAddr` faisait `'0x' + String(topic).slice(26)`. Sur un `topics[1]`
 * ABSENT ca rend la chaine '0x' — une adresse fantome comptee comme un porteur — et `BigInt(data)` sur
 * les 96 octets d'un Transfer NON indexe rendait un entier de 231 chiffres. Verdict publie pour un log
 * dont aucun champ n'avait ete lu: `holderCount: 1, error: null`.
 *
 * Troisieme: un seul log a `data: '0x'` faisait jeter `BigInt` et tuait le LOT ENTIER, y compris les logs
 * parfaitement lisibles. Le correctif ne remplace pas ce tout-ou-rien par un abandon silencieux — ce
 * serait le motif meme qu'on chasse. Il COMPTE ce qu'il n'a pas su lire et publie le compte
 * (`unreadableLogs`), et `healthy` ne peut plus etre affirme par-dessus un trou.
 *
 * ⚠️ LA BORNE QUI REND CES CAS REELS. Tout ce qui precede est satisfait par un module qui refuse tout et
 * ne dit jamais « sain ». Les refus ne valent donc rien sans leurs opposes a cote: un jeton reellement
 * CALME doit garder son `score: 20, error: null`, une distribution reellement SAINE doit encore rendre
 * `healthy: true`, et les logs valides d'un lot partiellement illisible doivent decoder a la valeur EXACTE.
 *
 * Run: node test/holders-health.test.js
 */
const assert = require('assert');
const { checkHoldersHealth, fetchTransfers } = require('../lib/holders-health');

let failed = 0;
let ran = 0;
const t = (label, fn) => {
  ran++;
  return Promise.resolve().then(fn).then(
    () => console.log('  ok   ' + label),
    (e) => { failed++; console.log('  FAIL ' + label + '\n       ' + e.message); }
  );
};

const TOK = '0x' + 'ab'.repeat(20);
const ZERO_TOPIC = '0x' + '0'.repeat(64);
const holderTopic = (n) => '0x' + '0'.repeat(24) + String(n).padStart(40, '0');
const holderAddr = (n) => '0x' + String(n).padStart(40, '0');
const word = (v) => '0x' + BigInt(v).toString(16).padStart(64, '0');
const mintLog = (n, v) => ({ topics: ['0xddf2', ZERO_TOPIC, holderTopic(n)], data: word(v), blockNumber: '0x1' });

/* Le PRODUCTEUR: un noeud bouchonne. On dit ce que repond eth_blockNumber et ce que repond eth_getLogs,
 * et on passe par checkHoldersHealth — jamais par un objet transfert fabrique a la main. */
/* ⚠️ Le defaut de parametre (`logs = []`) est INTERDIT ici: il transformerait `{logs: undefined}` — la
 * facon d'exprimer « le noeud a repondu sans champ result » — en liste vide, et le bouchon serait alors
 * incapable de produire le cas meme qu'on teste. C'est le motif chasse par ce fichier, reproduit dans
 * l'instrument: les deux premiers jets de ce test ont echoue pour cette raison, pas a cause du module.
 * `'logs' in cfg` distingue la cle ABSENTE de la cle posee a undefined. */
function node(cfg = {}) {
  const head = 'head' in cfg ? cfg.head : { jsonrpc: '2.0', id: 1, result: '0x100000' };
  const logs = 'logs' in cfg ? cfg.logs : [];
  const sent = [];
  const impl = async (url, opts) => {
    const req = JSON.parse(opts.body);
    sent.push(req);
    return {
      ok: true,
      status: 200,
      json: async () => (req.method === 'eth_blockNumber' ? head : { jsonrpc: '2.0', id: 1, result: logs })
    };
  };
  return { impl, sent };
}
const verdict = (cfg) => checkHoldersHealth(TOK, { fetchImpl: node(cfg).impl });

(async () => {
  console.log('holders-health — une absence de lecture ne peut plus se lire comme une mesure');

  /* ── la hauteur de bloc ────────────────────────────────────────────────────────────────────────── */

  await t('head sans champ `result`: une panne, pas un jeton calme', async () => {
    const r = await verdict({ head: { jsonrpc: '2.0', id: 1 } });
    assert.strictEqual(r.metrics, null, 'aucune metrique ne peut etre affirmee');
    assert.strictEqual(r.score, 100);
    assert.ok(/eth_blockNumber/.test(r.error), 'l erreur doit nommer l appel fautif, vue: ' + r.error);
  });

  await t('head `result: null`: idem', async () => {
    const r = await verdict({ head: { jsonrpc: '2.0', id: 1, result: null } });
    assert.strictEqual(r.metrics, null);
    assert.ok(/eth_blockNumber/.test(r.error), 'vue: ' + r.error);
  });

  await t('head `result` non hexadecimal: idem', async () => {
    const r = await verdict({ head: { jsonrpc: '2.0', id: 1, result: 'latest' } });
    assert.strictEqual(r.metrics, null);
    assert.ok(/eth_blockNumber/.test(r.error), 'vue: ' + r.error);
  });

  await t('★ un head illisible n interroge meme pas les logs (pas de plage 0xNaN envoyee)', async () => {
    const n = node({ head: { jsonrpc: '2.0', id: 1 } });
    await checkHoldersHealth(TOK, { fetchImpl: n.impl });
    const methodes = n.sent.map((r) => r.method);
    assert.deepStrictEqual(methodes, ['eth_blockNumber'], 'un seul appel attendu, vus: ' + methodes.join(','));
  });

  /* ── la liste de logs ──────────────────────────────────────────────────────────────────────────── */

  await t('getLogs sans `result`: une panne, pas « aucun transfert »', async () => {
    const r = await verdict({ logs: undefined });
    assert.strictEqual(r.metrics, null);
    assert.ok(/eth_getLogs/.test(r.error), 'vue: ' + r.error);
  });

  await t('getLogs rendant un objet au lieu d une liste: idem', async () => {
    const r = await verdict({ logs: { items: [] } });
    assert.strictEqual(r.metrics, null);
    assert.ok(/eth_getLogs/.test(r.error), 'vue: ' + r.error);
  });

  /* ── les logs individuels ──────────────────────────────────────────────────────────────────────── */

  await t('un Transfer NON indexe ne fabrique plus un porteur fantome', async () => {
    const nonIndexe = { topics: ['0xddf2'], data: '0x' + '11'.repeat(96), blockNumber: '0x1' };
    const r = await verdict({ logs: [nonIndexe] });
    assert.strictEqual(r.metrics.holderCount, 0, 'aucun champ lu => aucun porteur');
    assert.strictEqual(r.unreadableLogs, 1, 'mais la perte est DECLAREE');
  });

  await t('un log a `data: "0x"` ne tue plus le lot: les valides survivent ET la perte est declaree', async () => {
    const bad = { topics: ['0xddf2', ZERO_TOPIC, holderTopic(2)], data: '0x', blockNumber: '0x2' };
    const r = await verdict({ logs: [mintLog(1, 10n ** 18n), bad, mintLog(1, 10n ** 18n)] });
    assert.strictEqual(r.error, null, 'un log illisible n est pas une panne de lecture');
    assert.strictEqual(r.unreadableLogs, 1);
    assert.strictEqual(r.metrics.holderCount, 1);
    assert.strictEqual(r.metrics.top10Holders[0].address, holderAddr(1));
    assert.strictEqual(r.metrics.top10Holders[0].balance, (2n * 10n ** 18n).toString(), 'la valeur EXACTE des deux logs valides');
  });

  /* ── LES BORNES OPPOSEES: sans elles, un module qui refuse tout passerait tout ce qui precede ──── */

  await t('★ BORNE: un jeton reellement calme garde score 20 / error null / 0 illisible', async () => {
    const r = await verdict({ logs: [] });
    assert.strictEqual(r.error, null, 'lecture reussie et vide: ce n est PAS une erreur');
    assert.strictEqual(r.score, 20);
    assert.strictEqual(r.metrics.holderCount, 0);
    assert.strictEqual(r.unreadableLogs, 0);
  });

  await t('★ BORNE: une distribution reellement saine rend encore healthy = true', async () => {
    const logs = Array.from({ length: 200 }, (_, i) => mintLog(i + 1, 100));
    const r = await verdict({ logs });
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.unreadableLogs, 0);
    assert.strictEqual(r.metrics.holderCount, 200);
    assert.ok(r.metrics.top10Concentration < 20, 'top 10 sur 200 parts egales ~5 %, vu ' + r.metrics.top10Concentration);
    assert.strictEqual(r.healthy, true, 'le module DOIT pouvoir dire oui');
  });

  await t('★ la meme distribution saine + UN log illisible ne peut plus etre dite saine', async () => {
    const logs = Array.from({ length: 200 }, (_, i) => mintLog(i + 1, 100));
    logs.push({ topics: ['0xddf2'], data: '0x', blockNumber: '0x9' });
    const r = await verdict({ logs });
    assert.strictEqual(r.metrics.holderCount, 200, 'les 200 valides sont toujours lus');
    assert.strictEqual(r.unreadableLogs, 1);
    assert.strictEqual(r.healthy, false, 'healthy ne s affirme pas par-dessus un trou');
  });

  await t('★ CONTROLE de discrimination: les quatre situations donnent quatre sorties distinctes', async () => {
    /* Sans ce controle, deux corrections egalement cassees s accorderaient et les cas ci-dessus
     * mesureraient une constante. On exige que les signatures different. */
    const sig = (r) => JSON.stringify([r.error && r.error.slice(0, 22), r.score, r.unreadableLogs, r.metrics && r.metrics.holderCount]);
    const vus = new Set([
      sig(await verdict({ head: { jsonrpc: '2.0', id: 1 } })),
      sig(await verdict({ logs: undefined })),
      sig(await verdict({ logs: [] })),
      sig(await verdict({ logs: [{ topics: ['0xddf2'], data: '0x', blockNumber: '0x1' }] })),
      sig(await verdict({ logs: Array.from({ length: 200 }, (_, i) => mintLog(i + 1, 100)) }))
    ]);
    assert.strictEqual(vus.size, 5, 'cinq situations opposees doivent donner cinq sorties distinctes, vu ' + vus.size);
  });

  /* ── fetchTransfers, appele directement ────────────────────────────────────────────────────────── */

  await t('fetchTransfers decode from/to/value et expose unreadable = 0 sur un lot propre', async () => {
    const logs = [mintLog(7, 5n * 10n ** 18n)];
    const ts = await fetchTransfers(TOK, { fromBlock: '0x1', toBlock: '0x2', fetchImpl: node({ logs }).impl });
    assert.strictEqual(ts.length, 1);
    assert.strictEqual(ts[0].from, '0x' + '0'.repeat(40));
    assert.strictEqual(ts[0].to, holderAddr(7));
    assert.strictEqual(ts[0].value, 5n * 10n ** 18n);
    assert.strictEqual(ts.unreadable, 0);
  });

  console.log(ran + ' cas, ' + failed + ' echec(s)');
  if (failed) process.exit(1);
})();
