#!/usr/bin/env node
'use strict';
/**
 * introspectHttp — l'auditeur qui rapportait « personne n'a repondu » sans avoir envoye la requete.
 * ==================================================================================================
 * ⚠️ DEUX FAMILLES DE DEFAUTS, mesurees le 2026-07-29 contre un VRAI serveur local (cette fonction n'a
 * aucun joint d'injection: on ne peut la prouver qu'en la faisant parler a une socket).
 *
 * (A) TROIS FACONS DE NE JAMAIS QUITTER LE PROCESSUS, toutes rapportees « did not answer at all »:
 *     - le PORT de l'URL n'etait jamais transmis a `https.request`. `https://hote:8443/mcp` partait sur
 *       le 443. Prouve avec un ecouteur TCP nu: ZERO connexion sur le port demande. Un MCP auto-heberge
 *       — c'est-a-dire la plupart, sur :3000, :8080, :8443 — etait audite comme absent.
 *     - le module etait cable en dur sur `https`, donc un endpoint `http://` etait injoignable.
 *     - `new URL()` jetait sur une chaine malformee, et le throw echappait a `post`.
 *     Une entree refusee ne dit RIEN sur l'endpoint. `probed:false` les separe desormais d'un vrai
 *     silence reseau.
 *
 * (B) QUATRE SITUATIONS SANS RAPPORT, UNE SEULE PHRASE — « answered initialize but returned no tool
 *     list » sortait pour une page HTML de login (pas un serveur MCP), un refus JSON-RPC explicite, un
 *     `result` sans `tools`, et un serveur MCP a zero outil. Sur un outil dont la sortie sert a decider
 *     si on PAIE un agent, « ce n'est pas un endpoint MCP » ne doit pas se lire « un endpoint MCP qui
 *     n'expose rien ». Et un statut non-200 n'est pas une absence: le fichier l'avait deja etabli pour
 *     401/403 sans le generaliser a 404/500/302/405.
 *
 * ⚠️ LA BORNE: tout ceci serait satisfait par une fonction qui refuse tout. Les cas ★ ACCEPTE ci-dessous
 * exigent l'inverse — un vrai serveur doit rendre ses outils, et `tools: []` est une REPONSE.
 *
 * Run: node test/agent-vet-introspect.test.js
 */
const http = require('node:http');
const net = require('node:net');
const { introspectHttp } = require('../lib/agent-vet');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};
const rpc = (o) => JSON.stringify({ jsonrpc: '2.0', id: 1, ...o });
const OUTILS = [{ name: 'read_thing', description: 'reads', inputSchema: { type: 'object', properties: {} } }];

const ROUTES = {
  '/plein':    { code: 200, body: rpc({ result: { serverInfo: { name: 'demo', version: '1' }, tools: OUTILS } }) },
  '/zero':     { code: 200, body: rpc({ result: { serverInfo: { name: 'vide', version: '1' }, tools: [] } }) },
  '/html':     { code: 200, body: '<!doctype html><html><body>login</body></html>' },
  '/refus':    { code: 200, body: rpc({ error: { code: -32601, message: 'method not found' } }) },
  /* `tools` PRESENT mais pas un tableau. Ce cas existe parce qu'une mutation a survecu: `[] || null`
   * rend `[]` (un tableau vide est truthy), donc l'ancien code traitait bien le zero-outil — il laissait
   * en revanche passer n'importe quelle valeur truthy, et `auditTools()` puis `.length` recevaient alors
   * un objet ou une chaine. Un serveur hostile ou simplement casse suffit. */
  '/pastableau': { code: 200, body: rpc({ result: { serverInfo: { name: 'x', version: '1' }, tools: { a: 1 } } }) },
  /* ── SSE: le mode NORMAL d'un MCP moderne, et le seul que parseMcp lisait mal ─────────────────────
   * `parseMcp` prenait la PREMIERE ligne `data:` et s'arretait. Un serveur qui envoie une notification
   * avant sa reponse — courant en streaming — voyait donc sa notification parsee a la place de sa
   * reponse: JSON parfaitement valide, aucun repli declenche, et un serveur qui avait repondu ressortait
   * « the surface is UNREAD ». Sur un outil qui RECENSE l'auditabilite, ce faux negatif gonfle le compte
   * des non-auditables. Le meme payload est servi aux deux appels (initialize ET tools/list). */
  '/sse':      { code: 200, body: 'data: ' + rpc({ result: { serverInfo: { name: 'demo', version: '1' }, tools: OUTILS } }) + '\n\n' },
  '/sse-notif': { code: 200,
    body: 'data: ' + JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: {} }) + '\n\n'
      + 'data: ' + rpc({ result: { serverInfo: { name: 'demo', version: '1' }, tools: OUTILS } }) + '\n\n' },
  '/sse-ping': { code: 200,
    body: ': keep-alive\n\nevent: message\ndata: ' + rpc({ result: { serverInfo: { name: 'demo', version: '1' }, tools: OUTILS } }) + '\n\n' },
  /* Un JSON coupe sur PLUSIEURS lignes `data:` dans UNE trame. La spec SSE exige de les concatener;
   * sans ca, chaque moitie est du JSON invalide et la reponse entiere disparait. */
  '/sse-coupe': { code: 200,
    body: 'data: {"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"demo","version":"1"},\n'
      + 'data: "tools":' + JSON.stringify(OUTILS) + '}}\n\n' },
  /* Un serveur qui n'envoie QUE des notifications: il parle MCP, il n'a simplement pas repondu. Le dire
   * « pas un endpoint MCP » serait l'accusation inverse du defaut corrige. */
  '/sse-que-notif': { code: 200,
    body: 'data: ' + JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: {} }) + '\n\n' },
  '/404':      { code: 404, body: 'nope' },
  '/401':      { code: 401, body: 'auth' },
  '/500':      { code: 500, body: 'boom' },
};

const srv = http.createServer((req, res) => {
  const r = ROUTES[req.url] || { code: 200, body: '{}' };
  res.writeHead(r.code, { 'content-type': 'application/json' });
  res.end(r.body);
});

srv.listen(0, '127.0.0.1', async () => {
  const port = srv.address().port;
  const U = (p) => 'http://127.0.0.1:' + port + p;

  /* ── (A) ★ le port est-il seulement utilise ? ────────────────────────────────────────────────── */
  process.stdout.write('la requete part-elle vraiment ou l on croit ?\n');
  let frappes = 0;
  const nu = net.createServer((s) => { frappes++; s.destroy(); });
  await new Promise((r) => nu.listen(0, '127.0.0.1', r));
  await introspectHttp('https://127.0.0.1:' + nu.address().port + '/mcp');
  check('★ le PORT de l URL est utilise (0 connexion = la requete visait le 443)', String(frappes >= 1), 'true');
  nu.close();

  check('★ un endpoint http:// est joignable (le module n est plus cable en dur sur https)',
    String((await introspectHttp(U('/plein'))).reachable), 'true');

  /* ── (A) ★ une entree refusee ne dit rien sur l endpoint ─────────────────────────────────────── */
  process.stdout.write('\nune entree refusee n est PAS une absence:\n');
  for (const [nom, u] of [['une chaine qui n est pas une URL', 'pas du tout une url'],
    ['un schema non http(s)', 'ftp://exemple.test/x']]) {
    let r; try { r = await introspectHttp(u); } catch (e) { r = { jete: e.constructor.name }; }
    check('★ ' + nom + ' ne JETTE plus', String(!r.jete), 'true');
    check('   et se declare NON SONDE', String(r.probed), 'false');
    check('   la raison dit que rien n a ete contacte',
      String(/nothing was contacted/.test(r.reason || '')), 'true');
  }

  /* ── (B) ★ quatre situations, quatre reponses ────────────────────────────────────────────────── */
  process.stdout.write('\nce que l endpoint a dit, et ce qu il n a pas dit:\n');
  const plein = await introspectHttp(U('/plein'));
  check('★ ACCEPTE: un vrai serveur rend ses outils', String(plein.tools && plein.tools.length), '1');
  check('   et aucune raison d echec', String(plein.reason), 'null');
  check('   il se declare MCP', String(plein.mcp), 'true');

  const zero = await introspectHttp(U('/zero'));
  check('★ ACCEPTE: `tools: []` est une REPONSE, pas une absence de liste',
    String(Array.isArray(zero.tools) && zero.tools.length === 0), 'true');
  check('   donc aucune raison d echec non plus', String(zero.reason), 'null');

  const html = await introspectHttp(U('/html'));
  check('★ une page HTML n est pas « un MCP sans outils »', String(html.mcp), 'false');
  check('   et la raison le DIT', String(/not an MCP endpoint at all/.test(html.reason || '')), 'true');

  /* ── ★ SSE: une reponse en streaming doit etre LUE, pas classee « surface non lue » ─────────────── */
  process.stdout.write('\nles reponses en streaming (SSE), le mode normal d un MCP:\n');
  for (const [nom, route] of [['une trame simple', '/sse'],
    ['★ une NOTIFICATION avant la reponse', '/sse-notif'],
    ['un keep-alive puis un `event:` nomme', '/sse-ping']]) {
    const r = await introspectHttp(U(route));
    check('★ ' + nom + ' : les outils sont lus', String(r.tools && r.tools.length), '1');
    check('   et aucune raison d echec', String(r.reason), 'null');
  }

  /* Ces deux cas existent parce que DEUX MUTATIONS ONT SURVECU: j'avais ecrit la concatenation
   * multi-ligne et le repli sur la premiere trame lisible sans couvrir ni l'un ni l'autre. Du code non
   * teste, pas du code inutile — la difference se voit en mutant, pas en relisant. */
  const coupe = await introspectHttp(U('/sse-coupe'));
  check('★ un JSON coupe sur deux lignes `data:` est recolle (spec SSE)',
    String(coupe.tools && coupe.tools.length), '1');

  const queNotif = await introspectHttp(U('/sse-que-notif'));
  check('★ un serveur qui n envoie QUE des notifications parle quand meme MCP',
    String(queNotif.mcp), 'true');
  check('   sa surface est UNREAD, pas vide, et il n est PAS accuse de ne pas etre un MCP',
    String(/UNREAD, not empty/.test(queNotif.reason || '')), 'true');

  const pasTab = await introspectHttp(U('/pastableau'));
  check('★ un `tools` present mais non-tableau est refuse (sinon auditTools recoit un objet)',
    String(pasTab.tools), 'null');
  check('   et il est declare NON LU, pas vide',
    String(/UNREAD, not empty/.test(pasTab.reason || '')), 'true');

  const refus = await introspectHttp(U('/refus'));
  check('★ un refus explicite se lit REFUSED, pas « rien expose »',
    String(/REFUSED tools\/list/.test(refus.reason || '')), 'true');
  check('   et il reste reconnu comme MCP (il a parle MCP pour refuser)', String(refus.mcp), 'true');

  /* ── (B) ★ un statut non-200 est une PRESENCE ────────────────────────────────────────────────── */
  process.stdout.write('\nun statut d erreur prouve que l hote est la:\n');
  for (const s of ['404', '500']) {
    const r = await introspectHttp(U('/' + s));
    check('★ HTTP ' + s + ' : l hote a REPONDU', String(r.answered), 'true');
    check('   et la raison ne pretend plus le contraire',
      String(/the host answered/.test(r.reason || '')), 'true');
  }
  check('★ BORNE: 401 reste un `gated` distinct, pas un simple non-200',
    String((await introspectHttp(U('/401'))).gated), 'true');

  /* ── ★ et le vrai silence, lui, doit rester un silence ───────────────────────────────────────── */
  const mort = await introspectHttp('http://127.0.0.1:1/x');
  check('★ BORNE: un port ferme reste « did not answer at all »',
    String(/did not answer at all/.test(mort.reason || '')), 'true');
  check('   il a bien ete SONDE, lui (c est ce qui le separe d une entree refusee)',
    String(mort.probed), 'true');
  check('   et il n a PAS repondu', String(!!mort.answered), 'false');

  srv.close();
  process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
  process.exit(failed ? 1 : 0);
});
