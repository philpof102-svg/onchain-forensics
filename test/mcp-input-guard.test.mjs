#!/usr/bin/env node
/**
 * La surface MCP — une entree refusee ne doit pas ressembler a un verdict.
 * =========================================================================
 * ⚠️ LE DEFAUT, mesure le 2026-07-29 en pilotant le VRAI serveur en stdio (c'est la surface que les
 * utilisateurs appellent; aucun test ne la touchait):
 *
 *     rug_powers      sans `address`  ->  verdict "unknown", reason "no result"
 *     open_approvals  sans `owner`    ->  ok:true, "Every entry was confirmed by calling allowance()"
 *     open_approvals  owner malforme  ->  idem
 *
 * Le second est le pire: un balayage PROPRE ET CONFIRME, rendu pour un portefeuille que personne n'a
 * nomme. `pad(undefined)` fabrique un topic, l'explorateur ne trouve rien, et la liste vide devient un
 * feu vert sur l'outil qui repond « as-tu des autorisations ouvertes ? ». Un champ oublie par un agent
 * suffisait.
 *
 * ⚠️ ET DEUX OUTILS VOISINS FAISAIENT DEJA LE BON GESTE — `b20_authentic` repond « not a well-formed
 * address », `trace_theft` repond « txHash required ». La garde etait possible ici; elle n'etait
 * simplement pas appliquee partout. Meme motif que le plafond de `keyscan`: la bonne reponse etait deja
 * ecrite quelques lignes plus loin.
 *
 * ⚠️ LES BORNES. Tout ceci serait satisfait par un serveur qui refuse tout: le cas ★ ACCEPTE exige
 * qu'une adresse bien formee passe la garde et atteigne le moteur, et qu'un outil SANS adresse
 * (`vet_approach`) ne soit pas touche par elle.
 *
 * Run: node test/mcp-input-guard.test.mjs
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ICI = path.dirname(fileURLToPath(import.meta.url));
let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};

const srv = spawn(process.execPath, [path.join(ICI, '..', 'bin', 'onchain-forensics-mcp.js')],
  { stdio: ['pipe', 'pipe', 'pipe'] });
const att = new Map(); let buf = '', seq = 0;
srv.stdout.on('data', (c) => {
  buf += c; let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const l = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!l) continue;
    try { const m = JSON.parse(l); const r = att.get(m.id); if (r) { att.delete(m.id); r(m); } } catch {}
  }
});
const rpc = (method, params) => new Promise((res) => {
  const id = ++seq; att.set(id, res);
  srv.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
});
const call = async (name, args) => {
  const m = await rpc('tools/call', { name, arguments: args });
  try { return JSON.parse(m.result.content[0].text); } catch { return null; }
};
const estRefus = (o) => String(!!(o && typeof o.error === 'string' && /^REJECTED INPUT/.test(o.error)));

(async () => {
  await new Promise((r) => setTimeout(r, 400));
  await rpc('initialize', {});
  process.stdout.write('surface MCP — un champ oublie n est pas un resultat:\n');

  /* ── ★ les refus, sur les deux formes: absent et malforme ──────────────────────────────────────── */
  for (const [outil, champ] of [['rug_powers', 'address'], ['launch_funder', 'address'],
    ['open_approvals', 'owner'], ['watch_wallet', 'owner']]) {
    check(`★ ${outil} sans \`${champ}\` REFUSE`, estRefus(await call(outil, {})), 'true');
    check(`★ ${outil} avec un \`${champ}\` malforme REFUSE`,
      estRefus(await call(outil, { [champ]: 'pas-une-adresse' })), 'true');
  }
  const refus = await call('open_approvals', {});
  check('★ le refus DIT que rien n a ete consulte',
    String(/Nothing was looked up/.test(refus.error || '')), 'true');
  check('★ et qu il ne s agit PAS d un resultat vide',
    String(/NOT an empty result/.test(refus.error || '')), 'true');
  check('★ il ne porte AUCUN verdict (sinon on aurait juste renomme le probleme)',
    String(refus.verdict === undefined && refus.ok === undefined), 'true');

  /* ── ★ les bornes: la garde ne doit ni tout refuser, ni deborder ───────────────────────────────── */
  const bonne = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';   // USDC sur Base, adresse publique
  const passe = await call('rug_powers', { address: bonne });
  check('★ BORNE: une adresse BIEN FORMEE traverse la garde et atteint le moteur',
    estRefus(passe), 'false');
  check('   et elle revient avec un vrai verdict', String(typeof passe.verdict === 'string'), 'true');

  const sansAdresse = await call('vet_approach', { links: [], message: 'bonjour' });
  check('★ BORNE: un outil qui ne prend pas d adresse n est pas touche par la garde',
    estRefus(sansAdresse), 'false');
  check('   il rend toujours son verdict', String(typeof sansAdresse.verdict === 'string'), 'true');

  const temoin = await call('trace_theft', { mode: 'moved' });
  check('BORNE: la garde preexistante de trace_theft est intacte',
    String(/txHash required/.test(temoin.error || '')), 'true');

  /* ── la BIBLIOTHEQUE, pas seulement le serveur ─────────────────────────────────────────────────
   * `checkApprovals` est exporte par lib/index.js: un utilisateur qui l'appelle directement ne passe
   * jamais par la garde du serveur. Proteger uniquement la surface MCP laisserait le feu vert
   * fabrique intact pour tout le reste — et c'est la copie publiee sur npm. */
  process.stdout.write('\nla bibliotheque elle-meme (appelee sans passer par le serveur):\n');
  const { checkApprovals } = await import('../lib/approvals.js');
  for (const [nom, v] of [['undefined', undefined], ['une chaine vide', ''], ['un texte', 'nawak'],
    ['une adresse trop courte', '0x1234']]) {
    const r = await checkApprovals('base', v);
    check(`★ checkApprovals avec ${nom} rend ok:false`, String(r.ok), 'false');
    check('   et se declare entree refusee', String(r.rejectedInput), 'true');
  }
  const r0 = await checkApprovals('base', 'nawak');
  check('★ le message interdit de le lire comme une liste vide',
    String(/not an empty approval list/.test(r0.reason || '')), 'true');

  srv.kill();
  process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
  process.exit(failed ? 1 : 0);
})().catch((e) => { srv.kill(); process.stderr.write('le test a jete: ' + e.message + '\n'); process.exit(1); });
