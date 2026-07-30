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
import fs from 'node:fs';
import os from 'node:os';
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

  /* ── ★ L'AUTRE ARGUMENT: `paths` — mesure du 2026-07-30 ────────────────────────────────────────────
   * Avec USERPROFILE pointe sur une fausse maison vide et un dossier temoin contenant une phrase en
   * clair, `seed_exposure` appele avec paths: "<le dossier qui contient la phrase>" rendait EXACTEMENT
   * la meme reponse que sans paths du tout: nothing_found, complete:true, "nothing blocked a read".
   * `Array.isArray` etait faux, l'argument tombait en silence sur les chemins par defaut, et on
   * repondait le bulletin le plus rassurant du module a propos de dossiers que personne n'avait nommes.
   *
   * ⚠️ Aucun cas ici n'appelle l'outil SANS `paths`: cela balaierait le vrai dossier Documents de la
   * personne qui lance la suite. La borne positive passe par une fixture temporaire. */
  process.stdout.write('\nla liste de chemins — une entree inutilisable n est pas un balayage propre:\n');
  const bac = path.join(os.tmpdir(), 'mcp-paths-' + process.pid);
  fs.mkdirSync(bac, { recursive: true });
  fs.writeFileSync(path.join(bac, 'notes.txt'), 'backup\n' + ('abandon '.repeat(11) + 'about') + '\n');
  try {
    for (const outil of ['seed_exposure', 'key_exposure']) {
      for (const [nom, v] of [['une chaine', bac], ['un nombre', 42], ['un tableau vide', []],
        ['un tableau avec une chaine vide', ['']], ['un tableau avec un nombre', [123]]]) {
        check(`★ ${outil} avec ${nom} REFUSE`, estRefus(await call(outil, { paths: v })), 'true');
      }
    }
    const refusC = await call('seed_exposure', { paths: bac });
    check('★ le refus DIT que rien n a ete balaye',
      String(/Nothing was scanned/.test(refusC.error || '')), 'true');
    check('★ et interdit de le lire comme un resultat propre',
      String(/NOT a clean result/.test(refusC.error || '')), 'true');
    check('★ il ne porte AUCUN verdict', String(refusC.verdict === undefined), 'true');

    /* ★ BORNE — sinon un serveur qui refuse tout passerait tous les cas ci-dessus. Le dossier temoin
     * contient une phrase valide: la garde doit laisser passer, et le moteur doit la trouver. */
    const bonPaths = await call('seed_exposure', { paths: [bac] });
    check('★ BORNE: un tableau de chemins traverse la garde', estRefus(bonPaths), 'false');
    check('   et le moteur trouve bien la phrase du dossier temoin', String(bonPaths.verdict), 'exposed');
    const bonKeys = await call('key_exposure', { paths: [bac] });
    check('★ BORNE: key_exposure aussi traverse la garde', estRefus(bonKeys), 'false');
    check('   et rapporte un balayage reel', String(bonKeys.scanned > 0), 'true');

    /* ── la BIBLIOTHEQUE: `for (const root of paths)` accepte une CHAINE et l'iterait par caractere ──
     * "C:\\...\\coffre" devenait autant de chemins d'un caractere; le bulletin annoncait « 22 path(s)
     * were given », et sous Windows `existsSync('\\')` est vrai, donc le balayage partait sur la racine
     * du disque a profondeur 6 (la premiere sonde a tourne >120 s). */
    process.stdout.write('\nles deux fonctions de balayage appelees directement:\n');
    const SEED = await import('../lib/seedscan.js');
    const KEY = await import('../lib/keyscan.js');
    const idx = SEED.loadWordlist();
    const jette = (fn) => { try { fn(); return 'non'; } catch (e) { return e instanceof TypeError ? 'TypeError' : 'autre'; } };
    /* ⚠️ La chaine passee ici est `zz`, PAS un vrai chemin — et c'est le defaut lui-meme qui l'impose.
     * Mesure du 2026-07-30 en mutation-testant ces cas: en retirant la garde, `scanPaths('<vrai chemin>')`
     * decoupe l'argument en caracteres, tombe sur `\` qui EXISTE, et part balayer la racine du disque
     * jusqu'au delai de 180 s. La mutation etait bien tuee, mais par un BLOCAGE et non par une assertion
     * — un test dont le mode d echec est une suite figee trois minutes apprend a tuer la suite. Avec
     * `zz`, aucun caractere n'existe comme chemin: sans garde le cas rend `not_scanned` et le test
     * rougit tout de suite, ce qui est la meme information rendue en une seconde. */
    check('★ scanPaths avec une chaine JETTE', jette(() => SEED.scanPaths('zz', idx)), 'TypeError');
    check('★ scanPaths avec null JETTE', jette(() => SEED.scanPaths(null, idx)), 'TypeError');
    check('★ scanPaths avec [\'\'] JETTE', jette(() => SEED.scanPaths([''], idx)), 'TypeError');
    check('★ scanKeyPaths avec une chaine JETTE', jette(() => KEY.scanKeyPaths('zz')), 'TypeError');
    check('★ scanKeyPaths avec [123] JETTE', jette(() => KEY.scanKeyPaths([123])), 'TypeError');
    /* ★ BORNE — une liste VIDE reste valide: c'est ce que `defaultPaths` rend quand aucune racine n'est
     * resolue, et les deux balayages savent deja la traduire en « on n'a pas regarde ». Durcir jusqu'a
     * la refuser ici ferait jeter l'outil la ou il doit rendre `not_scanned`. */
    check('★ BORNE: scanPaths([]) ne jette PAS', jette(() => SEED.scanPaths([], idx)), 'non');
    check('   et rend not_scanned, pas nothing_found', SEED.scanPaths([], idx).verdict, 'not_scanned');
    check('★ BORNE: scanKeyPaths([]) ne jette PAS', jette(() => KEY.scanKeyPaths([])), 'non');
    check('   et rend not_scanned', KEY.scanKeyPaths([]).verdict, 'not_scanned');
    check('★ BORNE: un vrai tableau de chemins traverse et trouve', SEED.scanPaths([bac], idx).verdict, 'exposed');
  } finally {
    fs.rmSync(bac, { recursive: true, force: true });
  }

  srv.kill();
  process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
  process.exit(failed ? 1 : 0);
})().catch((e) => { srv.kill(); process.stderr.write('le test a jete: ' + e.message + '\n'); process.exit(1); });
