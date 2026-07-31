#!/usr/bin/env node
'use strict';
/**
 * agent-vet.tokenize — le decoupage du NOM d'outil, publie sur npm, nomme par aucun test jusqu'ici.
 * ====================================================================================================
 * ⚠️ LE DEFAUT QUE CES CAS EPINGLENT, mesure le 2026-07-31 PAR `auditTools` (le producteur), pas par un
 * objet fabrique a la main. Cinq outils au schema RIGOUREUSEMENT IDENTIQUE — `amount` + `to`, tous deux
 * REQUIS, soit une surface de paiement sans ambiguite — dont seul le NOM change:
 *
 *   send_usdc ....... movesValue   ✓
 *   swap1inch ....... readOnly     ⛔
 *   send2wallet ..... readOnly     ⛔
 *   USDCSend ........ readOnly     ⛔
 *   get_price ....... readOnly     ✓  le seul des cinq qui merite ce mot
 *
 * Quatre outils qui bougent des fonds recevaient donc le mot rendu a un lecteur de prix. Deux frontieres
 * de mot n'etaient pas lues: le chiffre (`swap1inch` -> ["swap1inch"]) et l'acronyme colle a un mot
 * (`USDCSend` -> ["usdcsend"], la regle ne coupant que minuscule->MAJUSCULE).
 *
 * C'est le motif du depot: une lecture RATEE rendue exactement comme une lecture reussie et vide.
 * `readOnly` est une affirmation sur l'outil; ici il ne disait que « je n'ai pas su lire son nom ».
 *
 * ⚠️ LES DEUX BORNES, partout. Chaque correctif ici pourrait etre singe par un decoupeur qui trouve un
 * verbe PLUS SOUVENT — a la limite, un decoupeur qui rend toutes les sous-chaines classerait tout en
 * `movesValue` et passerait chaque cas etoile. Donc chaque cas etoile est appaire avec son inverse:
 *   - `get_price` et `read_balance` doivent RESTER `readOnly`
 *   - `x402` doit rester un token ENTIER (c'est un nom de protocole), pas seulement `x` + `402`
 *   - un verbe sans champ de valeur ne doit pas devenir un paiement
 *   - `resendable` ne doit PAS livrer `send`: les morceaux naissent d'une frontiere reelle, jamais d'une
 *     recherche de sous-chaine
 *
 * ⚠️ ET LA LIMITE QUI RESTE, epinglee telle quelle plutot que masquee: `sendtoken` / `SENDTOKEN` n'ont
 * AUCUNE frontiere et restent un seul token. Le cas ci-dessous l'exige, pour qu'un futur « correctif » par
 * sous-chaine fasse rougir la suite au lieu de passer inapercu.
 *
 * Run: node test/agent-vet-tokenize.test.js
 */
const { tokenize, auditTools, DISCLOSURE } = require('../lib/agent-vet');

let failed = 0, cas = 0;
const check = (label, got, want) => {
  cas++;
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${JSON.stringify(want)}, obtenu ${JSON.stringify(got)}\n`);
};

/* Le PRODUCTEUR. Un seul schema, partage par tous les cas: seul le nom bouge, donc toute difference de
 * classement vient du decoupage du nom et de rien d'autre. */
const surfacePaiement = (name) => ({
  name,
  description: 'moves funds',
  inputSchema: { type: 'object', properties: { amount: { type: 'string' }, to: { type: 'string' } },
    required: ['amount', 'to'] },
});
const classe = (name) => {
  const r = auditTools([surfacePaiement(name)]);
  return Object.keys(r).find((k) => r[k].length) || 'AUCUNE';
};
const a = (s) => tokenize(s).join(',');

/* ── les temoins: ce qui marchait doit continuer a marcher ────────────────────────────────────────── */
process.stdout.write('tokenize — les decoupages qui marchaient:\n');
check('snake_case', a('wallet_transfer'), 'wallet,transfer');
check('camelCase', a('sendTransaction'), 'send,transaction');
check('kebab-case garde le token de protocole ENTIER', a('x402-settle'), 'x402,x,402,settle');
check('un acronyme en FIN de nom se detachait deja', a('sendETH'), 'send,eth');
check('point comme separateur', a('base.send.usdc'), 'base,send,usdc');
check('une entree vide ne jette pas et ne fabrique rien', a(''), '');
check('   ni null', a(null), '');

/* ── ★ la frontiere CHIFFRE ───────────────────────────────────────────────────────────────────────── */
process.stdout.write('\ntokenize — le chiffre est une frontiere de mot:\n');
check('★ swap1inch livre le verbe swap', a('swap1inch'), 'swap1inch,swap,1,inch');
check('★ send2wallet livre le verbe send', a('send2wallet'), 'send2wallet,send,2,wallet');
check('★ bridge2base livre le verbe bridge', a('bridge2base'), 'bridge2base,bridge,2,base');
check('BORNE: le nom ENTIER survit a cote des morceaux (x402 est un protocole)',
  String(tokenize('x402').includes('x402')), 'true');

/* ── ★ la frontiere ACRONYME ──────────────────────────────────────────────────────────────────────── */
process.stdout.write('\ntokenize — l acronyme colle a un mot:\n');
check('★ USDCSend', a('USDCSend'), 'usdc,send');
check('★ ETHTransfer', a('ETHTransfer'), 'eth,transfer');
check('★ un acronyme au milieu', a('getUSDCBalance'), 'get,usdc,balance');

/* ── ★ LA LIMITE QUI RESTE — exigee telle quelle ──────────────────────────────────────────────────── */
process.stdout.write('\ntokenize — ce qui reste illisible, et le reste EXPRES:\n');
check('★ sendtoken n a aucune frontiere: UN seul token', a('sendtoken'), 'sendtoken');
check('★ SENDTOKEN non plus', a('SENDTOKEN'), 'sendtoken');
check('★ BORNE: aucune sous-chaine inventee — resendable ne livre PAS send',
  String(tokenize('resendable').includes('send')), 'false');
check('★ BORNE: ni transfer dans retransfer', String(tokenize('retransfer').includes('transfer')), 'false');

/* ── par le PRODUCTEUR: le classement, qui est ce qui part chez l utilisateur ──────────────────────── */
process.stdout.write('\nauditTools — meme schema de paiement, seul le nom change:\n');
check('temoin: send_usdc etait deja lu', classe('send_usdc'), 'movesValue');
check('★ swap1inch n est PAS un outil en lecture seule', classe('swap1inch'), 'movesValue');
check('★ send2wallet non plus', classe('send2wallet'), 'movesValue');
check('★ USDCSend non plus', classe('USDCSend'), 'movesValue');
check('★ ETHTransfer non plus', classe('ETHTransfer'), 'movesValue');
check('BORNE: get_price reste en lecture seule — sinon « tout alarmer » passerait ces cas',
  classe('get_price'), 'readOnly');
check('BORNE: read_balance aussi', classe('read_balance'), 'readOnly');
check('BORNE: sendtoken reste readOnly — la limite est reelle, pas masquee',
  classe('sendtoken'), 'readOnly');

process.stdout.write('\nauditTools — la regle a DEUX conditions tient toujours:\n');
const sansValeur = auditTools([{ name: 'swap1inch',
  inputSchema: { type: 'object', properties: { q: { type: 'string' } } } }]);
check('un verbe SANS champ de valeur n est pas un paiement',
  Object.keys(sansValeur).find((k) => sansValeur[k].length) || 'AUCUNE', 'namedButNoSurface');
/* Indexation GARDEE: sous mutation ce tableau peut etre vide, et un test qui JETTE au lieu de rendre
 * FAIL rapporte un plantage la ou on attend une mesure. */
check('   et il est bien nomme malgre le chiffre',
  (sansValeur.namedButNoSurface[0] || {}).verb || 'AUCUN', 'swap');

process.stdout.write('\nDISCLOSURE — la limite se dit a l utilisateur:\n');
check('elle nomme le cas sans frontiere', String(/sendtoken/.test(DISCLOSURE)), 'true');
check('et elle refuse de faire de readOnly une preuve d inertie',
  String(/not that the tool was shown to be inert/.test(DISCLOSURE)), 'true');

/* Un fichier de test qui n exécuterait AUCUN cas sortirait vert. Le nombre est donc exige. */
if (cas < 30) { process.stdout.write(`\nSONDE CASSEE: ${cas} cas executes, moins que les 30 attendus\n`); failed++; }

process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : `tous les cas tiennent (${cas})\n`));
process.exit(failed ? 1 : 0);
