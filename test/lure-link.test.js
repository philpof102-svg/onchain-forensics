#!/usr/bin/env node
'use strict';
/**
 * lure.checkLink — the link judgement, published on npm, named in no test until now.
 * ===================================================================================
 * ⚠️ THE THREE DEFECTS THESE CASES PIN, measured 2026-07-29 by calling `checkLink` on real phishing forms.
 *
 * One shape: a URL whose host was never really read still received a verdict ABOUT A DOMAIN.
 *
 *   https://zoom.us@evil-recorder.com/join  -> `unrecognised`, "That is not an accusation"
 *   file:///C:/x/setup.exe                  -> `unrecognised`, 'Domain "" … not an accusation'
 *   http://185.62.188.12/recorder.exe       -> `unrecognised`, registrable "188.12"   ← invented
 *
 * The first is this module's own thesis turned against it. Its docstring reads "anyone can put any brand
 * name to the LEFT of a domain they control" — and the `@` form does exactly that, one character earlier.
 * `new URL` files everything before the `@` under `username`, so `hostname` comes back clean and every
 * check passed. The cost is not cosmetic: `brand_impersonation` is FATAL in `vetApproach` (verdict
 * `fraud`), while `unrecognised` is one flag among several. The MORE deceptive form scored LOWER.
 *
 * The third is the same failure as the one `registrableDomain`'s own docstring already confesses: a parse
 * that did not really succeed returns a plausible-looking answer. "188.12" reads like a domain. It is the
 * last two octets of an IP address.
 *
 * ⚠️ BOTH BOUNDS, EVERY TIME. Each fix could be faked by a function that refuses more often, so every
 * starred case is paired with its opposite:
 *   - the `@` check must NOT fire when the brand owns the destination (`zoom.us@zoom.us`)
 *   - the scheme check must NOT escalate `mailto:` — a check that fires on an email address gets muted
 *   - the three witness URLs must keep their exact previous verdicts
 *
 * Run: node test/lure-link.test.js
 */
const { checkLink, vetApproach } = require('../lib/lure');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       attendu ${want}, obtenu ${got}\n`);
};
const v = (url) => checkLink(url).verdict;

/* ── the witnesses: behaviour that existed and must not move ──────────────────────────────────────── */
process.stdout.write('checkLink — ce qui marchait doit continuer a marcher:\n');
check('un label de marque devant un domaine tiers reste une impersonation',
  v('https://wechat.web09eu.com/dl'), 'brand_impersonation');
check('   et il nomme le domaine REELLEMENT enregistre',
  checkLink('https://wechat.web09eu.com/dl').registrable, 'web09eu.com');
check('une plateforme navigateur reste reconnue', v('https://riverside.fm/studio/x'), 'browser_native');
check('le produit de la marque elle-meme n est PAS une impersonation',
  v('https://meet.google.com/abc-defg-hij'), 'browser_native');
check('un domaine inconnu reste inconnu', v('https://beaconlayer.co/'), 'unrecognised');
check('un service reel et neutre reste neutre', v('https://calendly.com/x/30min'), 'recognised_neutral');
check('une chaine illisible reste illisible', v('pas une url'), 'unreadable');

/* ── ★ the `@` trick: the brand to the left, one character earlier ────────────────────────────────── */
process.stdout.write('\ncheckLink — la marque avant l arobase:\n');
check('★ zoom.us@evil-recorder.com est une IMPERSONATION, pas un domaine inconnu',
  v('https://zoom.us@evil-recorder.com/join'), 'brand_impersonation');
check('★ et le domaine rapporte est la VRAIE destination',
  checkLink('https://zoom.us@evil-recorder.com/join').registrable, 'evil-recorder.com');
check('★ la marque usurpee est nommee',
  checkLink('https://zoom.us@evil-recorder.com/join').impersonates[0], 'zoom');
check('★ le mecanisme est declare, pour qu on ne confonde pas les deux formes',
  String(checkLink('https://zoom.us@evil-recorder.com/join').viaUserinfo), 'true');
check('★ la raison EXPLIQUE l arobase au lieu de parler de sous-domaine',
  String(/before the "@" is a username/.test(checkLink('https://zoom.us@evil-recorder.com/join').reason)), 'true');
check('★ un mot de passe cache la marque aussi bien qu un nom d utilisateur',
  v('https://x:riverside.fm@web09eu.com/dl'), 'brand_impersonation');
check('★ BORNE: la marque devant SON PROPRE domaine n est pas une impersonation',
  v('https://zoom.us@zoom.us/j/123'), 'browser_native');
check('★ BORNE: une arobase SANS marque connue ne declenche rien',
  v('https://user@beaconlayer.co/'), 'unrecognised');

/* ── ★ schemes that carry content instead of pointing at a page ───────────────────────────────────── */
process.stdout.write('\ncheckLink — un schema qui n est pas http(s):\n');
check('★ file: n est pas un domaine inconnu', v('file:///C:/Users/x/Downloads/setup.exe'), 'not_a_web_link');
check('★ javascript: non plus', v('javascript:alert(document.cookie)'), 'not_a_web_link');
check('★ data: non plus', v('data:text/html;base64,PHNjcmlwdD4='), 'not_a_web_link');
check('★ et AUCUN ne publie un domaine fabrique',
  String(checkLink('file:///C:/x/setup.exe').registrable), 'null');
check('★ le schema est rapporte, c est lui la reponse',
  checkLink('javascript:alert(1)').scheme, 'javascript');
check('★ la raison de file: DIT que le lien EST l installation',
  String(/IS the install, not a link to one/.test(checkLink('file:///C:/x/setup.exe').reason)), 'true');
check('BORNE: mailto: est ordinaire — il sort du chemin domaine mais ne crie pas',
  v('mailto:producer@web09eu.com'), 'not_a_web_link');

/* ── ★ raw addresses: nothing was registered, so there is no registrable part ──────────────────────── */
process.stdout.write('\ncheckLink — une adresse nue n est pas un domaine:\n');
check('★ une IPv4 n est plus un "domaine inconnu"', v('http://185.62.188.12/recorder.exe'), 'ip_literal');
check('★ et elle ne rapporte plus "188.12" comme domaine enregistrable',
  String(checkLink('http://185.62.188.12/recorder.exe').registrable), 'null');
check('★ une IPv6 non plus', v('http://[2001:db8::1]/x'), 'ip_literal');
check('★ et elle ne rapporte plus "[2001"',
  String(checkLink('http://[2001:db8::1]/x').registrable), 'null');
check('BORNE: un domaine qui CONTIENT des chiffres reste un domaine',
  v('https://web09eu.com/'), 'unrecognised');

/* ── the wiring: a new verdict nobody reads is a writer without a reader ──────────────────────────── */
process.stdout.write('\nvetApproach — les nouveaux verdicts sont-ils LUS ?\n');
const approche = (links, extra) => vetApproach({ links, ...extra });
check('★ un lien file: rend le verdict FRAUDE, pas "non verifie"',
  approche(['file:///C:/x/setup.exe']).verdict, 'fraud');
check('★ et la raison nomme le schema plutot qu un domaine',
  String(/does not point at a page/.test(approche(['file:///C:/x/setup.exe']).reason)), 'true');
check('★ un lien javascript: aussi', approche(['javascript:alert(1)']).verdict, 'fraud');
check('★ BORNE: un mailto: ne rend PAS fraude — sinon la verification se fait couper le son',
  approche(['mailto:producer@web09eu.com']).verdict, 'unverified');
check('★ BORNE: et il ne leve aucun fatal',
  String(approche(['mailto:producer@web09eu.com']).fatal.length), '0');
check('★ le lien en arobase remonte jusqu au verdict FRAUDE',
  approche(['https://zoom.us@evil-recorder.com/join']).verdict, 'fraud');
check('★ une IP nue leve un drapeau (et un seul drapeau ne suffit pas a escalader)',
  String(approche(['http://185.62.188.12/x']).flags.some((f) => /raw IP address/.test(f))), 'true');
check('   avec un seul drapeau, le verdict reste non verifie',
  approche(['http://185.62.188.12/x']).verdict, 'unverified');
check('BORNE: deux drapeaux escaladent toujours, la nouvelle voie ne casse pas le compte',
  approche(['http://185.62.188.12/x'], { urgency: true }).verdict, 'high_risk');

process.stdout.write('\n' + (failed ? `${failed} cas en echec\n` : 'tous les cas tiennent\n'));
process.exit(failed ? 1 : 0);
