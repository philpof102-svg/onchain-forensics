'use strict';
/**
 * lure.js — judging an inbound opportunity by what it ASKS, not by how good it looks.
 * ===================================================================================
 * Written from a real lure that worked on someone who verifies counterparties for a living. It was not
 * phishing in any recognisable sense: a 35-question production dossier across six chapters, with per-chapter
 * shot lists, that cited the target's actual scoring model, his settlement rails, his leaderboard
 * methodology, his own catchphrase, and quoted one of his posts verbatim.
 *
 * It also asked HARD questions — whether compressing reputation into one number creates false certainty,
 * whether the oracle profits from generating fear, what happens when a verdict is wrong. That was the
 * payload, not the praise. A flatterer never includes criticism, so including it is exactly what flips an
 * approach from "marketing" to "journalism" in the reader's head.
 *
 * The mechanism underneath is EFFORT AS A TRUST SIGNAL. Producing that much researched detail used to cost
 * hours of human work, so nobody spent it to scam one person, and every reader's intuition silently priced
 * that in. The arithmetic was correct for decades. It is not correct now: the same document generates in
 * minutes from a public profile. Effort stopped being evidence and nobody updated their instincts.
 *
 * So this module refuses to score the approach at all. Detail, professionalism, research and polish are all
 * cheap now, and grading them would just launder a forgery. It grades two things a forger cannot make
 * harmless: the DOMAIN the link actually points at, and what the sender WANTS you to do.
 */

// Brands whose names get borrowed as subdomains, each mapped to the domains that legitimately own it.
// The map is what makes this usable: a first version keyed on brand names alone flagged `meet.google.com` —
// Google Meet, the real one — as impersonation. A tool that warns about Google Meet is a tool people
// uninstall, and it would have been shipped without the false-positive test that caught it. A brand under
// its OWN domain is the product; the same brand under a domain nobody has heard of is the attack.
const IMPERSONATED = {
  wechat: ['wechat.com', 'weixin.qq.com', 'qq.com'],
  zoom: ['zoom.us', 'zoom.com'],
  teams: ['microsoft.com', 'office.com', 'live.com'],
  meet: ['google.com', 'jit.si'],
  google: ['google.com', 'goo.gl', 'withgoogle.com'],
  microsoft: ['microsoft.com', 'office.com', 'live.com', 'azure.com'],
  riverside: ['riverside.fm'],
  streamyard: ['streamyard.com'],
  calendly: ['calendly.com'],
  notion: ['notion.so', 'notion.com', 'notion.site'],
  discord: ['discord.com', 'discord.gg', 'discordapp.com'],
  telegram: ['telegram.org', 't.me', 'telegram.me'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  signal: ['signal.org'],
  skype: ['skype.com', 'microsoft.com'],
  webex: ['webex.com', 'cisco.com'],
  slack: ['slack.com'],
  linkedin: ['linkedin.com', 'lnkd.in'],
  metamask: ['metamask.io'],
  ledger: ['ledger.com'],
  trezor: ['trezor.io'],
  coinbase: ['coinbase.com', 'cb.id'],
  binance: ['binance.com', 'binance.us'],
  opensea: ['opensea.io'],
  uniswap: ['uniswap.org'],
  phantom: ['phantom.app', 'phantom.com'],
  rabby: ['rabby.io'],
};

// A genuine recording session runs in the browser. Every platform here needs nothing installed, which is why
// asking for an install is the discriminator rather than the platform's name.
const BROWSER_NATIVE = ['riverside.fm', 'zoom.us', 'meet.google.com', 'streamyard.com', 'teams.microsoft.com',
  'whereby.com', 'squadcast.fm', 'zencastr.com', 'meet.jit.si'];

/**
 * Extract the registrable domain — the part someone actually had to buy. Everything to its left is a label
 * the domain's owner creates for free, which is the entire trick: `wechat.web09eu.com` is not WeChat, it is
 * `web09eu.com` with a label named "wechat".
 *
 * Uses a two-label heuristic plus the common two-part public suffixes. A full public-suffix list would be
 * more precise, but the failure mode here is mild: an unusual suffix makes the registrable domain read one
 * label too short, which can only ever produce a MORE cautious answer, never a false all-clear.
 */
const TWO_PART_SUFFIX = ['co.uk', 'co.jp', 'com.br', 'com.au', 'co.nz', 'com.cn', 'co.in', 'com.mx', 'co.za', 'com.tr'];

function registrableDomain(hostnameOrUrl) {
  // Takes a hostname, and tolerates a full URL because that is what callers reach for. The earlier version
  // took only a hostname — correctly, per its own docstring — and handed back the entire URL unchanged when
  // given one: `https://beaconlayer.co/` in, `https://beaconlayer.co/` out. No throw, no empty string, just a
  // plausible-looking answer that is wrong. I did exactly that while testing this module against the real
  // attack it was written for. A public helper whose most likely misuse returns silent garbage is a defect
  // even when the docstring is right, because nobody reads a docstring to check an answer that looks fine.
  let s = String(hostnameOrUrl).trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try { s = new URL(s).hostname; } catch { /* unparseable: fall through and treat it as a hostname */ }
  }
  s = s.replace(/^\/+/, '').split('/')[0].split('?')[0].split('#')[0].split('@').pop().split(':')[0];
  const labels = s.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  return TWO_PART_SUFFIX.includes(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

/**
 * Platforms that are real and prove nothing. Calendly is not a recording tool, so it does not belong in
 * BROWSER_NATIVE — but calling it "not a platform this recognises" is worse than saying nothing: it is the
 * `meet.google.com` false positive again, and a tool that warns about Calendly gets muted.
 *
 * The distinction is the useful part. In the approach this module was written from, the Calendly link was
 * GENUINE — a real account on a real service. Legitimate infrastructure is the cover, not the tell. So these
 * report as recognised-and-neutral: no flag, and no comfort either.
 */
const LEGIT_NEUTRAL = ['calendly.com', 'cal.com', 'savvycal.com', 'hubspot.com', 'notion.so', 'notion.site',
  'docs.google.com', 'drive.google.com', 'typeform.com', 'airtable.com', 'lu.ma', 'eventbrite.com'];

/**
 * readAsk — derive the ask flags from the raw message, so the tool works on what actually ARRIVES.
 *
 * Until now vetApproach took booleans: the caller had to have already decided that the message asks you to
 * install something. That is the hard part, and leaving it to the caller made this a checklist rather than a
 * check — fine for a careful human, useless to an agent handed a raw email. Worse, the rule "a real podcast
 * records in your browser" was PRINTED in the output while nothing in the code applied it.
 *
 * Composition is fail-closed by construction: this can only ever ADD a flag. An explicit boolean from the
 * caller always wins, and a quiet text scan can never talk one down — text detection is a heuristic and must
 * not be able to clear anything.
 */
const ASK_PATTERNS = {
  install: /(\binstall\b|\bdownload\b|\.exe\b|\.msi\b|\.apk\b|\.dmg\b|\bsetup\s+file\b|\brun\s+(?:the\s+)?(?:file|installer|setup|attachment)\b|\bunzip\s+and\s+run\b)/i,
  keyOrSeed: /(private[\s_-]?key|seed[\s_-]?phrase|\bmnemonic\b|keystore|\bpassphrase\b|recovery[\s_-]?phrase|connect\s+your\s+wallet|\bimport\s+your\s+wallet\b)/i,
  signature: /(\bsign\s+(?:this|the|a)\s+(?:message|transaction|tx|request)\b|signature\s+(?:is\s+)?required|\bverify\s+your\s+wallet\b|\bsign\s+to\s+(?:verify|confirm|prove)\b)/i,
  upfrontPayment: /(\bupfront\b|\bup[\s-]front\b|\bin\s+advance\b|processing\s+fee|\bretainer\b|\bdeposit\s+(?:of|first)\b|before\s+we\s+(?:can\s+)?(?:release|send|deliver|publish))/i,
  urgency: /(\bwithin\s+\d+\s+(?:hour|minute|day)s?\b|\btoday\s+only\b|\blast\s+chance\b|\bslot\s+(?:closes|expires)\b|\bwe\s+go\s+live\b|\basap\b|\bwaiting\s+on\s+you\b)/i,
  // Moving the conversation into a chat app to RECEIVE something. Deliberately not fatal on its own: "join our
  // Telegram" is ordinary in this industry and flagging it alone would fire on half of all legitimate contact.
  // The tell is a media or production context that needs you to leave it to collect a file.
  moveToApp: /\b(?:join|hop\s+on|add\s+(?:me|us)\s+on|move\s+(?:this\s+)?to)\b[^.!?\n]{0,40}\b(wechat|whatsapp|telegram|skype|discord|line|kakao|signal|qq)\b/i,
};

function readAsk(text) {
  const t = String(text || '');
  const hit = {};
  for (const [k, re] of Object.entries(ASK_PATTERNS)) hit[k] = re.test(t);
  return hit;
}

/**
 * checkLink — does this URL point where it appears to point?
 * @returns { ok, url, hostname, registrable, impersonates, browserNative, verdict, reason }
 */
function checkLink(url) {
  let u;
  try { u = new URL(String(url).trim()); } catch { return { ok: false, verdict: 'unreadable', reason: 'not a parseable URL' }; }
  const host = u.hostname.toLowerCase();
  const reg = registrableDomain(host);
  const prefixLabels = host.slice(0, Math.max(0, host.length - reg.length)).split('.').filter(Boolean);

  // A brand to the LEFT of the registrable domain is impersonation ONLY when that domain is not one the
  // brand actually owns. `meet.google.com` and `teams.microsoft.com` are the products themselves.
  const impersonates = Object.keys(IMPERSONATED).filter((b) =>
    prefixLabels.some((l) => l === b || l.includes(b)) &&
    !IMPERSONATED[b].some((owned) => reg === owned || reg.endsWith('.' + owned)) &&
    !reg.startsWith(b + '.'));

  const browserNative = BROWSER_NATIVE.some((d) => reg === d || host === d || host.endsWith('.' + d));

  if (impersonates.length) return { ok: true, url, hostname: host, registrable: reg, impersonates, browserNative: false,
    verdict: 'brand_impersonation',
    reason: 'This link is NOT ' + impersonates[0] + '. The domain that was actually registered is "' + reg +
      '", and "' + impersonates[0] + '" is only a label its owner added for free. Anyone can put any brand name to the left of a domain they control.' };

  if (browserNative) return { ok: true, url, hostname: host, registrable: reg, impersonates: [], browserNative: true,
    verdict: 'browser_native', reason: 'Recognised browser-based platform (' + reg + ') — nothing to install.' };

  // Real service, and that is not a finding either way. Checked AFTER impersonation and browser-native, so
  // neither of those answers can shift for this: a link claiming to be Calendly while pointing somewhere else
  // is still impersonation, and this branch never sees it.
  if (LEGIT_NEUTRAL.some((d) => reg === d || host === d || host.endsWith('.' + d))) {
    return { ok: true, url, hostname: host, registrable: reg, impersonates: [], browserNative: false,
      verdict: 'recognised_neutral',
      reason: 'Domain "' + reg + '" is a real service, and that proves nothing: anyone can open an account on ' +
        'it in a minute. In the approach this module was written from, the scheduling link was GENUINE. ' +
        'Legitimate infrastructure is the cover, not the tell — so this is neither a flag nor a comfort.' };
  }

  return { ok: true, url, hostname: host, registrable: reg, impersonates: [], browserNative: false,
    verdict: 'unrecognised', reason: 'Domain "' + reg + '" is not a platform this recognises. That is not an accusation — but combined with any request to install something, treat it as the answer.' };
}

/**
 * vetApproach — judge an inbound approach (podcast, interview, partnership, job, AMA) by its ask.
 * @param {object} opts
 *   links[]              - every URL in the message
 *   platform             - the platform they named, if any
 *   asksToInstall        - do they require installing or downloading anything?
 *   asksForKeyOrSeed     - any request for a key, seed, keystore, or wallet connection
 *   asksForSignature     - any request to sign a message or transaction
 *   asksForUpfrontPayment- any fee before delivery
 *   urgency              - was there time pressure (a "you're late" nudge, a closing window)?
 * @returns { verdict, reason, fatal[], links[], rules, disclosure }
 *   verdict: 'fraud' | 'high_risk' | 'unverified'
 */
function vetApproach({ links = [], platform, message, asksToInstall, asksForKeyOrSeed, asksForSignature,
  asksForUpfrontPayment, urgency } = {}) {
  const linkChecks = (Array.isArray(links) ? links : [links]).filter(Boolean).map(checkLink);
  const impersonating = linkChecks.filter((l) => l.verdict === 'brand_impersonation');

  // Read the message if one was handed over, then OR it into whatever the caller already decided. Only ever
  // OR: an explicit `false` from a caller who looked must not be overridden, and a text scan that found
  // nothing must never be able to clear a flag someone set deliberately. Heuristics may accuse, never acquit.
  const read = message ? readAsk(message) : null;
  const asked = {
    install: asksToInstall === true || !!(read && read.install),
    keyOrSeed: asksForKeyOrSeed === true || !!(read && read.keyOrSeed),
    signature: asksForSignature === true || !!(read && read.signature),
    upfrontPayment: asksForUpfrontPayment === true || !!(read && read.upfrontPayment),
    urgency: urgency === true || !!(read && read.urgency),
  };

  const fatal = [];
  if (impersonating.length) fatal.push('A link impersonates ' + impersonating[0].impersonates[0] +
    ' by name while pointing at "' + impersonating[0].registrable + '". That is not a mistake anyone makes by accident.');
  if (asked.keyOrSeed) fatal.push('They want a key, seed or wallet connection. Nothing legitimate needs that to talk to you.');
  if (asked.install) fatal.push('They want you to install something. A real recording session runs in your browser; a real interviewer has no reason to put software on your machine.');
  if (asked.signature) fatal.push('They want a signature. A signature authorises an outgoing transfer — there is no version of an interview or partnership that needs one.');
  if (asked.upfrontPayment) fatal.push('They want money before delivering anything.');

  const flags = [];
  if (platform && !BROWSER_NATIVE.some((d) => String(platform).toLowerCase().includes(d.split('.')[0]))) {
    flags.push('The named platform ("' + platform + '") is not one of the browser-based tools productions actually record on.');
  }
  if (asked.urgency) flags.push('Time pressure was applied. Urgency exists to remove the pause in which you would have checked something.');
  if (linkChecks.some((l) => l.verdict === 'unrecognised')) flags.push('A link points at a domain that is not a recognised platform.');
  if (read && read.moveToApp) flags.push('They want the conversation moved into a chat app to hand you something. ' +
    'On its own that is ordinary in this industry — a production that needs you to leave its own platform to collect a file is not.');

  const verdict = fatal.length ? 'fraud' : flags.length >= 2 ? 'high_risk' : 'unverified';

  // The headline is chosen, not inherited from push order. On the real approach this module was written from,
  // `flags[0]` surfaced "a link points at a domain that is not a recognised platform" — true, generic, and the
  // weaker of the two findings — while the specific one, that they wanted the conversation moved into a chat
  // app to hand over a file, sat underneath it. Both were reported; only one is worth acting on. A security
  // tool's first line is what the reader acts on, so the most SPECIFIC flag leads and the generic ones fall
  // back. Everything still appears in `flags`; this only decides which one gets said first.
  const headline = (list) => {
    const rank = (f) => (/chat app/.test(f) ? 0 : /Time pressure/.test(f) ? 1 : /named platform/.test(f) ? 2 : 3);
    return [...list].sort((a, b) => rank(a) - rank(b))[0];
  };

  return { verdict, fatal, flags, links: linkChecks,
    reason: fatal.length ? fatal[0]
      : flags.length ? headline(flags)
      : 'Nothing fatal was reported and no link impersonates a platform. This is NOT a clearance — it only means the two things a forger cannot hide came back clean.',
    rules: [
      'Judge the ask, not the approach. Research, detail, professionalism and polish are all cheap to generate now — grading them just launders a forgery.',
      'Effort is no longer evidence. A 35-question production dossier used to cost hours of human work; it now takes minutes from a public profile, and the instinct that priced effort as sincerity has not caught up.',
      'Hard questions are not proof of independence. Including criticism is what makes an approach read as journalism rather than marketing — which is exactly why a good forgery includes it.',
      'A real podcast records in your browser. A real security team never wants a key. A real recovery never needs your signature.',
      'One wrong note in an otherwise flawless approach is the whole finding. A near-perfect signal is what lets the single anomaly get smoothed over.',
    ],
    disclosure: 'This never returns "safe". It deliberately does not score how convincing an approach is, because convincingness is now manufacturable and scoring it would give a forgery a good grade. It grades only the domain a link truly points at and what the sender wants you to do.' };
}

module.exports = { vetApproach, checkLink, registrableDomain, readAsk, ASK_PATTERNS, LEGIT_NEUTRAL, IMPERSONATED, BROWSER_NATIVE };
