#!/usr/bin/env node
'use strict';
/**
 * The truth table for reading an ask out of raw text, plus the two false positives this module keeps earning.
 *
 * Rows 1-3 are the REAL approach that this whole repository exists because of, replayed at three levels of
 * what the reader has in hand. It matters that they give three different answers: the email text alone does
 * not prove fraud, and a tool that cried fraud on it would be right by luck. The WeChat link is what proves it.
 *
 * The EVASION rows exist because a text scan is the easiest thing in here to walk past, and the FALSE POSITIVE
 * rows exist because this module has now produced two of them in real use — `meet.google.com` read as
 * impersonation, and `calendly.com` read as an unrecognised platform. Both would have got the tool muted, which
 * on a security tool is the same outcome as being wrong.
 */
const { vetApproach, readAsk, registrableDomain } = require('../lib/lure');

let failed = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'} ${label}\n`);
  if (!ok) process.stdout.write(`       expected ${want}, got ${got}\n`);
};

const REAL = 'Hi Clansy — BeaconLayer here. We would love to have you on the show to talk about your on-chain ' +
  'scoring model. Confirm a slot on our calendar and then join our WeChat room to receive the recording kit.';

process.stdout.write('the real approach, at three levels of evidence:\n');

// 1. The text alone. high_risk, not fraud — and that is the correct answer, not a miss.
check('text + site + calendly -> high_risk',
  vetApproach({ links: ['https://beaconlayer.co/', 'https://calendly.com/beaconlayer/interview'], message: REAL }).verdict,
  'high_risk');

// 2. The headline must be the SPECIFIC finding, not the generic one. This is what push order got wrong.
check('headline names the chat-app hand-off, not the unknown domain',
  /chat app/.test(vetApproach({ links: ['https://beaconlayer.co/'], message: REAL }).reason),
  true);

// 3. Add the link that actually delivered the payload. Now it is provable.
check('with the wechat.web09eu.com link -> fraud',
  vetApproach({ links: ['https://beaconlayer.co/', 'https://wechat.web09eu.com/'], message: REAL }).verdict,
  'fraud');

process.stdout.write('\nthe ask, read out of text:\n');
check('install language is fatal', vetApproach({ message: 'download and run the setup file' }).verdict, 'fraud');
check('seed request is fatal', vetApproach({ message: 'please share your recovery phrase to verify' }).verdict, 'fraud');
check('signature request is fatal', vetApproach({ message: 'just sign this message to confirm ownership' }).verdict, 'fraud');
check('upfront fee is fatal', vetApproach({ message: 'a processing fee is required in advance' }).verdict, 'fraud');

process.stdout.write('\nevasions and false positives:\n');

// EVASION — a text scan must never be able to CLEAR a flag the caller set deliberately. Silent text, explicit
// boolean: the boolean wins. If this ever flips, every caller who did the judging themselves is overridden.
check('EVASION: quiet text cannot clear an explicit flag',
  vetApproach({ message: 'looking forward to the interview', asksToInstall: true }).verdict, 'fraud');

// EVASION — the moveToApp pattern must not fire on an ordinary Telegram handle, which is half of this industry.
check('EVASION: bare "our telegram is @x" is not a hand-off',
  vetApproach({ message: 'our telegram is @beaconlayer if easier' }).flags.some((f) => /chat app/.test(f)), false);

// FALSE POSITIVE — the one already paid for once. Google Meet is Google Meet.
check('meet.google.com is not impersonation',
  vetApproach({ links: ['https://meet.google.com/abc-defg-hij'] }).links[0].verdict, 'browser_native');

// FALSE POSITIVE — and the one found by pointing this at the real attack. Calendly is real, and real proves
// nothing: in that approach the scheduling link was GENUINE. Neither a flag nor a comfort.
check('calendly.com is recognised_neutral, not unrecognised',
  vetApproach({ links: ['https://calendly.com/x/y'] }).links[0].verdict, 'recognised_neutral');

// A brand under a domain that does not own it is still impersonation, LEGIT_NEUTRAL or not.
check('calendly.evil.com is still impersonation',
  vetApproach({ links: ['https://calendly.evil.com/x'] }).links[0].verdict, 'brand_impersonation');

process.stdout.write('\nregistrableDomain accepts what callers actually pass:\n');
check('full URL', registrableDomain('https://beaconlayer.co/'), 'beaconlayer.co');
check('URL with path', registrableDomain('https://meet.google.com/abc-defg-hij'), 'google.com');
check('bare hostname', registrableDomain('wechat.web09eu.com'), 'web09eu.com');
check('two-part suffix', registrableDomain('https://sub.example.co.uk/path?q=1'), 'example.co.uk');
check('an email address', registrableDomain('info@beaconlayer.co'), 'beaconlayer.co');

process.stdout.write('\n' + (failed ? `${failed} case(s) failed\n` : 'all cases hold\n'));
process.exit(failed ? 1 : 0);
