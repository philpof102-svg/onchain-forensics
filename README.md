# onchain-forensics

Seven checks you run before you pay, and after you've been robbed. Exposed as an MCP server so an agent can
call them, and as plain modules so you can call them yourself.

No API keys. No accounts. Every source is a public endpoint. Read-only throughout — nothing here can move
funds, and none of it will ever ask you for one.

## Why this exists

It was written in one sitting, while tracing a real theft. Someone's wallet was drained on Base; the trail
went through a DEX, a bridge, and out to TRON. Each tool here answers a question that came up during that
trace, and each one was kept only after it reproduced a fact already established by hand.

That origin matters more than the feature list. **Where a check turned out to be wrong, the fix and the
reason it was wrong are written into the module.** Those comments are the useful part of this repository —
they are the difference between a scanner that sounds confident and one you can act on.

Three examples, all real, all caught by testing against known answers:

- The bridge exit carried `0x2b6653dc`, which reads as a perfectly plausible token amount. It is chain id
  728126428 — TRON mainnet. Reading it as a quantity produced a **confident wrong answer**, which is the
  worst output a forensic tool can give.
- A one-byte chain id matched inside calldata padding and reported Optimism on a transaction that went to
  TRON. Ids under two bytes are now returned separately as unusable rather than as evidence.
- The curated security index reports `holder_count: 0` on a freshly indexed token, meaning "not computed
  yet" rather than "no holders". Read literally, it stamps a warning on every new launch — which is exactly
  the noise that makes people stop reading warnings.

## The tools

| Tool | The question |
|---|---|
| `vet_meme` | Which contract is the real one behind this ticker? |
| `rug_powers` | What powers does the deployer still hold over my money? |
| `b20_authentic` | Real Base-native asset, or an ERC-20 wearing its address prefix? |
| `launch_funder` | Who paid for this launch, and what else did they pay for? |
| `trace_theft` | Where did the stolen funds go? |
| `recovery_offer` | Is this offer to get my money back the second theft? |
| `vet_approach` | Is this inbound opportunity a lure? |

### The two ideas worth stealing from this repo

**A dangerous capability only counts if someone can still fire it.** `is_mintable` with ownership renounced
is inert; the same flag with a live owner is an armed rug. Scanners that list flags without that distinction
produce noise, and noise gets ignored, and ignored warnings are the same as no warnings. Proven on a live
token: BRETT reports a modifiable tax and unlocked LP, and is not a rug, because nobody can fire either.

**An event is not a transaction.** ERC-20 `Transfer` logs are strings the emitting contract chooses. Spam
contracts routinely emit transfers naming addresses that never signed anything — during the trace this came
from, a bot forged a fake transfer four minutes after the real theft, using a token named `EṬH` (a Unicode
homoglyph) and an address engineered to look like the victim's. Any tool that reads "transfers where
from = target" straight from an indexer will report movements that never happened. Check the signer.

### On `vet_approach`, and why it refuses to grade how convincing something is

The lure that started this repository was not phishing in any recognisable sense. It was a 35-question
production dossier across six chapters, with per-chapter shot lists, citing the target's real scoring model
and settlement rails, using his own catchphrase back at him, and quoting his posts verbatim.

It also asked genuinely hard questions — whether one score creates false certainty, whether the oracle
profits from generating fear. **That was the payload, not the praise.** A flatterer never includes criticism,
so including it is exactly what flips an approach from marketing into journalism in the reader's head.

The mechanism underneath is **effort as a trust signal**. Producing that much researched detail used to cost
hours of human work, so nobody spent it to scam one person, and every reader's instinct silently priced that
in. The arithmetic held for decades. It does not hold now — the same document generates in minutes from a
public profile — and nobody updated their instincts.

So this tool deliberately does not score how convincing an approach is. Convincingness is manufacturable, and
grading it would hand a forgery a good mark. It grades the two things a forger cannot make harmless: **where
a link actually points**, and **what the sender wants you to do**. A brand name to the left of the
registrable domain is a free label — `wechat.web09eu.com` is `web09eu.com`.

The false-positive test earned its keep on the first run: a version keyed on brand names alone flagged
`meet.google.com` — Google Meet, the real one — as impersonation. A tool that warns about Google Meet is a
tool people uninstall.

### On `recovery_offer`

This is the only tool here that can answer with certainty rather than a score, and it is the one most likely
to matter to someone reading this after a bad day.

Recovering stolen funds happens through the thief returning them, or a court, an exchange, or a token issuer
freezing and reassigning them. **None of those routes require anything from the victim's wallet.** So a
recovery that needs your signature or an upfront fee is not merely suspicious — it is structurally impossible
as described. That holds no matter how credible the person sounds, and no matter how accurately they recite
your loss back to you: the theft is public, and reciting it proves nothing.

The tool never returns "safe".

## Install

```bash
git clone https://github.com/philpof102-svg/onchain-forensics
cd onchain-forensics
```

No dependencies to install — it uses only the Node standard library.

### As an MCP server

```bash
claude mcp add onchain-forensics -- node /absolute/path/to/onchain-forensics/bin/onchain-forensics-mcp.js
```

Or in any MCP client's config:

```json
{
  "mcpServers": {
    "onchain-forensics": {
      "command": "node",
      "args": ["/absolute/path/to/onchain-forensics/bin/onchain-forensics-mcp.js"]
    }
  }
}
```

### As modules

```js
const { scanRugOne } = require('./lib/rugsignals');
const { classifyB20 } = require('./lib/b20');
const { followTron } = require('./lib/trace');

const v = await scanRugOne('base', '0x...');
console.log(v.verdict, v.reason);   // rug_ready | high_risk | caution | clean | unknown
```

## Data sources

Blockscout (EVM chains) · TronGrid (TRON) · DexScreener (liquidity) · GoPlus (contract security) ·
honeypot.is (live trade simulation). All keyless, all public, all rate-limited — the code throttles and caps
its own crawls, because being rude to a free endpoint is how everyone loses access to it.

## What this does not do

It reports **structure**, never identity or intent. A shared funder proves shared control or shared
infrastructure; a launchpad and a rug factory are indistinguishable from the graph alone. An amount-matched
forward proves a pass-through; it says nothing about who holds the keys.

Every verdict is a pointer to the chain, not a badge. Re-verify.

## Licence

MIT.
