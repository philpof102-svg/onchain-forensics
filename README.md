# onchain-forensics

Ten checks you run before you pay, and after you've been robbed. Exposed as an MCP server so an agent can
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
| `open_approvals` | Which doors into my wallet are still open? |
| `watch_wallet` | What **changed** around this wallet since we last looked? |
| `vet_agent` | Is this agent safe to connect to, and safe to pay? |

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

### A correction, kept because it is the most useful thing here

An earlier version of this README and of `rugsignals.js` claimed that the rugs observed while building
this all died by liquidity withdrawal, and that the unlocked-LP flag had already been printed on each
verdict. That was checked against the stored evidence and it is false. Not one of the eight rugs carried
that flag. Seven carried a single flag and it was the holder count; the eighth had no data at all. The
unlocked-pool flag appeared on tokens that **survived**.

The claim had been generalised from two examples that fit the story and neither of which rugged. It was
plausible, mechanically sound, and wrong — which is exactly the shape of the errors this repository is
meant to catch, so it stays documented rather than quietly edited away.

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

### On `open_approvals`, and the all-clear it fabricated in its own first draft

An ERC-20 approval is a standing permission to move your tokens without asking again. It is the most common
drain route that does **not** need your private key: approved once for an unlimited amount, months ago, to a
contract you no longer remember. Wallets do not surface these.

The load-bearing rule is that **an `Approval` event is not the current state.** A later approval of zero
revokes an earlier one and emits its own event; reading the log gives you a list of doors that may or may not
still be open. So the log is used only to collect candidate `(token, spender)` pairs, and every pair is then
confirmed by calling `allowance()` on the chain right now.

My first draft of this counted a failed RPC call as a revoked approval. It reported **forty closed doors
having actually verified nine** — a fabricated all-clear, on the one tool whose entire job is telling you
what is still open. I had documented that exact fault in someone else's scanner an hour earlier.

The fix is four outcomes rather than two: `live`, `confirmed-revoked`, `not-applicable` (the call reverted,
which is a definitive answer), and `could-not-check`. That last state is the whole point — an unanswered call
is not a closed door, and the tool now says so and reports `complete: false`.

Then the unread count was driven to zero for real, by batching every `allowance()` into one `aggregate3`
call through Multicall3 — one request instead of dozens, so the rate limiting that caused the unread calls
stops happening. Verified against a live wallet: 11 unread became 0.

### On `watch_wallet`, and why a monitor that repeats itself is worth nothing

Every other tool here answers at a point in time. This one remembers, which is what turns them into a guard.

Three unlimited approvals granted last year are a **standing condition**. A fourth appearing this morning is
an **event**. Only the second deserves to interrupt anyone — a monitor that re-reports its standing
conditions every hour trains its reader to close it, and a closed monitor catches nothing. So state is
persisted per address and the output is a diff.

It also **judges** each new counterparty instead of merely announcing it, because detecting and then
declining to think is half a product. And it reports its own blind spots on every run: on a wallet monitor,
an empty alert list reads as *"you are safe"*, so a check that could not run has to say so out loud.

### On `vet_agent`, and why it will not grade a tool description

Agents now call other agents and pay them. Four dangers are checkable without trusting a word of the listing:
it does not exist; its tools can move money; it asks for key material; or it is paid to an address with no
past.

The discipline that made this work is that **a name is marketing, the input schema is the capability.** A
tool called `helpful_assistant` with an `amount` field and a `to` field is a payment tool. And only a
**quantity** field proves a payment surface — a message has a recipient exactly as a payment does, but you
cannot move value without saying how much. Keying on recipients alone flagged our own messaging tool.

Two bugs worth repeating because both produced silent passes. A word-boundary regex (`\bsend\b`) matched
**none** of nine `snake_case` tool names, because an underscore is a word character — `wallet_transfer` never
matches `\btransfer\b`. And an HTTP 401 was first classified as *unreachable*, when it means the opposite: the
agent is running and gated. That is `unauditable` — neither a pass nor a fail.

It deliberately does not score how good the description reads, for the same reason `vet_approach` does not:
a well-written tool listing is free to fabricate, and grading prose hands a forgery a good mark.

### The publish gate, and a test that passed while the server was dead

`npm test` runs `test/publishable.js`, which refuses to call this repo publishable unless every relative
`require` resolves to a file that is here, `lib/index.js` exports every entry point, and the MCP server boots
over real stdio and lists all ten tools with usable schemas.

It exists because of one specific failure. `lib/wallet-watch.js` was copied in from the private repo it was
written in, carrying `require('./screen')` for a file that never came with it. The whole server then died on
load — every tool gone, not just that one. **The smoke test I had run passed**, because I ran it *before*
adding that dependency and then copied the changed file over without re-running it.

A stale test feels exactly like a passing one. That is why the correction here is a gate and not a resolution
to be more careful. The gate's rule is asymmetric on purpose: a require may resolve to nothing **only** if
the line says `optional-require`, so an absence has to be claimed in the source to be tolerated and silence
means broken. And a marker that claims optional while sitting outside a `try` is reported as a lie, because a
marker nobody verifies is just a comment. Both failure modes were reproduced deliberately to confirm the gate
catches them.

## Install

```bash
git clone https://github.com/philpof102-svg/onchain-forensics
cd onchain-forensics
```

No dependencies to install — it uses only the Node standard library. To check the clone is intact:

```bash
npm test
```

That boots the server and verifies all ten tools list, so a broken copy fails here rather than in your client.

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
