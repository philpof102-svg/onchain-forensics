'use strict';
/** Every check in one place, for callers who want the modules rather than the MCP server. */
module.exports = {
  ...require('./meme'),        // vetMeme, candidatesFrom
  ...require('./rugsignals'),  // scanRug, scanRugOne, assessRugFields
  ...require('./b20'),         // classifyB20
  ...require('./feeder'),      // traceFeeder
  ...require('./trace'),       // whatMoved, readBridgeExit, followTron, hexToTron, tronToHex
  ...require('./recovery'),    // assessRecoveryOffer, HARD_RULES
  ...require('./lure'),        // vetApproach, checkLink, registrableDomain
  ...require('./approvals'),   // checkApprovals, liveAllowance
  ...require('./multicall'),   // multiCall, allowancesBatch
  ...require('./wallet-watch'),// watchWallet
};
