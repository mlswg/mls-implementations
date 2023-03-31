// Convert a transcript of an active test to a passive client test vector file
//
// Usage: node active_to_passive.js <results.json >test-vector.json
//
// The file <results.json> should be in the format output by `test-runner`.
// The resulting test vector file is written to stdout.
//
// For each test case (combination of clients / encryption / ciphersuite), and
// for each client that joins via Welcome in that test case, the script emits a
// passive test vector that covers:
// 
// 1. The Welcome that adds the client to the group
// 2. Further commits that the client is instructed to handle in the test script
// 3. ... until the first time the client emits a message (since it is no longer passive)

const fs = require('fs');

// Load the live test results from stdin
const resultsFile = fs.readFileSync(0, "utf-8");
const results = JSON.parse(resultsFile);

// Translate the test cases
const passiveTests = [];
for (const scriptName in results.scripts) {
  for (const testCase of results.scripts[scriptName]) {
    // Identify the actors that join via Welcome
    const rpcs = testCase.transcript;
    const passiveActors = rpcs.filter(rpc => rpc.rpc == "JoinGroup")
                              .map(rpc => rpc.actor);

    // Construct a passive test from each vantage point
    for (const actor of passiveActors) {
      const passiveTest = activeToPassive(testCase.cipher_suite, actor, rpcs);
      if (!passiveTest) {
        continue;
      }

      passiveTests.push(passiveTest);
    }
  }
}

console.log(JSON.stringify(passiveTests, null, 2));

//////// Translation Logic //////////

function base64ToHex(b64) {
  return Buffer.from(b64, "base64").toString("hex");
}

function activeToPassive(cipher_suite, actor, allRPCs) {
  let rpcs = allRPCs.filter(rpc => rpc.actor == actor);

  // Filter out PSK RPCs
  const storePSKRPCs = rpcs.filter(rpc => rpc.rpc == "StorePSK");
  rpcs = rpcs.filter(rpc => rpc.rpc != "StorePSK");

  // We require the following sequence:
  // * CreateKeyPackage
  // * JoinGroup
  // * [HandleCommit | InstallExternalPSK]*
  if (rpcs[0].rpc != "CreateKeyPackage" || rpcs[1].rpc != "JoinGroup") {
    // TODO(RLB) Add support for NewMemberAddProposal
    if (rpcs[0].rpc == "NewMemberAddProposal") {
      return;
    }

    throw "Invalid passive member";
  }

  const end = rpcs.slice(2).find(rpc => rpc.rpc != "HandleCommit");
  const handleCommitRPCs = rpcs.slice(2).slice(0, end);

  // Grab private data from the CreateKeyPackage response
  const passiveTest = { cipher_suite };
  passiveTest.key_package = base64ToHex(rpcs[0].response.key_package);
  passiveTest.init_priv = base64ToHex(rpcs[0].response.init_priv);
  passiveTest.encryption_priv = base64ToHex(rpcs[0].response.encryption_priv);
  passiveTest.signature_priv = base64ToHex(rpcs[0].response.signature_priv);

  // Grab welcome, ratchet tree and initial epoch authenticator from the
  // JoinGroup request
  passiveTest.welcome = base64ToHex(rpcs[1].request.welcome);

  passiveTest.ratchet_tree = null;
  if (rpcs[1].request.ratchet_tree) {
    passiveTest.ratchet_tree = base64ToHex(rpcs[1].request.ratchet_tree);
  }

  passiveTest.initial_epoch_authenticator = base64ToHex(rpcs[1].response.epoch_authenticator);

  // Install any required external PSKs
  passiveTest.external_psks = storePSKRPCs.map(rpc => {
    return {
      psk_id: base64ToHex(rpc.request.psk_id),
      psk: base64ToHex(rpc.request.psk_secret),
    };
  });

  // Handle commits
  passiveTest.epochs = handleCommitRPCs.map(rpc => {
    const epoch = {
      commit: base64ToHex(rpc.request.commit),
      epoch_authenticator: base64ToHex(rpc.response.epoch_authenticator),
    };

    epoch.proposals = [];
    if (rpc.request.proposal) {
      epoch.proposals = rpc.request.proposal.map(base64ToHex);
    }

    return epoch;
  });

  return passiveTest;
}
