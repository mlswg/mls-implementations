// Convert a transcript of an active test to a passive client test vector file
//
// Usage: node active_to_passive.js config.json trasncript.json >test-vector.json
//
// The file <config.json> should be in the format taken as input by `test-runner`.
// The file <transcript.json> should be in the format output by `test-runner`.
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

// Load the required files
const configFile = fs.readFileSync(process.argv[2]);
const transcriptFile = fs.readFileSync(process.argv[3]);

const config = JSON.parse(configFile);
const transcript = JSON.parse(transcriptFile);

// Translate the test cases
const passiveTests = [];
for (let scriptName in config.scripts) {
  if (!transcript.scripts[scriptName]) {
    console.error(`Unknown script name "${scriptName}"`);
    continue;
  }

  // Identify the actors that join via Welcome
  const steps = config.scripts[scriptName];
  const passiveActors = steps.filter(step => step.action == "fullCommit" && step.joiners)
                             .map(step => step.joiners)
                             .reduce((a, b) => a.concat(b));

  // Construct test cases from passive vantage points
  for (let testCase of transcript.scripts[scriptName]) {
    for (let actor of passiveActors) {
      let passiveTest = activeToPassive(steps, testCase, actor);
      if (!passiveTest) {
        continue;
      }

      passiveTests.push(passiveTest);
    }
  }
}

console.log(JSON.stringify(passiveTests, null, 2));

//////// Translation Logic //////////

function activeToPassive(rawSteps, testCase, actor) {
  // Identify where in the transcript we should look for relevant data
  const steps = rawSteps.map((step, i) => { step.transcriptIndex = i; return step; });
  const kp_steps = steps.filter(step => step.action == "createKeyPackage" && step.actor == actor);
  const join_steps = steps.filter(step => step.action == "fullCommit" && step.joiners && step.joiners.includes(actor));
  const commit_steps = steps.filter(step => step.action == "fullCommit" && step.members && step.members.includes(actor));

  if (kp_steps.length == 0 || join_steps.length == 0) {
    console.warn("Actor did not join via Welcome", actor);
    return;
  }
  
  // Grab private data
  const passiveTest = {
    cipher_suite: testCase.cipher_suite,
  };
  const transcript = testCase.transcript;
  
  // Grab private state from createKeyPackage step in transcript
  const kpTranscript = transcript[kp_steps[0].transcriptIndex];
  passiveTest.key_package = kpTranscript.key_package;
  passiveTest.init_priv = kpTranscript.init_priv;
  passiveTest.encryption_priv = kpTranscript.encryption_priv;
  passiveTest.signature_priv = kpTranscript.signature_priv;
  
  // Grab welcome and epoch authenticator from joinGroup
  const commitTranscript = transcript[join_steps[0].transcriptIndex];
  passiveTest.welcome = commitTranscript.welcome;
  passiveTest.initial_epoch_authenticator = commitTranscript.epoch_authenticator;
  
  // TODO Enable provisioning these fields
  passiveTest.external_psks = [];
  passiveTest.ratchet_tree = null;

  // Grab Commits 
  passiveTest.epochs = [];
  for (let step of commit_steps) {
    const commitTranscript = transcript[step.transcriptIndex];
    const proposals = step.byReference.map(i => transcript[i].proposal);

    passiveTest.epochs.push({
      proposals,
      commit: commitTranscript.commit,
      epoch_authenticator: commitTranscript.epoch_authenticator,
    });
  }

  return passiveTest;
}
