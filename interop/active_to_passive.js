// Inputs: 
// * config.json
// * transcript.json
// * test name => steps, testCase
// * actor name
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
  const passiveActors = steps.filter(step => step.action == "joinGroup")
                             .map(step => step.actor);

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

function activeToPassive(steps, testCase, actor) {
  // Identify where in the transcript we should look for relevant data
  const my_steps = steps.map((step, i) => { step.transcriptIndex = i; return step; })
                        .filter(step => step.actor == actor);
  
  if (my_steps.length == 0) {
    console.warn("Unknown actor");
    return;
  }
  
  if (my_steps[0].action != "createKeyPackage" || 
      my_steps[1].action != "joinGroup") {
    console.warn("Actor did not join via Welcome");
    return;
  }
  
  // Grab private data
  const passiveTest = {
    cipher_suite: testCase.cipher_suite, // from transcript
  };
  const transcript = testCase.transcript;
  
  // Grab private state from createKeyPackage step in transcript
  const kpTranscript = transcript[my_steps[0].transcriptIndex];
  passiveTest.key_package = kpTranscript.key_package;
  passiveTest.init_priv = kpTranscript.init_priv;
  passiveTest.encryption_priv = kpTranscript.encryption_priv;
  passiveTest.signature_priv = kpTranscript.signature_priv;
  
  // Grab welcome and epoch authenticator from joinGroup
  const welcomeStep = my_steps[1];
  const commitTranscript = transcript[welcomeStep.welcome];
  passiveTest.welcome = commitTranscript.welcome;
  passiveTest.initial_epoch_authenticator = commitTranscript.epoch_authenticator;
  
  // TODO Enable provisioning these fields
  passiveTest.external_psks = [];
  passiveTest.ratchet_tree = null;

  // Grab Commits 
  passiveTest.epochs = [];
  for (let i = 2; i < my_steps.length; i++) {
    const step = my_steps[i];
    const skipActions = ["unprotect"];
    if (skipActions.includes(step.action)) {
      continue;
    }
  
    if (step.action != "handleCommit") {
      // Stop if this member does anything active
      console.info("stopping bc", step.action);
      break;
    }

    const commitTranscript = transcript[step.commit];
    const proposals = step.byReference.map(i => transcript[i].proposal);

    passiveTest.epochs.push({
      proposals,
      commit: commitTranscript.commit,
      epoch_authenticator: commitTranscript.epoch_authenticator,
    });
  }

  return passiveTest;
}
