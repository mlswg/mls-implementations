#!/bin/bash

# Convert all active test scripts to passive client tests
#
# This script runs each of the configurations in `configs` against a single
# client, collects the RPC transcript, and then uses the `active_to_passive.js`
# script to convert the RPC transcript to a collection of passive client tests.
#
# XXX(RLB): Right now, `deep_random.json` is omitted because the output it
# produces is too large.

CLIENT_HOST=localhost
CLIENT_PORT=50001
CONFIG_DIR=configs
PASSIVE_DIR=passive

RESULTS_DIR=`mktemp -d`

for name in `ls ${CONFIG_DIR}/*.json | grep -v deep | sed -e "s/${CONFIG_DIR}\///"`
do
  echo ${name}

  # Run the live test and collect the RPC transcript
  ./test-runner/test-runner -client ${CLIENT_HOST}:${CLIENT_PORT} \
                            -config ${CONFIG_DIR}/${name} \
                            >${RESULTS_DIR}/${name}

  # Convert the RPC transcript to passive client tests
  node active_to_passive.js <${RESULTS_DIR}/${name} >${PASSIVE_DIR}/${name}
done
