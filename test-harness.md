MLS Interop Test Harness Specification
======================================

To automate interoperability testing across multiple MLS implementations, we
need to be able to have a test runner control multiple clients, on different
platforms and written in different languages. The interface to the MLS clients
needs to cover all of the protocol operations for which we want to test interop,
and expose enough information to evaluate whether interop succeeded.

At a logical level, the necessary operations are all basically RPCs from the
test runner to the clients.  First we describe the RPCs, then we discuss some
ways these RPCs could be implemented.

## Test Harness RPCs

Ways to become a member of a group ("encrypt flag" indicates whether handshake
messages in the group are encrypted):

* Create a new group
  * Inputs: Group ID, ciphersuite, credential, signature private key, encrypt
    flag 
  * Outputs: Pointer to new state
* Create a new KeyPackage to begin a join
  * Inputs: ciphersuite, credential, signature private key
  * Outputs: KeyPackage, callback to which Welcome should be sent
* Complete joining a group (Welcome callback)
  * Inputs: Welcome, encrypt flag
  * Outputs: Pointer to new state
* External join
  * Inputs: PublicGroupState, encrypt flag
  * Outputs: MLSPlaintext(Commit), Welcome, pointer to new state

Operations using a group state:

* Get state auth
  * Inputs: (none)
  * Outputs: authentication_secret
* Export a secret
  * Inputs: label, context
  * Outputs: exported_value

* Protect an application message
  * Inputs: Application data
  * Outputs: MLSCiphertext(ApplicationData)
* Unprotect an application message
  * Inputs: MLSCiphertext(ApplicationData)
  * Outputs: Application data

* Generate an add proposal
  * Inputs: KeyPackage
  * Outputs: MLSPlaintext(Proposal(Add))
* Generate an update proposal
  * Inputs: (none)
  * Outputs: MLSPlaintext(Proposal(Update))
* Generate an remove proposal
  * Inputs: index
  * Outputs: MLSPlaintext(Proposal(Remove))
* Store an external PSK
  * Inputs: PSK ID, PSK value
  * Outputs: (none)
* Generate a PSK proposal
  * Inputs: PSK type, PSK ID (depending on type)
  * Outputs: MLSPlaintext(Proposal(PSK))
* Generate a ReInit proposal
  * Inputs: Group ID, ciphersuite
  * Outputs: MLSPlaintext(Proposal(ReInit))
* Generate an AppAck proposal for all messages processed in this epoch
  * Inputs: (none)
  * Outputs: MLSPlaintext(Proposal(AppAck))
* Generate a Commit message covering a set of proposals
  * Inputs: One or more MLSPlaintext(Proposal(\*))
  * Outputs: Zero or more MLSPlaintext(Proposal(\*)), MLSPlaintext(Commit)
  * Note: The committer chooses whether to inline any proposals, and returns the
    proposals not inlined.  If they commiter can't commit one or more of the
    proposals, it must return an error.

* Handle a collection of MLSPlaintexts and a Commit
  * Inputs: Zero or more MLSPlaintext(Proposal(\*)), MLSPlaintext(Commit)
  * Outputs: pointer to new state

## RPC Implementation Candidates

There are multiple technologies around for performing RPCs across mostly
independent software stacks.  The most obvious candidates are:

* Manually specified HTTP API
* HTTP API structured with something like [RAML](https://raml.org/) or
  [Swagger](https://swagger.io/)
* Using an RPC framework such as [gRPC](https://grpc.io/) or
  [Thrift](https://thrift.apache.org/)

All of these options allow implementations in multiple languages and on multiple
platforms.  Using a pre-provided RPC framework could simplify some RPC details,
but would require implementors to figure out how ti integrate that framework.
