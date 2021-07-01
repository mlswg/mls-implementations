# Test vectors

We use test vectors as a way of testing basic, deterministic functions of the
MLS stack.  Each test harness should have a way to produce and verify test
vectors of a few kinds.  In this document we specify the format for test vectors
and how they are verified.

The idea here is to test the cryptographic operations underlying MLS without the
complexity of the full protocol.  We tackle the overall cryptographic operation
in pieces:

```
                           epoch_secret
                                |
|\ Ratchet                      |                            Secret /|
| \ Tree                        |                             Tree / |
|  \                            |                                 /  |
|   \                           V                                /   |
|    --> commit_secret --> epoch_secret --> encryption_secret -->    |
|   /                           |                                \   |
|  /                            |                                 \  |
| /                             |                                  \ |
|/                              |                                   \|
                                V
                           epoch_secret

<-------------> <----------------------------------> <--------------->
    TreeKEM                KeySchedule                   Encryption
```

The `TreeMath` and `Messages` testvectors verify basic tree math operations and
the syntax of the messages used for MLS (independent of semantics).

### Representation

Test vectors are JSON serialized.  `optional<type>` is serialized as the value
itself or `null` if not present.  MLS structs are binary encoded according to
spec and represented as hex-encoded strings in JSON.

## Tree Math

Parameters:
* Number of leaves in the test tree

Format:

```
{
  "n_leaves": /* uint32 */,
  "n_nodes": /* uint32 */,
  "root": [ /* array of uint32 */ ],
  "left": [ /* array of optional<uint32> */ ],
  "right": [ /* array of optional<uint32> */ ],
  "parent": [ /* array of optional<uint32> */ ],
  "sibling": [ /* array of optional<uint32> */ ]
}
```

Verification:

* `n_nodes` is the number of nodes in the tree with `n_leaves` leaves
* `root[i]` is the root node index of the tree with `i+1` leaves
* `left[i]` is the node index of the left child of the node with index `i` in a
  tree with `n_leaves` leaves
* `right[i]` is the node index of the right child of the node with index `i` in
  a tree with `n_leaves` leaves
* `parent[i]` is the node index of the parent of the node with index `i` in a
  tree with `n_leaves` leaves
* `sibling[i]` is the node index of the sibling of the node with index `i` in a
  tree with `n_leaves` leaves

## Encryption

Parameters:
* Ciphersuite
* Number of leaves
* Number of generations

Format:

```text
{
  "result": /* "valid" or "invalid" */,
  "error": /* uint16 */,

  "cipher_suite": /* uint16 */,
  "n_leaves": /* uint32 */,
  "encryption_secret": /* hex-encoded binary data */,
  "sender_data_secret": /* hex-encoded binary data */,

  "sender_data_info": {
    "ciphertext": /* hex-encoded binary data */,
    "key": /* hex-encoded binary data */,
    "nonce": /* hex-encoded binary data */,
  },
  "leaves": [
    {
      "generations": /* uint32 */,
      "handshake": [ /* array with `generations` handshake keys and nonces */
        {
          "key": /* hex-encoded binary data */,
          "nonce": /* hex-encoded binary data */,
          "plaintext": /* hex-encoded binary data */
          "ciphertext": /* hex-encoded binary data */
        },
        ...
      ],
      "application": [ /* array with `generations` application keys and nonces */
        {
          "key": /* hex-encoded binary data */,
          "nonce": /* hex-encoded binary data */,
          "plaintext": /* hex-encoded binary data */
          "ciphertext": /* hex-encoded binary data */
        },
        ...
      ]
    }
  ]
}
```

Verification:

For all `N` entries in the `leaves` and all generations `j`
* `leaves[N].handshake[j].key = handshake_ratchet_key_[2*N]_[j]`
* `leaves[N].handshake[j].nonce = handshake_ratchet_nonce_[2*N]_[j]`
* `leaves[N].handshake[j].plaintext` represents an MLSPlaintext containing a
  handshake message (Proposal or Commit) from leaf `N`
* `leaves[N].handshake[j].ciphertext` represents an MLSCiphertext object that
  successfully decrypts to an MLSPlaintext equivalent to
  `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and generation
  `j`.
* `leaves[N].application[j].key = application_ratchet_key_[2*N]_[j]`
* `leaves[N].application[j].nonce = application_ratchet_nonce_[2*N]_[j]`
* `leaves[N].application[j].plaintext` represents an MLSPlaintext containing
  application data from leaf `N`
* `leaves[N].application[j].ciphertext` represents an MLSCiphertext object that
  successfully decrypts to an MLSPlaintext equivalent to
  `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and generation
  `j`.
* `sender_data_info.secret.key = sender_data_key(sender_data_secret, sender_data_info.ciphertext)`
* `sender_data_info.secret.nonce = sender_data_nonce(sender_data_secret, sender_data_info.ciphertext)`
* `error` codes:
  * 1 := MembershipTagMissing
  * 2 := UnexpectedMembershipTag
  * 3 := InvalidSenderData
  * 9 := ConfirmationTagMissing
  * 10 := UnexpectedConfirmationTag
  * 14 := MissingPath
  * 15 := InvalidPath

The extra factor of 2 in `2*N` ensures that only chains rooted at leaf nodes are
tested.  The definitions of `ratchet_key` and `ratchet_nonce` are in the
[Encryption
Keys](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#encryption-keys)
section of the specification.

Among other things, this test vector ensure the following spec requirements

> The membership_tag field in the MLSPlaintext object authenticates the sender's membership in the group. For an MLSPlaintext with a sender type other than member, this field MUST be omitted. For messages sent by members, it MUST be present

> The field confirmation_tag MUST be present if content_type equals commit. Otherwise, it MUST NOT be present.

> When parsing a SenderData struct as part of message decryption, the recipient MUST verify that the sender field represents an occupied leaf in the ratchet tree. In particular, the sender index value MUST be less than the number of leaves in the tree.

> The path field of a Commit message MUST be populated if the Commit covers at least one Update or Remove proposal. The path field MUST also be populated if the Commit covers no proposals at all (i.e., if the proposals vector is empty).

> If the path field is required based on the proposals that are in the commit (see above), then it MUST be populated.

## Key Schedule

Parameters:
* Ciphersuite
* Number of epochs

Format:

```text
{
  "cipher_suite": /* uint16 */,
  
  // Chosen by the generator
  "group_id": /* hex-encoded binary data */,
  "initial_init_secret": /* hex-encoded binary data */,

  "epochs": [
    {
      // Chosen by the generator
      "tree_hash": /* hex-encoded binary data */,
      "commit_secret": /* hex-encoded binary data */,
      "psk_secret": /* hex-encoded binary data */,
      "confirmed_transcript_hash": /* hex-encoded binary data */,
      
      // Computed values
      "group_context": /* hex-encoded binary data */,
      
      "joiner_secret": /* hex-encoded binary data */,
      "welcome_secret": /* hex-encoded binary data */,
      "init_secret": /* hex-encoded binary data */,
      
      "sender_data_secret": /* hex-encoded binary data */,
      "encryption_secret": /* hex-encoded binary data */,
      "exporter_secret": /* hex-encoded binary data */,
      "authentication_secret": /* hex-encoded binary data */,
      "external_secret": /* hex-encoded binary data */,
      "confirmation_key": /* hex-encoded binary data */,
      "membership_key": /* hex-encoded binary data */,
      "resumption_secret": /* hex-encoded binary data */,

      // A TLS-serialized HPKEPublicKey object
      "external_pub": /* hex-encoded binary data */
    },
    ...
  ]
}
```

Verification:
* Initialize the first key schedule epoch for the group [as defined in the
  specification](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#group-creation),
  using `group_id`, `initial_tree_hash`, and `initial_init_secret` for the
  non-constant values.
* For epoch `i`:
  * Construct a GroupContext with the following contents:
    * `group_id` as specified
    * `epoch = i`
    * `tree_hash` as specified
    * `confirmed_transcript_hash` as specified
    * `extensions = {}`
  * Verify that group context matches the provided `group_context` value
  * Verify that the key schedule outputs are as specified given the following
    inputs:
    * `init_key` from the prior epoch or `initial_init_secret`
    * `commit_secret` and `psk_secret` as specified
    * `GroupContext_[n]` as computed above

## Commits and Transcript Hashes

Parameters:
* Ciphersuite

Format:

```text
{
  "cipher_suite": /* uint16 */,

  // Chosen by the generator
  "group_id": /* hex-encoded binary data */,
  "epoch": /* uint64 */,
  "tree_hash_before": /* hex-encoded binary data */,
  "confirmed_transcript_hash_before": /* hex-encoded binary data */,
  "interim_transcript_hash_before": /* hex-encoded binary data */,

  "membership_key": /* hex-encoded binary data */,
  "confirmation_key": /* hex-encoded binary data */,
  "commit": /* hex-encoded TLS-serialized MLSPlaintext(Commit) */
  
  // Computed values
  "group_context": /* hex-encoded binary data */,
  "confirmed_transcript_hash_after": /* hex-encoded binary data */,
  "interim_transcript_hash_after": /* hex-encoded binary data */,
}
```

Verification:
* Verify that `confirmed_transcript_hash_after` and
  `interim_transcript_hash_after` are the result of updating
  `interim_transcript_hash_before` with `commit`
* Verify that group context matches the provided `group_context` value
* Verify that `commit.confirmation_tag` is present and verifies using
  `confirmed_transcript_hash_after` and `confirmation_key`
* Verify that `commit.membership_tag` is present and verifies using
  `membership_key` and a GroupContext object with the following contents:
  * `group_id = group_id`
  * `epoch = epoch`
  * `tree_hash = tree_hash_before`
  * `confirmed_transcript_hash = confirmed_transcript_hash_before`
  * `extensions = {}`

## TreeKEM

Parameters:
* Ciphersuite
* Number of leaves in the test tree

Format:
```text
{
  "result": /* "valid" or "invalid" */,
  "error": /* uint16 */,

  "cipher_suite": /* uint16 */,

  // Chosen by the generator
  "ratchet_tree_before": /* hex-encoded binary data */,
  
  "add_sender": /* uint32 */,
  "my_leaf_secret": /* hex-encoded binary data */,
  "my_key_package": /* hex-encoded binary data */,
  "my_path_secret": /* hex-encoded binary data */,

  "update_sender": /* uint32 */,
  "update_path": /* hex-encoded binary data */,
  "update_group_context": /* hex-encoded binary data */,

  // Computed values
  "tree_hash_before": /* hex-encoded binary data */,
  "root_secret_after_add": /* hex-encoded binary data */
  "root_secret_after_update": /* hex-encoded binary data */
  "ratchet_tree_after": /* hex-encoded binary data */,
  "tree_hash_after": /* hex-encoded binary data */
}
```

Some of the binary fields contain TLS-serialized objects:
* `ratchet_tree_before` and `ratchet_tree_after` contain serialized ratchet
  trees, as in [the `ratchet_tree` extension](https://tools.ietf.org/html/draft-ietf-mls-protocol-11#section-11.3)
* `my_key_package` contains a KeyPackage object
* `update_path` contains an UpdatePath object
* The exclusion list in the update path is empty.

Verification:
* Verify that the tree hash of `tree_before` equals `tree_hash_before`
* Verify that the tree hash of `tree_after` equals `tree_hash_after`
* Verify that both `tree_before` and `tree_after` have valid parent hashes
* Identify the test participant's location in the tree using `my_key_package`
* Initialize the private state of the tree by setting `my_path_secret` at the
  common ancestor between the test participant's leaf and `add_sender`
  and `my_leaf_secret` for the leaf
* Verify that the root secret for the initial tree matches `root_secret_after_add`
* Process the `update_path` to get a new root secret and update the tree
* Verify that the new root root secret matches `root_secret_after_update`
* Verify that the tree now matches `tree_after`
* `error` codes:
  * 1 := ParentHashMissing
  * 2 := InvalidParentHash

Among other things, this test vector ensure the following spec requirements

> [about parent hash] In particular, the extension MUST be present in the leaf_key_package field of an UpdatePath object.

> [about parent hash] To this end, when processing a Commit message clients MUST recompute the expected value of parent_hash for the committer's new leaf and verify that it matches the parent_hash value in the supplied leaf_key_package.

> [about parent hash] Moreover, when joining a group, new members MUST authenticate each non-blank parent node P.

## Messages

Parameters:
* (none)

Format:
```
{
  "result": /* "valid" or "invalid" */,
  "error": /* uint16 */,

  "key_package": /* serialized KeyPackage */,
  "capabilities": /* serialized Capabilities */,
  "lifetime": /* serialized {uint64 not_before; uint64 not_after;} */,
  "ratchet_tree": /* serialized optional<Node> ratchet_tree<1..2^32-1>; */,

  "group_info": /* serialized GroupInfo */,
  "group_secrets": /* serialized GroupSecrets */,
  "welcome": /* serialized Welcome */,

  "public_group_state": /* serialized PublicGroupState */,

  "add_proposal": /* serialized Add */,
  "update_proposal": /* serialized Update */,
  "remove_proposal": /* serialized Remove */,
  "pre_shared_key_proposal": /* serialized PreSharedKey */,
  "re_init_proposal": /* serialized ReInit */,
  "external_init_proposal": /* serialized ExternalInit */,
  "app_ack_proposal": /* serialized AppAck */,

  "commit": /* serialized Commit */,

  "mls_plaintext_application": /* serialized MLSPlaintext(ApplicationData) */,
  "mls_plaintext_proposal": /* serialized MLSPlaintext(Proposal(*)) */,
  "mls_plaintext_commit": /* serialized MLSPlaintext(Commit) */,
  "mls_ciphertext": /* serialized MLSCiphertext */,
}
```

As elsewhere, the serialized binary objects are hex-encoded.

Verification:
* The contents of each field must decode using the corresponding structure
* Each decoded object must re-encode to produce the bytes in the test vector
* The signature on each message must be valid
  * The signature scheme used must be the one specified in the `KeyPackage` credential of the sender's leaf
* The key package must have a valid signature
* `error` codes:
  * 1 := InvalidMLSPlaintextSignature
  * 2 := InvalidKeyPackageSignature
  * 3 := InvalidCiphersuite
  * 4 := MissingCapabilitiesExtension
  * 5 := InvalidCapabilitiesExtension
  * 6 := MissingLifeTimeExtension
  * 7 := BeforeLifeTime
  * 8 := AfterLifeTime
  * 9 := ConfirmationTagMissing
  * 10 := UnexpectedConfirmationTag
  * 11 := PSKMissing
  * 12 := MultiplePSK
  * 13 := InvalidPSK
  * 14 := MissingPath
  * 15 := InvalidPath
  * 16 := InvalidWelcomeKey

The specific contents of the objects are chosen by the creator of the test
vectors.  The objects produced must be syntactically valid. The optional MAC
values may be invalid but should be populated.

Among other things, this test vector ensure the following spec requirements

> The signature algorithm specified in the ciphersuite is the mandatory algorithm to be used for signatures in MLSPlaintext and the tree signatures. It MUST be the same as the signature algorithm specified in the credential field of the KeyPackage objects in the leaves of the tree (including the InitKeys used to add new members).

> A KeyPackage object with an invalid signature field MUST be considered malformed.

> KeyPackage objects MUST contain at least two extensions, [...]

> [about capabilities] This extension MUST be always present in a KeyPackage. Extensions that appear in the extensions field of a KeyPackage MUST be included in the extensions field of the capabilities extension.

> [about lifetime] A client MUST NOT use the data in a KeyPackage for any processing before the not_before date, or after the not_after date

> The field confirmation_tag MUST be present if content_type equals commit. Otherwise, it MUST NOT be present.

> The Welcome message MUST specify exactly one pre-shared key with psktype = reinit, and with psk_group_id and psk_epoch equal to the group_id and epoch of the existing group after the Commit containing the reinit Proposal was processed.

> The path field of a Commit message MUST be populated if the Commit covers at least one Update or Remove proposal. The path field MUST also be populated if the Commit covers no proposals at all (i.e., if the proposals vector is empty).

> If the path field is required based on the proposals that are in the commit (see above), then it MUST be populated.

> [about the welcome message] The private key MUST be the private key that corresponds to the public key in the node.
