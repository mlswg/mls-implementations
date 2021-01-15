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
  "cipher_suite": /* uint16 */,
  "n_leaves": /* uint32 */,
  "encryption_secret": /* hex-encoded binary data */,
  "sender_data_secret": /* hex-encoded binary data */,
  "sender_data_info": {
    "ciphertext": /* hex-encoded binary data */,
    "secrets": {
      "key": /* hex-encoded binary data */,
      "nonce": /* hex-encoded binary data */,
    }
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

The extra factor of 2 in `2*N` ensures that only chains rooted at leaf nodes are
tested.  The definitions of `ratchet_key` and `ratchet_nonce` are in the
[Encryption
Keys](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#encryption-keys)
section of the specification.

## Key Schedule

Parameters:
* Ciphersuite
* Number of epochs

Format:

```
struct {
  MLSPlaintext commit;       // chosen by generator.  membership_tag and
                             // confirmation_tag MUST be valid; otherwise 
                             // content is only used for transcript.
  CryptoValue tree_hash;     // chosen by generator

  CryptoValue commit_secret; // chosen by generator
  CryptoValue psk_secret;    // chosen by generator

  CryptoValue confirmed_transcript_hash;
  CryptoValue interim_transcript_hash;
  CryptoValue group_context;

  CryptoValue joiner_secret;
  CryptoValue welcome_secret;
  CryptoValue epoch_secret;
  CryptoValue init_secret;

  CryptoValue sender_data_secret;
  CryptoValue encryption_secret;
  CryptoValue exporter_secret;
  CryptoValue authentication_secret;
  CryptoValue external_secret;
  CryptoValue confirmation_key;
  CryptoValue membership_key;
  CryptoValue resumption_secret;

  HPKEPublicKey external_pub;
} Epoch;

struct {
  CipherSuite cipher_suite;
  CryptoValue group_id;
  CryptoValue initial_tree_hash;    // chosen by generator
  CryptoValue initial_init_secret;  // chosen by generator
  Epoch epochs<0..2^32-1>;
} KeyScheduleTestVector;
```

Verification:
* Initialize the first key schedule epoch for the group [as defined in the
  specification](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#group-creation), using `group_id`, `initial_tree_hash`, and `initial_init_secret` for the non-constant values.
* For epoch `i`:
  * Verify the `membership_tag` on the included commit using the
    `membership_key` from the prior epoch
  * Update the transcript hash with the provided commit message
  * Construct a GroupContext with the following contents:
    * `group_id = group_id`
    * `epoch = i`
    * `tree_hash` as specified
    * `confirmed_transcript_hash` as computed from the commit message
    * `extension = {}`
  * Verify that the transcript hashes and group context are as specified
  * Verify that the key schedule outputs are as specified given the following
    inputs:
    * `init_key` from the prior epoch or `base_init_key`
    * `commit_secret` and `psk_secret` as specified
    * `GroupContext_[n]` as computed above
  * Verify the `confirmation_tag` on the included commit

## TreeKEM

Parameters:
* Ciphersuite
* Number of leaves in the test tree

Format:
```
struct {
  optional<Node> nodes<1..2^32-1>;
} RatchetTree;

struct {
  CipherSuite cipher_suite;

  RatchetTree ratchet_tree_before; // chosen by generator
  CryptoValue tree_hash_before;

  uint32 add_sender;               // chosen by generator
  KeyPackage my_key_package;       // chosen by generator
  CryptoValue my_path_secret;      // chosen by generator

  uint32 update_sender;            // chosen by generator
  UpdatePath update_path;          // chosen by generator

  CryptoValue root_secret;
  RatchetTree tree_after;
  CryptoValue tree_hash_after;

} TreeKEMTestVector;
```

Verification:
* Verify that the tree hash of `tree_before` equals `tree_hash_before`
* Verify that the tree hash of `tree_after` equals `tree_hash_after`
* Verify that both `tree_before` and `tree_after` have valid parent hashes
* Identify the test participant's location in the tree using `my_key_package`
* Initialize the private state of the tree by setting `my_path_secret` at the
  common ancestor between the test participant's leaf and `add_sender`
* Process the `update_path` to get a new root secret and update the tree
* Verify that the new root root secret matches `root_secret`
* Verify that the tree now matches `tree_after`

## Messages

Parameters:
* (none)

Format:
```
struct {
  opaque data<0..2^32-1>;
} Message;

struct {
  Message key_package;                // KeyPackage
  Message capabilities;               // Capabilities
  Message lifetime;                   // uint64 not_before; uint64 not_after;
  Message ratchet_tree;               // optional<Node> ratchet_tree<1..2^32-1>;

  Message group_info;                 // GroupInfo
  Message group_secrets;              // GroupSecrets
  Message welcome;                    // Welcome

  Message public_group_state;         // PublicGroupState

  Message add_proposal;               // Add
  Message update_proposal;            // Update
  Message remove_proposal;            // Remove
  Message pre_shared_key_proposal;    // PreSharedKey
  Message re_init_proposal;           // ReInit
  Message external_init_proposal;     // ExternalInit
  Message app_ack_proposal;           // AppAck

  Message commit;                     // Commit

  Message mls_plaintext_application;  // MLSPlaintext(ApplicationData)
  Message mls_plaintext_proposal;     // MLSPlaintext(Proposal(*))
  Message mls_plaintext_commit;       // MLSPlaintext(Commit)
  Message mls_ciphertext;             // MLSCiphertext
} MessagesTestVector;
```

Verification:
* The contents of each field must decode using the corresponding structure
* Each decoded object must re-encode to produce the bytes in the test vector

The specific contents of the objects are chosen by the creator of the test
vectors.  The objects produced must be syntactically valid, but are not required
to meet any other requirements for such objects.  For example, signatures or MAC
values may be invalid.  Optional fields should be populated.
