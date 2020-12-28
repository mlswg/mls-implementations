# Test vectors

We use test vectors as a way of testing basic, deterministic functions of the
MLS stack.  Each test harness should have a way to produce and verify test
vectors of a few kinds.  In this document we specify the format for test vectors
and how they are verified.

## Tree Math

Parameters:
* Number of leaves in the test tree

Format:

```
struct {
  uint32 n_leaves;
  uint32 root<0..2^32-1>;
  uint32 left<0..2^32-1>;
  uint32 right<0..2^32-1>;
  uint32 parent<0..2^32-1>;
  uint32 sibling<0..2^32-1>;
} TreeMathTestVector;
```

Verification:

* `root[i]` is the root node index of the tree with `i+1` leaves
* `left[i]` is the node index of the left child of the node with index `i` in a
  tree with `n_leaves` leaves
* `right[i]` is the node index of the right child of the node with index `i` in
  a tree with `n_leaves` leaves
* `parent[i]` is the node index of the parent of the node with index `i` in a
  tree with `n_leaves` leaves
* `sibling[i]` is the node index of the sibling of the node with index `i` in a
  tree with `n_leaves` leaves

## Hash Ratchet

Parameters:
* Ciphersuite
* Number of leaves
* Number of generations

Format:

```
struct {
  opaque data<0..255>;
} CryptoValue;

struct {
  CryptoValue key;
  CryptoValue nonce;
} KeyAndNonce;

struct {
  KeyAndNonce steps<0..2^32-1>;
} HashRatchetSequence;

struct {
  CryptoValue base_secret;
  HashRatchetSequence chains<0..2^32-1>;
} HashRatchetTestVector;
```

Verification:

* For all `N`, `j`...
  * `chains[N][j].key = ratchet_key_[2*N]_[j]` 
  * `chains[N][j].nonce = ratchet_nonce_[2*N]_[j]` 

The extra factor of 2 in `2*N` ensures that only chains rooted at leaf nodes are
tested.  The definitions of `ratchet_key` and `ratchet_nonce` are in the
[Encryption
Keys](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#encryption-keys)
section of the specification.

## Secret Tree

Parameters:
* Ciphersuite
* Number of leaves in the test tree

Format:

```
struct {
  CryptoValue base_secret;
  CryptoValue tree_node_secrets<0..2^32-1>;
} SecretTreeTestVector;
```

Verification:

* The length of `tree_node_secrets` is odd
* `tree_node_secrets[N] = tree_node_[N]_secret`

The definition of `tree_node_[N]_secret` is in the [Secret
Tree](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#secret-tree-secret-tree)
section of the specification.

## Key Schedule

Parameters:
* Ciphersuite
* Number of epochs

Format:

```
struct {
  CryptoValue tree_hash;     // chosen by generator
  MLSPlaintext commit;       // chosen by generator.  membership_tag and
                             // confirmation_tag MUST be valid; otherwise 
                             // content is only used for transcript.

  CryptoValue confirmed_transcript_hash;
  CryptoValue interim_transcript_hash;
  CryptoValue group_context;

  CryptoValue commit_secret; // chosen by generator
  CryptoValue psk_secret;    // chosen by generator

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
  CryptoValue group_id;
  CryptoValue base_init_secret;
  Epoch epochs<0..2^32-1>;
} KeyScheduleTestVector;
```

Verification:
* Initialize `interim_transcript_hash = confirmed_transcript_hash = ""`
* For epoch `i`:
  * if `i > 0`: Verify the `membership_tag` on the included commit using the
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

## Tree Hashing

Parameters:
* Ciphersuite
* Number of leaves in the test tree

Format:
```
struct {
  optional<Node> nodes<1..2^32-1>;
} RatchetTree;

struct {
  CryptoValue tree_hash;
  optional<Node> ratchet_tree<1..2^32-1>; 
} TreeKEMTestVector;
```

Verification:
* The tree hash of ratchet tree equals `tree_hash`
* The ratchet tree has valid parent hashes

## Messages

Parameters:
* (none)

Format:
```
struct {
  opaque data<0..2^32-1>;
} Message;

struct {
  Message key_package;
  Message capabilities;
  Message ratchet_tree;

  Message group_info;
  Message group_secrets;
  Message welcome;

  Message public_group_state;

  Message add_proposal;
  Message update_proposal;
  Message remove_proposal;
  Message pre_shared_key_proposal;
  Message re_init_proposal;
  Message external_init_proposal;
  Message app_ack_proposal;

  Message commit;

  Message mls_ciphertext;
} MessagesTestVector;
```

Verification:
* The contents of each field must decode using the corresponding structure
* Each decoded object must re-encode to produce the bytes in the test vector

The specific contents of the objects are chosen by the creator of the test
vectors.  The objects produced must be syntactically valid, but are not required
to meet any other requirements for such objects.  For example, signatures or MAC
values may be invalid.  Optional fields should be populated.
