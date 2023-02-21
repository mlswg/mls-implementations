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

* Test vectors are JSON serialized.
* Each test vector file is an array of objects in the form described here.
* `optional<type>` is serialized as the value itself or `null` if not present.
* MLS structs are binary encoded according to spec and represented as
  hex-encoded strings in JSON.
* HPKE and Signature public keys are encoded in the formats specified for
  HPKEPublicKey and SignaturePublicKey in the MLS specification, but as raw
  binary data, without the length prefix used in encoding those structs
* HPKE and Signature private keys are encoded as binary objects in the following
  formats:
  * HPKE private keys are encoded according to the `SerializePrivateKey` function
    for the HPKE method for the ciphersuite
  * ECDSA private keys are encoded using the `Field-Element-to-Octet-String`
    transformation (i.e., big-endian integers, as with HPKE ECDH private keys)
  * EdDSA private keys are encoded in their native byte string representation.


## Tree Math

Parameters:
* A range of test tree sizes

Format:

```
{
  "n_leaves": /* uint32 */,
  "n_nodes": /* uint32 */,
  "root": /* uint32 */,
  "left": [ /* array of optional<uint32> */ ],
  "right": [ /* array of optional<uint32> */ ],
  "parent": [ /* array of optional<uint32> */ ],
  "sibling": [ /* array of optional<uint32> */ ]
}
```

Verification:

* `n_nodes` is the number of nodes in the tree with `n_leaves` leaves
* `root` is the root node index of the tree
* `left[i]` is the node index of the left child of the node with index `i` in a
  tree with `n_leaves` leaves
* `right[i]` is the node index of the right child of the node with index `i` in
  a tree with `n_leaves` leaves
* `parent[i]` is the node index of the parent of the node with index `i` in a
  tree with `n_leaves` leaves
* `sibling[i]` is the node index of the sibling of the node with index `i` in a
  tree with `n_leaves` leaves

## Crypto Basics

Parameters:
* Ciphersuite

Format:

```text
{
  "cipher_suite": /* uint16 */,

  "ref_hash": {
    "label": /* string */,
    "value": /* hex-encoded binary data */,
    "out": /* hex-encoded binary data */,
  }

  "expand_with_label": {
    "secret": /* hex-encoded binary data */,
    "label": /* string */,
    "context": /* hex-encoded binary data */,
    "length": /* uint16 */,
    "out": /* hex-encoded binary data */,
  },

  "derive_secret": {
    "secret": /* hex-encoded binary data */,
    "label": /* string */,
    "out": /* hex-encoded binary data */,
  },

  "derive_tree_secret": {
    "secret": /* hex-encoded binary data */,
    "label": /* string */
    "generation": /* uint32 */
    "length": /* uint16 */
    "out": /* hex-encoded binary data */,
  },

  "sign_with_label": {
    "priv": /* hex-encoded binary data */,
    "pub": /* hex-encoded binary data */,
    "content": /* hex-encoded binary data */,
    "label": /* string */,
    "signature": /* hex-encoded binary data */,
  },

  "encrypt_with_label": {
    "priv": /* hex-encoded binary data */,
    "pub": /* hex-encoded binary data */,
    "label": /* string */,
    "context": /* hex-encoded binary data */,
    "plaintext": /* hex-encoded binary data */,
    "kem_output": /* hex-encoded binary data */,
    "ciphertext": /* hex-encoded binary data */,
  }
}
```

Verification:

* `ref_hash`: `out == RefHash(label, value)`
* `expand_with_label`: `out == ExpandWithLabel(secret, label, context, length)`
* `derive_secret`: `out == DeriveSecret(secret, label)`
* `derive_tree_secret`: `out == DeriveTreeSecret(secret, label, generation, length)`
* `sign_with_label`:
  * `VerifyWithLabel(pub, label, content, signature) == true`
  * `VerifyWithLabel(pub, label, content, SignWithLabel(priv, label, content)) == true`
* `encrypt_with_label`:
  * `DecryptWithLabel(priv, label, context, kem_output, ciphertext) == plaintext`
  * `kem_output_candidate, ciphertext_candidate = EncryptWithLabel(pub, label, context, plaintext)`
  * `DecryptWithLabel(priv, label, context, kem_output_candidate, ciphertext_candidate) == plaintext`

## Secret Tree

Parameters:
* Ciphersuite
* Number of leaves
* Set of generations

Format:

```text
{
  "cipher_suite": /* uint16 */,

  "sender_data": {
    "sender_data_secret": /* hex-encoded binary data */,
    "ciphertext": /* hex-encoded binary data */,
    "key": /* hex-encoded binary data */,
    "nonce": /* hex-encoded binary data */,
  },

  "encryption_secret": /* hex-encoded binary data */,
  "leaves": [
    [
      {
        "generation": /* uint32 */
        "handshake_key": /* hex-encoded binary data */,
        "handshake_nonce": /* hex-encoded binary data */,
        "application_key": /* hex-encoded binary data */,
        "application_nonce": /* hex-encoded binary data */,
      },
      ...
    ],
    ...
  ]
}
```

Verification:

* `sender_data`:
  * `key == sender_data_key(sender_data_secret, ciphertext)`
  * `nonce == sender_data_nonce(sender_data_secret, ciphertext)`
* Initialize a secret tree with a number of leaves equal to the number of
  entries in the `leaves` array, with `encryption_secret` as the root secret
* For each entry in `leaves`:
  * For each entry in the array `leaves[i]`, verify that:
    * `handshake_key = handshake_ratchet_key_[i]_[generation]`
    * `handshake_nonce = handshake_ratchet_nonce_[i]_[generation]`
    * `application_key = application_ratchet_key_[i]_[generation]`
    * `application_nonce = application_ratchet_nonce_[i]_[generation]`

The index `i` into the hash ratchets represents the leaf node with leaf index `i`. 

## Message Protection

Parameters:
* Ciphersuite

Format:

``` text
{
  "cipher_suite": /* uint16 */,

  "group_id": /* hex-encoded binary data */,
  "epoch": /* uint64 */,
  "tree_hash": /* hex-encoded binary data */,
  "confirmed_transcript_hash": /* hex-encoded binary data */,

  "signature_priv": /* hex-encoded binary data */,
  "signature_pub": /* hex-encoded binary data */,

  "encryption_secret": /* hex-encoded binary data */,
  "sender_data_secret": /* hex-encoded binary data */,
  "membership_key": /* hex-encoded binary data */,

  "proposal":  /* serialized Proposal */,
  "proposal_pub":  /* serialized MLSMessage(PublicMessage) */,
  "proposal_priv":  /* serialized MLSMessage(PrivateMessage) */,

  "commit":  /* serialized Commit */,
  "commit_pub":  /* serialized MLSMessage(PublicMessage) */,
  "commit_priv":  /* serialized MLSMessage(PrivateMessage) */,

  "application":  /* hex-encoded binary application data */,
  "application_priv":  /* serialized MLSMessage(PrivateMessage) */,
}
```

Verification:

* Construct a GroupContext object with the provided `cipher_suite`, `group_id`,
  `epoch`, `tree_hash`, and `confirmed_transcript_hash` values, and empty
  `extensions`
* For each of `proposal`, `commit` and `application`:
  * Initialize a secret tree for 2 members with the specified
  `encryption_secret`
  * In all of these tests, use the member with LeafIndex 1 as the sender
  * Verify that the `pub` message verifies with the provided `membership_key`
    and `signature_pub`, and produces the raw proposal / commit / application
    data
  * Verify that protecting the raw value with the provided `membership_key` and
    `signature_priv` produces a PublicMessage that verifies with `membership_key`
    and `signature_pub`
    * When protecting the Commit message, add the supplied confirmation tag
    * For the application message, instead verify that protecting as a
      PublicMessage fails
  * Verify that the `priv` message successfully unprotects using the secret tree
    constructed above and `signature_pub`
  * Verify that protecting the raw value with the secret tree,
    `sender_data_secret`, and `signature_priv` produces a PrivateMessage that
    unprotects with the secret tree, `sender_data_secret`, and `signature_pub`
    * When protecting the Commit message, add the supplied confirmation tag

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
      "epoch_authenticator": /* hex-encoded binary data */,
      "external_secret": /* hex-encoded binary data */,
      "confirmation_key": /* hex-encoded binary data */,
      "membership_key": /* hex-encoded binary data */,
      "resumption_psk": /* hex-encoded binary data */,

      "external_pub": /* hex-encoded binary data */,
      "exporter": {
        "label": /* string */,
        "context: /* hex-encoded binary data*/,
        "length": /* uint32 */,
        "secret": /* hex-encoded binary data */
      }
    },
    ...
  ]
}
```

Verification:
* Initialize the first key schedule epoch for the group [as defined in the
  specification](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#group-creation),
  using `group_id`, `initial_tree_hash`, and `initial_init_secret` for the
  non-constant values. Note that `psk_secret` can sometimes be the all zero vector.
* For epoch `epoch[i]`:
  * Construct a GroupContext with the following contents:
    * `cipher_suite` as specified
    * `group_id` as specified
    * `epoch = i`
    * `tree_hash` as specified
    * `confirmed_transcript_hash` as specified
    * `extensions = {}`
  * Verify that group context matches the provided `group_context` value
  * Verify that the key schedule outputs are as specified given the following
    inputs:
    * `init_key` from the prior epoch or `initial_init_secret`
    * `commit_secret` as specified and `psk_secret` (if present)
    * `GroupContext_[n]` as computed above
  * Verify the `external_pub` is the public key output from `KEM.DeriveKeyPair(external_secret)`
  * Verify the `exporter.secret` is the value output from `MLS-Exporter(exporter.label, exporter.context, exporter.length)`

## Pre-Shared Keys

Parameters:
* Ciphersuite
* Number of PreSharedKeys

Format:

```text
{
  "cipher_suite": /* uint16 */,

  // Chosen by the generator
  "psks": [
    {
      "psk_id": /* hex-encoded binary data */,
      "psk": /* hex-encoded binary data */,
      "psk_nonce": /* hex-encoded binary data */,
    },
    ...
  ],

  // Computed values
  "psk_secret": /* hex-encoded binary data */,
}
```

Verification:
* For each PreSharedKey in `psks`, compute `PreSharedKeyID` with external
  `PSKType` and with provided `psk_id` and `psk_nonce`
* Use the computed `PreSharedKeyID` values and provided `psk` values to
  compute the `psk_secret` as described in
  [the specification](https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17#name-pre-shared-keys)
  and verify that it matches the provided `psk_secret`

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
  "credential": /* hex-encoded binary data */,

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
* Verify that the commit has a valid signature using the `credential`
* Verify that `commit.membership_tag` is present and verifies using
  `membership_key` and a GroupContext object with the following contents:
  * `group_id = group_id`
  * `epoch = epoch`
  * `tree_hash = tree_hash_before`
  * `confirmed_transcript_hash = confirmed_transcript_hash_before`
  * `extensions = {}`

## Welcome

Parameters:
* Ciphersuite

Format:

```text
{
  "cipher_suite": /* uint16 */,

  // Chosen by the generator
  "init_priv": /* hex-encoded serialized HPKE private key */,
  "signer_pub": /* hex-encoded serialized signature public key */,

  "key_package": /* hex-encoded serialized MLSMessage(KeyPackage) */,
  "welcome": /* hex-encoded serialized MLSMessage(Welcome) */,
}
```

Verification:
* Decrypt the Welcome message:
  * Identify the entry in `welcome.secrets` corresponding to `key_package`
  * Decrypt the encrypted group secrets using `init_priv`
  * Decrypt the encrypted group info
* Verify the signature on the decrypted group info using `signer_pub`
* Verify the `confirmation_tag` in the decrypted group info:
  * Initialize a key schedule epoch using the decrypted `joiner_secret` and no PSKs
  * Recompute a candidate `confirmation_tag` value using the `confirmation_key`
    from the key schedule epoch and the `confirmed_transcript_hash` from the
    decrypted GroupContext

## Tree Validation

Parameters:
* Ciphersuite

Format:
```text
{
  "cipher_suite": /* uint16 */,

  // Chosen by the generator
  "tree": /* hex-encoded binary data */,
  "group_id": /* hex-encoded binary data */,

  // Computed values
  "resolutions": [
    [uint32, ...],
  ...
  ],

  "tree_hashes": [
    /* hex-encoded binary data */,
  ...
  ]
}
```

`tree` contains a TLS-serialized ratchet tree, as in
[the `ratchet_tree` extension](https://tools.ietf.org/html/draft-ietf-mls-protocol-17#section-12.4.3.3)

Verification:
* Verify that the resolution of each node in tree with node index `i` matches
  `resolutions[i]`.
* Verify that the tree hash of each node in tree with node index `i` matches
  `tree_hashes[i]`.
* [Verify the parent hashes](https://tools.ietf.org/html/draft-ietf-mls-protocol-17#section-7.9.2)
  of `tree` as when joining the group.
* Verify the signatures on all leaves of `tree` using the provided `group_id`
  as context.

### Origins of Test Trees
Trees in the test vector are ordered according to increasing complexity. Let
`get_tree(n)` denote the tree generated as follows: Initialize a tree
with a single node. For `i=0` to `n - 1`, leaf with leaf index `i`
commits adding a member (with leaf index `i + 1`).

Note that the following tests cover `get_tree(n)` for all `n` in
`[2, 3, ..., 9, 32, 33, 34]`.

* Full trees: `get_tree(n)` for `n` in `[2, 4, 8, 32]`.
* A tree with internal blanks: start with `get_tree(8)`; then the leaf with
  index `0` commits removing leaves `2` and `3`, and adding new member.
* Trees with trailing blanks: `get_tree(n)` for `n` in `[3, 5, 7, 33]`.
* A tree with internal blanks and skipping blanks in the parent hash links:
  start with `get_tree(8)`; then the leaf with index `0` commits removing
  leaves `1`, `2` and `3`.
* Trees with skipping trailing blanks in the parent hash links:
  `get_tree(n)` for `n` in `[3, 34]`.
* A tree with unmerged leaves: start with `get_tree(7)`, then the leaf
  with index `0` adds a member.
* A tree with unmerged leaves and skipping blanks in the parent hash links:
  the tree from [Figure 20](https://tools.ietf.org/html/draft-ietf-mls-protocol-17#appendix-A).

## TreeKEM

Parameters:
* Ciphersuite
* Number of leaves in the test tree

Format:
```text
{
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

## Messages

Parameters:
* (none)

Format:
``` text
{
  /* Serialized MLSMessage with MLSMessage.wire_format == mls_welcome */
  "mls_welcome": "...",
  /* Serialized MLSMessage with MLSMessage.wire_format == mls_group_info */
  "mls_group_info": "...",
  /* Serialized MLSMessage with MLSMessage.wire_format == mls_key_package */
  "mls_key_package": "...",

  /* Serialized optional<Node> ratchet_tree<1..2^32-1>; */
  "ratchet_tree": "...",
  /* Serialized GroupSecrets */
  "group_secrets": "...",

  "add_proposal":                      /* Serialized Add */,
  "update_proposal":                   /* Serialized Update */,
  "remove_proposal":                   /* Serialized Remove */,
  "pre_shared_key_proposal":           /* Serialized PreSharedKey */,
  "re_init_proposal":                  /* Serialized ReInit */,
  "external_init_proposal":            /* Serialized ExternalInit */,
  "group_context_extensions_proposal": /* Serialized GroupContextExtensions */,

  "commit": /* Serialized Commit */,

  /* Serialized MLSMessage with
       MLSMessage.wire_format == mls_public_message and
       MLSMessage.public_message.content.content_type == application */
  "public_message_application": "...",
  /* Serialized MLSMessage with
       MLSMessage.wire_format == mls_public_message and
       MLSMessage.public_message.content.content_type == proposal */
  "public_message_proposal": "...",
  /* Serialized MLSMessage with
       MLSMessage.wire_format == mls_public_message and
       MLSMessage.public_message.content.content_type == commit */
  "public_message_commit": "...",
  /* Serialized MLSMessage with MLSMessage.wire_format == mls_private_message */
  "private_message": "...",
}
```

As elsewhere, the serialized binary objects are hex-encoded.

Verification:
* The contents of each field must decode using the corresponding structure
* Each decoded object must re-encode to produce the bytes in the test vector
* The signature on each message must be valid

The specific contents of the objects are chosen by the creator of the test
vectors.  The objects produced must be syntactically valid. The optional MAC
values may be invalid but should be populated.

## Passive Client Scenarios

This section describes a class of test vectors that verify that a client can
"follow along" with group operations (rather than a single test vector).  A test
vector as described in this section represents a scenario in which a client is
added to a group with a Welcome, and verifies that the client can follow along
as the group evolves.

Parameters:
* Ciphersuite
* Operations to be performed on the group

Format:
``` text
{
  "cipher_suite": /* uint16 */,

  "key_package": /* serialized KeyPackage */,
  "signature_priv":  /* hex-encoded binary data */,
  "encryption_priv": /* hex-encoded binary data */,
  "init_priv": /* hex-encoded binary data */,

  "welcome":  /* serialized MLSMessage (Welcome) */,
  "initial_epoch_authenticator":  /* hex-encoded binary data */,
  
  "epochs": [
    {
      "proposals": [
        /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
        /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
      ],
      "commit": /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
      "epoch_authenticator": /* hex-encoded binary data */,
    },
    // ...
  ]
}
```

Verification:

* Verify that `signature_priv`, `leaf_priv`, and `init_priv` correspond to the
  public keys (`signature_key`, `encryption_key`, and `init_key`) in the KeyPackage object described by `key_package`
* Join the group using the Welcome message described by `welcome`
* Verify that the locally computed `epoch_authenticator` value is equal to the
  `initial_epoch_authenticator` value
* For each entry in `epochs`:
  * Apply the Commit from `commit`, using any values from `proposals` that are
    incorporated by reference in the Commit
  * Verify that the locally computed `epoch_authenticator` value is equal to the
    `epoch_authenticator` value in the epoch object
