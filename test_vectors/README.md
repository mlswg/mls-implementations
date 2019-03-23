# Test vectors

This directory contains binary files with pre-serialized test
vectors.  Each file contains a single structure in a TLS-syntax
format defined below (in each case, the `XXXTestVectors` struct).

## Deltas from the Spec

The primary interop target for now is draft-03.  However, due to a
couple of deficiencies in the spec, these test vectors deviate from
the spec.

First, we use an altertive `ECIESCiphertext` struct that uses three
length octets to accommodate the `Welcome` message.

```
struct {
  DHPublicKey ephemeral_key;
  opaque ciphertext<0..2^24-1>;
} ECIESCiphertext;
```

[[ TODO: Beurdouche's fixes to the application key schedule ]]

## Tree Math

File: [tree_math.bin](https://github.com/mlswg/mls-implementations/blob/master/test_vectors/tree_math.bin)

```
struct {
  uint32 tree_size;
  uint32 root<0..2^32-1>;
  uint32 left<0..2^32-1>;
  uint32 right<0..2^32-1>;
  uint32 parent<0..2^32-1>;
  uint32 sibling<0..2^32-1>;
} TreeMathTestVectors;
```

These vectors have the following meaning, where the tree relations
are as defined in [the specification](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#tree-computation-terminology):

* `tree_size` specifies the size of the test tree for the left /
  right / parent / sibling tests.
* `root[i]` is the index of the root of a tree with `i+1` leaves
* The remaining vectors are all within the context of a tree with
  `tree_size` leaves:
  * `left[i]` is the index of the left child of node `i` 
  * `right[i]` is the index of the right child of node `i` 
  * `parent[i]` is the index of the parent of node `i` 
  * `sibling[i]` is the index of the sibling of node `i` 

Your implementation's tree math library should be able to reproduce
these values.

## Resolution

File: [resolution.bin](https://github.com/mlswg/mls-implementations/blob/master/test_vectors/resolution.bin)

```
uint8_t Resolution<0..255>;
Resolution ResolutionCase<0..2^16-1>;

struct {
  uint32_t n_leaves;
  ResolutionCase cases<0..2^32-1>;
} ResolutionTestVectors;
```

These vectors represent the output of the resolution algorithm on
all configurations of a tree with `n_leaves` leaves.  

* The `cases` vector should have `2^(2*n_leaves - 1)` entries
  * The entry at index `t` represents the set of resolutions for the
    tree with a blank / filled pattern matching the bit pattern of the
    integer `t`.  
  * If `((t >> n) & 1) == 1`, then node `n` in the tree is
    filled; otherwise it is blank.
* Each `ResolutionCase` vector contains the resolutions of every
  node in the tree, in order
* Thus `cases[t][i]` contains the resolution of node `i` in tree
  `t`

Your implementation should be able to reproduce these values.

## Cryptographic Functions

File: [crypto.bin](https://github.com/mlswg/mls-implementations/blob/master/test_vectors/crypto.bin)

```
struct {
  opaque hkdf_extract_out<0..255>;
  GroupState derive_secret_state;
  opaque derive_secret_out<0..255>;
  DHPublicKey derive_key_pair_pub;
  ECIESCiphertext ecies_out;
} CryptoCase;

struct {
  opaque hkdf_extract_salt<0..255>;
  opaque hkdf_extract_ikm<0..255>;
  opaque derive_secret_salt<0..255>;
  opaque derive_secret_label<0..255>;
  uint32 derive_secret_length;
  opaque derive_key_pair_seed<0..255>;
  opaque ecies_plaintext<0..255>;

  CryptoCase case_p256_p256;
  CryptoCase case_x25519_ed25519;
} CryptoTestVectors;
```

The `CryptoTestVectors` struct contains the inputs to cryptographic
functions, and the `CryptoCase` members hold the outputs when using
the indicated ciphersuites.  The following functions are tested:

* `HKDF-Extract`
* `Derive-Secret`
* `Derive-Key-Pair`
* ECIES
  * Encryption and decryption is done using the key pair generated
    in the `Derive-Key-Pair` stage.
  * The encryption phase is made deterministic by deriving the
    ephemeral key pair from the inputs.
  * `(skE, pkE)  = Derive-Key-Pair(pkR || plaintext)`, where `pkR`
    is the serialization of the recipient's public key (the body of
    a `DHPublicKey`, with no length octets), and `plaintext` is the
    plaintext being encrypted.

Your implementation should be able to reproduce these values.

## Key Schedule

File: [key_schedule.bin](https://github.com/mlswg/mls-implementations/blob/master/test_vectors/key_schedule.bin)

```
struct {
  opaque update_secret<0..255>;
  opaque epoch_secret<0..255>;
  opaque application_secret<0..255>;
  opaque confirmation_key<0..255>;
  opaque init_secret<0..255>;
} KeyScheduleEpoch;

struct {
  CipherSuite suite;
  Epoch epochs<0..2^16-1>;
} KeyScheduleCase;

struct {
  uint32_t n_epochs;
  opaque base_group_state<0..2^32-1>;

  KeyScheduleCase case_p256;
  KeyScheduleCase case_x25519;
} KeyScheduleTestVectors;
```

For each ciphersuite, the `KeyScheduleTestVectors` struct provides a
`KeyScheduleCase` that describes the outputs of the MLS key schedule
over the course of several epochs.

* The `init_secret` input to the first stage of the key schedule is
  the all-zero vector of length `Hash.length` for the hash indicated
  by the ciphersuite.
* For future epochs, the `init_secret` is the value output at the
  previous stage of the key schedule.
* The initial `GroupState` object input to the key schedule should
  be deserialized from the `base_group_state` object.
* For each epoch, the `epoch` field of the GroupState object is
  incremented after being provided to the key schedule. This is to
  say, the key schedule is run on the `base_group_state` object before
  its `epoch` is incremented for the first time.

For each epoch, given inputs as described above, your implementation
should replacate the `epoch_secret`, `application_secret`,
`confirmation_key`, and `init_secret` outputs of the key schedule.

## Message Parsing and Serialization

File: [messages.bin](https://github.com/mlswg/mls-implementations/blob/master/test_vectors/messages.bin)

```
struct {
  CipherSuite cipher_suite;
  SignatureScheme sig_scheme;

  opaque user_init_key<0..2^32-1>;
  opaque welcome_info<0..2^32-1>;
  opaque welcome<0..2^32-1>;
  opaque add<0..2^32-1>;
  opaque update<0..2^32-1>;
  opaque remove<0..2^32-1>;
} MessagesCase;

struct {
  uint32_t epoch;
  uint32_t signer_index;
  uint32_t removed;
  opaque user_id<0..255>;
  opaque group_id<0..255>;
  opaque uik_id<0..255>;
  opaque dh_seed<0..255>;
  opaque sig_seed<0..255>;
  opaque random<0..255>;

  SignatureScheme uik_all_scheme;
  opaque user_init_key_all<0..2^32-1>;

  MessagesCase case_p256_p256;
  MessagesCase case_x25519_ed25519;
} MessagesTestVectors;
```

The elements of the struct have the following meanings:

* The first several fields contain the values used to construct the
  example messages.
* `user_init_key_all` contains a UserInitKey that offers all four
  ciphersuites.  It is validly signed with an Ed25519 key.
* The remaining cases each test message processing for a given
  ciphersuite:
  * `case_p256_p256` uses P256 for DH and ECDSA-P256 for signing
  * `case_x25519_ed25519` uses X25519 for DH and Ed25519 for signing
* In each case:
  * `user_init_key` contains a UserInitKey offering only the
    indicated ciphersuite, validly signed with the corresponding
    signature scheme
  * `welcome_info` contains a `WelcomeInfo` message with
    syntactically valid but bogus contents
  * `welcome` contains a Welcome message generated by encrypting
    `welcome_info` for a Diffie-Hellman public key derived from the
    `dh_seed` value.
  * `add`, `update`, and `remove` each contain a Handshake message
    with a GroupOperation of the corresponding type.  The signatures
    on these messages are not valid

Your implementation should be able to pass the following tests:

* `user_init_key_all` should parse successfully 
* The test cases for any supported ciphersuites should parse
  successfully
* All of the above parsed values should survive a marshal /
  unmarshal round-trip


## MLS Sessions

```
struct {
  opaque welcome<0..2^32-1>; // may be empty
  opaque handshake<0..2^32-1>;

  uint32 epoch;
  opaque epoch_secret<0..255>;
  opaque application_secret<0..255>;
  opaque confirmation_key<0..255>;
  opaque init_secret<0..255>;
} Epoch;

struct {
  opaque value<0..2^32-1>;
} SerializedUserInitKey;

struct {
  CipherSuite cipher_suite;
  SignatureScheme sig_scheme;
  SerializedUserInitKey user_init_keys<0..2^32-1>;
  Epoch transcript<0..2^32-1>;
} SessionCase;

struct {
  uint32 group_size;
  opaque group_id<0..255>;

  SessionCase case_p256_p256;
  SessionCase case_x25519_ed25519;
} SessionTestVectors;
```

A `SessionTestVectors` struct specifies the messages exchanged
during an MLS session and the resulting group secrets.  The specific
sequence of actions taken over the lifetime of a session (adds,
updates, etc.) is specified in a "script" for a particular test.

The elements of this struct have the following meanings:

* The `group_size` field specifies the size of the group created
  during the session
* The `group_id` field specifies the group ID to be used in
  `GroupState` objects
* For each case:
  * The `cipher_suite` and `sig_scheme` fields specify the
    algorithms in use
  * The `user_init_keys` field represents the `UserInitKey` messages
    generated by the participants
    * There is one DH init key, derived from the two-octet value
      `{i, 0}`, where `i` is the position of the member in the
      group, using the ciphersuite in use
    * The credential in the UserInitKey is a `BasicCredential` with
      the following values:
      * Identity: The same two-octet value as above
      * Signature key: A key derived from the same two-octet
        value (in the same way as `Derive-Key-Pair` for the
        corresponding curve)
  * The `transcript` field contains a sequence of `Epoch` structs,
    where with each epoch:
    * The `welcome` field, if non-zero-length, represents a Welcome
      message to be provided to the new joiner, according to the
      script in use
    * The `handshake` field contains the handshake message that
      initiates this epoch
    * The remaining values describe the state of the group after
      processing the handshake message
* All ECIES is done with the deterministic variant described above

Your implementation should be able to pass the following tests:

* For any of the participants in the group, you should be able to
  initialize the participant as described above, consume Welcome
  and Handshake messages as prescribed by the script, and reproduce
  the outputs for each Epoch where the participant is joined to the
  group.

* For cases where the algorithms in use are deterministic (all
  besides ECDSA), you should be able to run a session among
  instances of your implementation, following the script, and
  reproduce the transcript byte-exactly.

### A Basic Session 

In this script, a group is created, then all members update, then
the members are all removed.

1. Members are added left-to-right
  * In each epoch, the last-added member adds a new member at the
    right edge of the tree.
2. Members update left-to-right
  * Each member sends an update, in order of their position in the
    tree.
  * The new leaf key pare for the member at position `i` is derived
    from the two-octet value `{i, 1}`.
3. Members remove each other right-to-left
  * In each epoch, the next-to-last member removes the last member
    (in tree-leaf order)
  * The eviction secret used by the member at position `i` is
    the two-octet value `{i, 2}`.

For example, in a case with 5 members would have the following
epochs, with the lifetime of member 2 illustrated:

```
 0 M0 add M1
 1 M1 add M2  <-- Process epoch.welcome and epoch.handshake (Add)
 2 M2 add M3  <-- Generate epoch.handshake (Add)
 3 M3 add M4  <-+
 4 M0 upd       |
 5 M1 upd       |
 6 M2 upd       | Passively process and update state
 7 M3 upd       |
 8 M4 upd       |
 9 M3 rem m4  <-+
10 M2 rem M3  <-- Generate epoch.handshake (Remove)
11 M1 rem M2  ... (No longer part of the group from here on)
12 M0 rem M1
```
