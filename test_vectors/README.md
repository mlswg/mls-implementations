# Test vectors

This directory contains binary files with pre-serialized test
vectors.  Each file contains a single structure in a TLS-syntax
format defined below (in each case, the `XXXTestVectors` struct).

## Tree Math

File: [tree_math.bin](https://github.com/mlswg/mls-implementations/blob/master/test_vectors/tree_math.bin)

```
struct {
  uint32 root<0..2^32-1>;
  uint32 left<0..2^32-1>;
  uint32 right<0..2^32-1>;
  uint32 parent<0..2^32-1>;
  uint32 sibling<0..2^32-1>;
} TreeMathTestVectors;
```

These vectors have the following meaning, where the tree relations
are as defined in [the specification](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#tree-computation-terminology):

* `root[i]` is the index of the root of a tree with `i+1` leaves
* The remaining vectors are all within the context of a tree with
  255 leaves:
  * `left[i]` is the index of the left child of node `i` 
  * `right[i]` is the index of the right child of node `i` 
  * `parent[i]` is the index of the parent of node `i` 
  * `sibling[i]` is the index of the sibling of node `i` 

Your implementation's tree math library should be able to reproduce
these values.


## Message Parsing and Serialization

File: [messages.bin](https://github.com/mlswg/mls-implementations/blob/master/test_vectors/messages.bin)

```
struct {
  CipherSuite cipher_suite;
  UserInitKey user_init_key;
  Welcome welcome;
  Handshake add;
  Handshake update;
  Handshake remove;
} CipherSuiteCase;

struct {
  UserInitKey user_init_key_all;
  CipherSuiteCase case_p256_p256;
  CipherSuiteCase case_x25519_ed25519;
  CipherSuiteCase case_p521_p521;
  CipherSuiteCase case_x448_ed448;
} MessagesTestVectors;
```

The elements of the struct have the following meanings:

* `user_init_key_all` contains a UserInitKey that offers all four
  ciphersuites.  It is validly signed with an Ed448 key.
* The remaining cases each test message processing for a given
  ciphersuite:
  * `case_p256_p256` uses P256 for DH and ECDSA-P256 for signing
  * `case_x25519_ed25519` uses X25519 for DH and Ed25519 for signing
  * `case_p521_p521` uses P521 for DH and ECDSA-P521 for signing
  * `case_x448_ed448` uses X448 for DH and Ed448 for signing
* In each case:
  * 
  * `user_init_key` contains a UserInitKey offering only the
    indicated ciphersuite, validly signed with the corresponding
    signature scheme
  * `welcome` contains a Welcome message with syntactically valid
    but bogus contents
  * `add`, `update`, and `remove` each contain a Handshake message
    with a GroupOperation of the corresponding type.  The signatures
    on these messages are not valid

Your implementation should be able to pass the following tests:

* `user_init_key_all` should parse successfully 
* The test cases for any supported ciphersuites should parse
  successfully
* All of the above parsed values should survive a marshal /
  unmarshal round-trip
