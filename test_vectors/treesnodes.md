# Trees and Nodes

## Node key derivation

Curve25519

Structs:

```
struct NodeSecret {
   uint8 bytes<0..31>;
}

struct PrivateKey {
    uint8 bytes<0..31>
}

struct PublicKey {
    uint8 bytes<0..31>
}
```

Input:

```
Node secret:
20E029FBE9DE859E7BD6AEA95AC258AE743A9EABCCDE9358420D8C975365938714
```

Output:

```
Private key:
20E029FBE9DE859E7BD6AEA95AC258AE743A9EABCCDE9358420D8C975365938714

Public key:
206667B1715A0AD45B0510E850322A8D471D4485EBCBFCC0F3BCCE7BCAE7B44F7F
```