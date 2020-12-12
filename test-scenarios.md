MLS Interop Test Scenarios
==========================

Participants are labeled A, B, C, ..., with the idea that they can be
instantiated by any of the available implementations.  Tests are listed by
scenario, which mainly corresponds to the message flow.  Other parameters
include:

* Ciphersuite
* Credential type

## Verifying Common State (subroutine)

Since the major goal of MLS is to synchronize cryptographic state across a
group's members, the key factor for verifying interop is verifying whether
clients do indeed have the same cryptographic state.  The following things
should be checked:

* Each member's state produces the same authentication secret
* An export with the same label and context produces the same exported value at
  each member
* For each member:
  * A message can be encrypted
  * The message can be successfully decrypted by all other members

This is indicated in the flows below as:

```
***:  Verify group state
```

## 1:1 join

```
A:    Create group
B->A: KeyPackage
A->B: Welcome
***:  Verify group state
```

## 3-party join

```
A:    Create group
B->A: KeyPackage
A->B: Welcome
C->A: KeyPackage
A->B: Add(C), Commit
A->C: Welcome
***:  Verify group state
```

## Multiple joins at once

```
A:    Create group
B->A: KeyPackage
C->A: KeyPackage
A->B: Welcome
A->C: Welcome
***:  Verify group state
```

## External join

```
A:    Create group
B->A: KeyPackage
A->B: Welcome
A->C: PublicGroupState
C->A: Commit
C->B: Commit
***:  Verify group state
```

## Update

```
A:    Create group
B->A: KeyPackage
A->B: Welcome
A->B: Update, Commit
***:  Verify group state
```

## Remove

```
A:    Create group
B->A: KeyPackage
C->A: KeyPackage
A->B: Welcome
A->C: Welcome
A->B: Remove(B), Commit 
***:  Verify group state
```

## External PSK

```
A:    Create group
B->A: KeyPackage
A->B: Welcome
A->B: PSK, Commit
***:  Verify group state
```

## Resumption

```
A:    Create group
B->A: KeyPackage
A->B: Welcome
A->B: Welcome(resumption PSK)
***:  Verify group state
```

## ReInit

```
A:    Create group
B->A: KeyPackage
A->B: Welcome
A->B: ReInit(new group ID, ciphersuite)
A->B: KeyPackage(new ciphersuite)
B->A: Welcome(new group ID, reinit PSK)
***:  Verify group state
```

## Large Group, Full Lifecycle

* Create group
* Group creator adds the first M members
* Until group size reaches N members, a randomly-chosen group member adds a new
  member
* All members update
* While the group size is >1, a randomly-chosen group member removes a
  randomly-chosen other group member

