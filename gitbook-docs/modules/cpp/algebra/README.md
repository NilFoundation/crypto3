---
description: Crypto3.Algebra module
---

# Algebra

Crypto3.Algebra provides useful interfaces for basic cryptography math. It's based on NilFoundation fork of Boost.Multiprecision so that it can be used with boost cpp\_int, gmp or other back-ends. It library is stateless for most part and&#x20;

Along with finite field arithmetic, the library also provides linear algebra computation/constructs for matrices/scalars/vectors which can be resolved at compile time which are handy for constructions like algebraic hashes.

The library can be further sub-divided into the following parts :&#x20;

* [Curves](manual/curves.md) - Elliptic curve base classes
* [Fields](implementation/field.md) -  Finite field elements and extension fields for elliptic curves with and field arithmetic.
* [Pairings](manual/pairings.md) - Bi-linear parings for efficient computation
* [Matrix](manual/matrix.md) - Compile time matrix operations on vectors/scalars
* [Multi-Exponentiation](manual/multi-exponentiation.md) - Multi-exponentiation algorithms for field elements





##



