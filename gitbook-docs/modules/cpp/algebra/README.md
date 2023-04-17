---
description: Crypto3.Algebra module
---

# Algebra

Crypto3.Algebra provides useful interfaces for basic cryptography math. It's based on the =nil; Foundation's fork of Boost.Multiprecision so that it can be used with boost cpp\_int, gmp or other back-ends. The library is stateless for the most part.

Along with finite field arithmetic, the library also provides linear algebra computation/constructs for matrices/scalars/vectors. These can be resolved at compile time and are handy for constructions like algebraic hashes.

The library can be further subdivided into the following parts :

* [Curves](manual/curves.md) - Elliptic curve base classes
* [Fields](implementation/field.md) - Finite field elements and extension fields for elliptic curves with field arithmetic.
* [Pairings](manual/pairings.md) - Bi-linear parings for efficient computation
* [Matrix](manual/matrix.md) - Compile time matrix operations on vectors/scalars
* [Multi-Exponentiation](manual/multi-exponentiation.md) - Multi-exponentiation algorithms for field elements

##
