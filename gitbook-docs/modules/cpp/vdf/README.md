# Vdf



Crypto3.VDF library extends the =nil;Foundation's cryptography suite and provides a set of verifiable delay functions implemented in the way the C++ standard library implies concepts, algorithms, predictable behaviour, latest standard features support and clean architecture without compromising security and performance.

Crypto3.VDF consists of several parts to review:

* Manual
* Implementation
* Concepts

## Dependencies  <a href="#vdf_dependencies" id="vdf_dependencies"></a>

Internal dependencies:

None

Outer dependencies:

1. [Boost (optional)](https://boost.org) (>= 1.58)

## What is a VDF?

A Verifiable Delay Function (VDF) is a function that requires substantial time to evaluate (even with a polynomial number of parallel processors) but can be very quickly verified as correct. VDFs can be used to construct randomness beacons with multiple applications in a distributed network environment. VDFs prevent malicious actors from influencing the output by introducing a time delay during evaluation. The output cannot be differentiated from a random number until the final result is computed. See [https://eprint.iacr.org/2018/712.pdf](https://eprint.iacr.org/2018/712.pdf) for more details.
