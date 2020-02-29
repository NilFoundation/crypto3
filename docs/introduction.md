# Message Authentication Codes Introduction # {#mac_introduction}

The Crypto3.MAC library extends the Nil Foundation's cryptography suite and provides a set of key derivation
 functions implemented in way C++ standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean architecture without compromising security and performance.
 
Crypto3.MAC consists of several parts to review:
* [Manual](@ref mac_manual).
* [Implementation](@ref mac_impl).
* [Concepts](@ref mac_concepts).

## Dependencies ## {#mac_dependencies}

Internal dependencies:

1. [Crypto3.Block](https://github.com/nilfoundation/block.git)
2. [Crypto3.Hash](https://github.com/nilfoundation/hash.git)
3. [Crypto3.Modes](https://github.com/nilfoundation/modes.git)

Outer dependencies:
1. [Boost](https://boost.org) (>= 1.58)