# Public Key Cryptography Introduction # {#pubkey_introduction}

The Crypto3.Pubkey library extends the =nil; Foundation's cryptography suite and provides a set of publib key
 schemes implemented in way C++ standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean architecture without compromising security and performance.
 
Crypto3.Pubkey consists of several parts to review:
* [Manual](@ref pubkey_manual).
* [Implementation](@ref pubkey_impl).
* [Concepts](@ref pubkey_concepts).

## Dependencies ## {#pubkey_dependencies}

Internal dependencies:

1. [Crypto3.Mac](https://github.com/nilfoundation/block.git)
2. [Crypto3.Hash](https://github.com/nilfoundation/hash.git)

Outer dependencies:
1. [Boost](https://boost.org) (>= 1.58)