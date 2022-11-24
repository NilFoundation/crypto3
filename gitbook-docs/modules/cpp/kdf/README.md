# Introduction # {#kdf_introduction}

@tableofcontents

The Crypto3.Kdf library extends the Nil Foundation's cryptography suite and provides a set of key derivation functions
implemented in way C++ standard library implies: concepts, algorithms, predictable behavior, latest standard features
support and clean architecture without compromising security and performance.

Crypto3.Kdf consists of several parts to review:

* [Manual](@ref kdf_manual).
* [Implementation](@ref kdf_impl).
* [Concepts](@ref kdf_concepts).

## Dependencies ## {#kdf_dependencies}

Internal dependencies:

1. [Crypto3.Block](https://github.com/nilfoundation/block.git)
2. [Crypto3.Hash](https://github.com/nilfoundation/hash.git)
3. [Crypto3.Mac](https://github.com/nilfoundation/mac.git)

External dependencies:

1. [Boost](https://boost.org) (>= 1.58)
