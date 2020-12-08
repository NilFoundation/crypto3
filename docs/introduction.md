# Introduction # {#hashes_introduction}

@tableofcontents

Crypto3.Hash library extends the =nil Crypto3 C++ cryptography suite and provides a set of hashes implemented in way C++
standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean
architecture without compromising security and performance.

Crypto3.Hash consists of several parts to review:

* [Manual](@ref hashes_manual).
* [Implementation](@ref hashes_impl).
* [Concepts](@ref hashes_concepts).

## Dependencies ## {#hashes_dependencies}

Internal dependencies:

1. [Crypto3.Block](https://github.com/nilfoundation/block.git)
2. [Crypto3.Codec](https://github.com/nilfoundation/codec.git)

External dependencies:

1. [Boost](https://boost.org) (>= 1.58)