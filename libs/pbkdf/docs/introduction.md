# Introduction # {#pbkdf_introduction}

@tableofcontents

The Crypto3.Pbkdf library extends the Nil Foundation's cryptography suite and provides a set of password-based key
 derivation functions implemented in way C++ standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean architecture without compromising security and performance.
 
Crypto3.Pbkdf consists of several parts to review:
* [Manual](@ref pbkdf_manual).
* [Implementation](@ref pbkdf_impl).
* [Concepts](@ref pbkdf_concepts).

## Dependencies ## {#pbkdf_dependencies}

Internal dependencies:

1. [Crypto3.Mac](https://github.com/nilfoundation/block.git)
2. [Crypto3.Hash](https://github.com/nilfoundation/hash.git)

Outer dependencies:
1. [Boost](https://boost.org) (>= 1.58)