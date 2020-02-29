# Key Derivation Functions Introduction # {#kdf_introduction}

The Crypto3.KDF library extends the Nil Foundation's cryptography suite and provides a set of key derivation
 functions implemented in way C++ standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean architecture without compromising security and performance.
 
Crypto3.KDF consists of several parts to review:
* [Manual](@ref kdf_manual).
* [Implementation](@ref kdf_impl).
* [Concepts](@ref kdf_concepts).

## Dependencies ## {#kdf_dependencies}

Internal dependencies:

1. Crypto3.Block
2. Crypto3.Hash
2. Crypto3.MAC

Outer dependencies:
1. Boost (>= 1.58)