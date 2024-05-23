# Introduction # {#pkmodes_introduction}

@tableofcontents

The Crypto3.PkModes library extends the =nil; Foundation's cryptography suite and provides a set of modes for
 public key cryptography schemes defined in pubkey library (e.g. threshold) implemented in way C++ standard library
  implies: concepts
 , algorithms, predictable
  behavior, latest standard features support and clean architecture without compromising security and performance.
 
Crypto3.Modes consists of several parts to review:
* [Manual](@ref pkmodes_manual).
* [Implementation](@ref pkmodes_impl).
* [Concepts](@ref pkmodes_concepts).

## Dependencies ## {#pkmodes_dependencies}

Internal dependencies:

1. [Crypto3.Pubkey](https://github.com/nilfoundation/pubkey.git)
2. [Crypto3.Pkpad](https://github.com/nilfoundation/pkpad.git)

Outer dependencies:
1. [Boost](https://boost.org) (>= 1.58)