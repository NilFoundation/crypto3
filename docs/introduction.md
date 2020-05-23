# Introduction # {#fft_introduction}

@tableofcontents

CAS.FFT library extends the =nil; Foundation's computer algebra system and provides a set of Fast Fourier Transforms evaluation algorithms
 implemented in way C++ standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean architecture without compromising security and performance.
 
CAS.FFT consists of several parts to review:
* [Manual](@ref vdf_manual).
* [Implementation](@ref vdf_impl).
* [Concepts](@ref vdf_concepts).

## Dependencies ## {#fft_dependencies}

Internal dependencies:

None

Outer dependencies:
1. [Boost (optional)](https://boost.org) (>= 1.58)

## What is a VDF?

A Verifiable Delay Function (VDF) is a function that requires substantial time
to evaluate (even with a polynomial number of parallel processors) but can be
very quickly verified as correct. VDFs can be used to construct randomness
beacons with multiple applications in a distributed network environment. By
introducing a time delay during evaluation, VDFs prevent malicious actors from
influencing output. The output cannot be differentiated from a random number
until the final result is computed.  See <https://eprint.iacr.org/2018/712.pdf>
for more details.