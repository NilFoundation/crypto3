# Introduction # {#fft_introduction}

@tableofcontents

Crypto3.FFT library extends the =nil; Foundation's computer algebra system and provides a set of Fast Fourier Transforms
evaluation algorithms implemented in way C++ standard library implies: concepts, algorithms, predictable behavior,
latest standard features support and clean architecture without compromising security and performance.

Crypto3.FFT consists of several parts to review:

* [Manual](@ref fft_manual).
* [Implementation](@ref fft_impl).
* [Concepts](@ref fft_concepts).

## Dependencies ## {#fft_dependencies}

Internal dependencies:

1. [=nil; Algebra](https://github.com/nilfoundation/algebra.git)

Outer dependencies:

1. [Boost (optional)](https://boost.org) (>= 1.58)