# Introduction # {#fft_introduction}

@tableofcontents

Crypto3.FFT library extends the =nil; Foundation's computer algebra system and provides a set of Fast Fourier Transforms
evaluation algorithms implemented in way C++ standard library implies: concepts, algorithms, predictable behavior,
latest standard features support and clean architecture without compromising security and performance.

Crypto3.FFT consists of several parts to review:

* [Manual](@ref fft_manual).
* [Implementation](@ref fft_impl).
* [Concepts](@ref fft_concepts).

## Background

There is currently a variety of algorithms for computing the Fast Fourier Transform (FFT) over the field of complex
numbers. For this situation, there exists many libraries, such as [FFTW](http://www.fftw.org/), that have been
rigorously developed, tested, and optimized. Our goal is to use these existing techniques and develop novel
implementations to address the more interesting case of FFT in finite fields. We will see that in many instances, these
algorithms can be used for the case of finite fields, but the construction of FFT in finite fields remains, in practice,
challenging.

Consider a finite field _F_ with _2^m_ elements. We can define a discrete Fourier transform by choosing a _2^m − 1_ root
of unity _ω ∈ F_. Operating over the complex numbers, there exists a variety of FFT algorithms, such as
the [Cooley-Tukey algorithm](http://en.wikipedia.org/wiki/Cooley%E2%80%93Tukey_FFT_algorithm) along with its variants,
to choose from. And in the case that _2^m - 1_ is prime - consider the Mersenne primes as an example - we can turn to
other algorithms, such as [Rader's algorithm](http://en.wikipedia.org/wiki/Rader%27s_FFT_algorithm)
and [Bluestein's algorithm](http://en.wikipedia.org/wiki/Bluestein%27s_FFT_algorithm). In addition, if the domain size
is an extended power of two or the sum of powers of two, variants of the radix-2 FFT algorithms can be employed to
perform the computation.

However, in a finite field, there may not always be a root of unity. If the domain size is not as mentioned, then one
can consider adjoining roots to the field. Although, there is no guarantee that adjoining such a root to the field can
render the same performance benefits, as it would produce a significantly larger structure that could cancel out
benefits afforded by the FFT itself. Therefore, one should consider other algorithms which continue to perform better
than the naïve evaluation.

## Domains

Given a domain size, the library will determine and perform computations over the best-fitted domain. Ideally, it is
desired to perform evaluation and interpolation over a radix-2 FFT domain, however, this may not always be possible.
Thus, the library provides the arithmetic and geometric sequence domains as fallback options, which we show to perform
better than naïve evaluation.

|               | Basic Radix-2 | Extended Radix-2 | Step Radix-2 |  Arithmetic Sequence | Geometric Sequence |
|---------------|:-------------:|:----------------:|:------------:|:--------------------:|:------------------:|
| Evaluation    |  O(n log n)   |    O(n log n)    |  O(n log n)  | M(n) log(n) + O(M(n)) |    2M(n) + O(n)    |
| Interpolation |  O(n log n)   |    O(n log n)    |  O(n log n)  | M(n) log(n) + O(M(n)) |    2M(n) + O(n)    |

### Radix-2 FFTs

The radix-2 FFTs are comprised of three domains: basic, extended, and step radix-2. The radix-2 domain implementations
make use of pseudocode from [CLRS 2n Ed, pp. 864].

#### Basic radix-2 FFT

The basic radix-2 FFT domain has size _m = 2^k_ and consists of the _m_-th roots of unity. The domain uses the standard
FFT algorithm and inverse FFT algorithm to perform evaluation and interpolation. Multi-core support includes
parallelizing butterfly operations in the FFT operation.

#### Extended radix-2 FFT

The extended radix-2 FFT domain has size _m = 2^(k + 1)_ and consists of the _m_-th roots of unity, union a coset of
these roots. The domain performs two _basic\_radix2\_FFT_ operations for evaluation and interpolation in order to
account for the extended domain size.

#### Step radix-2 FFT

The step radix-2 FFT domain has size _m = 2^k + 2^r_ and consists of the _2^k_-th roots of unity, union a coset of _2^r_
-th roots of unity. The domain performs two _basic\_radix2\_FFT_ operations for evaluation and interpolation in order to
account for the extended domain size.

### Arithmetic sequence

The arithmetic sequence domain is of size _m_ and is applied for more general cases. The domain applies a basis
conversion algorithm between the monomial and the Newton bases. Choosing sample points that form an arithmetic
progression, _a\_i = a\_1 + (i - 1)*d_, allows for an optimization of computation over the monomial basis, by using the
special case of Newton evaluation and interpolation on an arithmetic progression, see \[BS05\].

### Geometric sequence

The geometric sequence domain is of size _m_ and is applied for more general cases. The domain applies a basis
conversion algorithm between the monomial and the Newton bases. The domain takes advantage of further simplications to
Newton evaluation and interpolation by choosing sample points that form a geometric progression, _a\_n = r^(n-1)_, see
\[BS05\].

## Dependencies ## {#fft_dependencies}

Internal dependencies:

1. [=nil; Algebra](https://github.com/nilfoundation/algebra.git)

Outer dependencies:

1. [Boost (optional)](https://boost.org) (>= 1.58)