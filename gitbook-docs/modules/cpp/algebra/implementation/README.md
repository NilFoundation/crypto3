# implementation

We expanded Boost.Multiprecision with `modular_adaptor`, which is actually a multi-precision number by some modular. It contains modular number-specific algorithms using Montgomery representation. It also supports compile-time computations because it gives us the opportunity to implement algebra constructions as constexpr.

For crypto3, we needed to use field and curve arithmetic in compile time, which became possible thanks to compile-time `modular_adaptor`.
