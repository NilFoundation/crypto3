# Implementation # {#algebra_impl}

@tableofcontents

The key idea of `algebra` is to provide usefull interfaces for basic cryptography math. It's based on NilFoundation fork of 
nil::crypto3::multiprecision and boost::integer modules as backend so that it can be used with boost cpp_int, gmp or other backends.

We expanded nil::crypto3::multiprecision with `modular_adaptor`, which is actually a multi-precision number by some modular. It contains 
modular number-specific algorithms using Montgomery representation. It also supports compile-time computations, because it gives 
us opportunity to implement algebra constructions as constexpr.

For our purposes we needed the opportunity to use field and curve arithmetic in compile time, what became possible thanks to 
compile-time `modular_adaptor`.

Algebra library consists of several modules listed below:

1. Fields arithmetic
2. Elliptic curves arithmetic
3. Pairings on elliptic curves
4. Multiexponentiation algorithm (will be part of some other module after a while)
5. Matricies and vectors

This separation defines the implementation architecture.



## Fields Architecture ## {#fields_architecture}

Fields were meant to be a wrapper over `multiprecision` module and concept of `modular_adaptor` number. So it basically consist 
of several parts listed below:

1. Field Policies
2. Field Extensions (e.g. Fp2, Fp4)
3. Field Parameters
4. Field Element Algorithms, which are actually wrappers over the `multiprecision` operations.

@dot
digraph fields_arch {
bgcolor="#222222"
rankdir="TB"
node [shape="box"]

  a [label="Field Policies" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_policies"];
  b [label="Field Extensions" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_extensions"];
  c [label="Field Parameters" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_parameters"];
  d [label="Field Element Algorithms" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_element_algorithms"];
  
  a -> b;
  b -> c;
  c -> d;
}
@enddot

### Field Policies ### {#field_policies}

A field policy describes its essential parameters such as `modulus`, `arity` or `mul_generator` - multiply generator. 

### Field Extensions ### {#field_extensions}

For the purposes of effictive field/elliptic curve operations and pairings evaluation fields are arranged as a field tower.

For example, this is the tower used for `bn128` and `bls12_381` operations and pairings evaluation:

Fp -> Fp2 -> Fp6 -> Fp12;

@dot
digraph fp12_2over3over2_arch {
bgcolor="#222222"
rankdir="TB"
node [shape="box"]

  a [label="Fp12" color="#F5F2F1" fontcolor="#F5F2F1"];
  b [label="Fp6" color="#F5F2F1" fontcolor="#F5F2F1"];
  c [label="Fp2" color="#F5F2F1" fontcolor="#F5F2F1"];
  d [label="Fp" color="#F5F2F1" fontcolor="#F5F2F1"];
  
  a -> b;
  b -> c;
  c -> d;
}
@enddot

There are also the following towers implemented:

Fp -> Fp3 -> Fp6 -> Fp12;

@dot
digraph fp12_2over2over3_arch {
bgcolor="#222222"
rankdir="TB"
node [shape="box"]

  a [label="Fp12" color="#F5F2F1" fontcolor="#F5F2F1"];
  b [label="Fp6" color="#F5F2F1" fontcolor="#F5F2F1"];
  c [label="Fp3" color="#F5F2F1" fontcolor="#F5F2F1"];
  d [label="Fp" color="#F5F2F1" fontcolor="#F5F2F1"];
  
  a -> b;
  b -> c;
  c -> d;
}
@enddot

Fp -> Fp2 -> Fp4 -> Fp12;

@dot
digraph fp12_3over2over2_arch {
bgcolor="#222222"
rankdir="TB"
node [shape="box"]

  a [label="Fp12" color="#F5F2F1" fontcolor="#F5F2F1"];
  b [label="Fp4" color="#F5F2F1" fontcolor="#F5F2F1"];
  c [label="Fp2" color="#F5F2F1" fontcolor="#F5F2F1"];
  d [label="Fp" color="#F5F2F1" fontcolor="#F5F2F1"];
  
  a -> b;
  b -> c;
  c -> d;
}
@enddot

### Field Parameters ### {#field_parameters}

Other field parameters are kept in the specific structures. All this structures inherit from basic `params` structure, containing all the 
basic parameters.

For example, `extension_params` structure keeps all the parameters needed for field and field extensions arithmetical operation evaluations.

### Field Element Algorithms ### {#field_element_algorithms}

Field element corresponds an element of the field and has all the needed methods and overloaded arithmetic operators. The corresponding 
algorithms are also defined here. As the backend they use now Boost::multiprecision, but it can be easily changed.

## Elliptic Curves Architecture ## {#curves_architecture}

Curves were build upon the `fields`. So it basically consist of several parts listed below:

1. Curve Policies
2. Curve g1, g2 group element arithmetic
3. Basic curve policies

@dot
digraph curves_arch {
bgcolor="#222222"
rankdir="TB"
node [shape="box"]

  a [label="Curve Policies" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref curve_policies"];
  b [label="Curve Element Algorithms" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref curve_element_algorithms"];
  c [label="Basic curve policies" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref basic_curve_policies"];
  
  a -> b;
  b -> c;
}
@enddot

### Curve Policies ### {#curve_policies}

A curve policy describes its parameters such as base field modulus `p`, scalar field modulus `q`, group element types `g1_type` and `g2_type`. 
It also contains `pairing_policy` type, needed for comfortable usage of curve pairing.

### Curve Element Algorithms ### {#curve_element_algorithms}

Curve element corresponds an point of the curve and has all the needed methods and overloaded arithmetic operators. The corresponding algorithms 
are based on the underlying field algorithms are also defined here.

### Basic Curve Policies ### {#basic_curve_policies}

Main reason for existence of basic policyis is that we need some of it params using in group element and pairing arithmetic. 
So it contains such parameters that are needed by group element arithmetic e.g. coeffs `a` and `b` or generator coordinates `x`, `y`. 
It also contains all needed information about the underlying fields. 

## Pairing Architecture ## {#pairing_architecture}

Pairing module consist of some internal functions and frontend interface templated by Elliptic Curve.
