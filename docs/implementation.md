# Implementation # {#algebra_impl}

@tableofcontents

Algebra library consists of several modules listed below:

1. Fields arithmetic
2. Elliptic curves arithmetic
3. Pairings on elliptic curves
4. Multiexponentiation algorithm (will be part of some other module after a while)

This separation defines the implementation architecture.

Some particular cases merge accumulation step with encryption step. This means 
block gets encrypted as far as it is found filled with enough data.  

## Fields Architecture ## {#fields_architecture}

Fields module architecture consists of several parts listed below:

1. Field Extensions (e.g. Fp, Fp2, Fp4)
2. Field Policies
3. Field Parameters
4. Field Element Algorithms
5. Field Double-precision Algorithms


@dot
digraph fields_arch {
bgcolor="#222222"
rankdir="TB"
node [shape="box"]

  a [label="Field Extensions" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_extensions"];
  b [label="Field Policies" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_policies"];
  c [label="Field Parameters" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_parameters"];
  d [label="Field Element Algorithms" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_element_algorithms"];
  e [label="Field Double-precision Algorithms" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref field_double_precision_algorithms"];
  
  a -> b;
  b -> c;
  c -> d;
  d -> e;
}
@enddot

### Field Extensions ### {#field_extensions}

For the purposes of effictive field/elliptic curve operations and pairings evaluation fields are arranged as a field tower.

For example, this is the tower used for bn128 and bls12_381 oparations and pairings evaluation:

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

### Field Policies ### {#field_policies}

A field policy describes its essential parameters such as `modulus`, `arity` or `mul_generator` - multiply generator. 

### Field Parameters ### {#field_parameters}

Other field parameters are kept in the specific structures. All this structures inherit from basic `params` structure, containing all the basic parameters.

For example, `extension_params` structure keeps all the parameters needed for field and field extensions arithmetical operation evaluations.

### Field Element Algorithms ### {#field_element_algorithms}

Field element corresponds an element of the field and has all the needed methods and overloaded arithmetic operators. The corresponding algorithms are also defined here. As the backend they use now Boost::multiprecision, but it can be easily changed.

### Field Double-precision Algorithms ### {#field_double_precision_algorithms}

For some elliptic curve operations and pairing algorithms its easier to provide intermediate evaluations using double-precision numbers. For these purposes we have specific structure with all the needed methods.

## Elliptic Curves Architecture ## {#curves_architecture}

Fields module architecture consists of several parts listed below:

1. Curve Type Policies (NIST/Weierstrass)
2. Curve Policies
3. Curve Element Algorithms

@dot
digraph curves_arch {
bgcolor="#222222"
rankdir="TB"
node [shape="box"]

  a [label="Curve Type Policies" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref curve_type_policies"];
  b [label="Curve Policies" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref curve_policies"];
  c [label="Curve Element Algorithms" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref curve_element_algorithms"];
  
  a -> b;
  b -> c;
}
@enddot

### Curve Type Policies ### {#curve_type_policies}

Curves implemented at the moment are one of two types: NIST curves (such as p521 curve) and Weierstrass curves (such as BLS12-381 or BN-128). Curve type policy describes parameters general for all the curves of the particular type.

We also intend to generalize curve algorithms by making it curve type-determinable.

### Curve Policies ### {#curve_policies}

A field policy describes its parameters such as modulus `p`, coeffs `a` and `b` or generator coordinates `x`, `y`. It also contains elliptic curve `value_type` defining curve element type. 

### Curve Element Algorithms ### {#curve_element_algorithms}

Curve element corresponds an point of the curve and has all the needed methods and overloaded arithmetic operators. The corresponding algorithms based on the underlying field algorithms are also defined here.

## Pairing Architecture ## {#pairing_architecture}

Pairing module consist of some internal functions and frontend interface templated by Elliptic Curve.
