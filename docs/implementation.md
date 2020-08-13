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

## Architecture Overview ## {#algebra_architecture}

### Fields Architecture ### {#fields_architecture}

Fields module architecture consists of several parts listed below:

1. Field Extensions (e.g. Fp, Fp2, Fp4)
2. Field Policies
3. Field Parameters
4. Field Element Algorithms
5. Field Double-precision Algorithms


@dot
digraph block_cipher_arch {
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

### Elliptic Curves Architecture ### {#curves_architecture}

Fields module architecture consists of several parts listed below:

1. Curve Type Policies (NIST/Weierstrass)
2. Curve Policies
3. Curve Element Algorithms

@dot
digraph block_cipher_arch {
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


### Pairing Architecture ### {#pairing_architecture}

Pairing module consist of some internal functions and frontend interface templated by Elliptic Curve.
