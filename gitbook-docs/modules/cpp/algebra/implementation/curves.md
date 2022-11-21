# curves

## Elliptic Curves Architecture <a href="#curves_architecture" id="curves_architecture"></a>

Curves were build upon the `fields`. So it basically consist of several parts listed below:

1. Curve Policies
2. Curve g1, g2 group element arithmetic
3. Basic curve policies

![](../../../../.gitbook/assets/image%20\(3\).png)

### ![](../../../../.gitbook/assets/image.png) <a href="#curve_policies" id="curve_policies"></a>

### &#x20;<a href="#curve_policies" id="curve_policies"></a>

### Curve Policies <a href="#curve_policies" id="curve_policies"></a>

A curve policy describes its parameters such as base field modulus `p`, scalar field modulus `q`, group element types `g1_type` and `g2_type`. It also contains `pairing_policy` type, needed for comfortable usage of curve pairing.

### Curve Element Algorithms <a href="#curve_element_algorithms" id="curve_element_algorithms"></a>

Curve element corresponds an point of the curve and has all the needed methods and overloaded arithmetic operators. The corresponding algorithms are based on the underlying field algorithms are also defined here.

### Basic Curve Policies <a href="#basic_curve_policies" id="basic_curve_policies"></a>

Main reason for existence of basic policy is is that we need some of it params using in group element and pairing arithmetic. So it contains such parameters that are needed by group element arithmetic e.g. coeffs `a` and `b` or generator coordinates `x`, `y`. It also contains all needed information about the underlying fields.
