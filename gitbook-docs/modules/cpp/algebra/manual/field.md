---
description: Crypto3.Field manual
---

# field elements

## Field

`field` type is a generic type which is an extension of `boost::multiprecision`.

All fields implemented in the algebra library conform to the concept of a field type. A field must conform to the field traits defined in `algebra/include/nil/crypto3/algebra/type_traits.hpp`

The field consists of a set of stateless policies and, with the extension,  `modular_adaptor` allows for finite field arithmetic. The field is generally extended per curve, and it holds the domain and other curve-specific constants.

If you wish to use elliptic curve-related arithmetic, use \_\_ `element_fp.`

If you wish to perform multi-precision arithmetic unrelated to curves, see `crypto3::multiprecision`

### Usage

Fields are defined under the namespace `nil::crypto3::algebra::fields` and header need to be included ex: `nil/crypto3/algebra/fields/field.hpp`

A field can be instantiated as:

```cpp
field<254> //254 - is the modulus Bits
```

Specialised for curves as `base` fields and `scalar` fields are usually defined as

```cpp
//fields/secp/secp_k1
struct secp_k1_base_field<256> : public field<256>
struct secp_k1_scalar_field<256> : public field<256>
```

#### Example#1

In this example, we see finite field element arithmetic performed on filed elements over`BLS12-381` curve.

```cpp
#include <iostream>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>

using namespace nil::crypto3::algebra::fields;
using namespace nil::crypto3::multiprecision;

int main() {
    auto f1 = bls12_fq<381>::value_type(0x1);
    auto f2 = bls12_fq<381>::value_type(0x2);

    //Addition
    auto add  = f1 + f2;

    //Subtraction
    auto sub = f1 - f2;

    //Multiplication
    auto mul  = f1 * f2;

    //Equality
    if (f1 == f2){
        std::cout<<"Equal field elements\n";
    } else
    {
        std::cout<<"Inequality of field elements\n";
    }

    //Inverse
    auto inv = f1.inversed();

    //negative
    auto f1neg = -f1;

    // Power
    auto f1pow3 = f1.pow(3);

    //Square (& square root)
    auto f1sq = f1.squared().sqrt();

    if (f1 == f1sq){
        std::cout <<"Matching field elements\n";
    }

    return 0;
}
```

## Field Extensions

Following field extensions are already built in and are used in the suite.

* FP2
* FP3
* FP4
* FP6\_2OVER3
* FP6\_3OVER2
* FP12\_2OVER3OVER2

Each of the above defines a type trait which is then exhibited by specialisations.

### Usage

#### Example#1

```cpp
template<typename BaseField>
struct fp2 {
	typedef BaseField base_field_type;
	typedef base_field_type policy_type;
	typedef detail::fp2_extension_params<policy_type> extension_policy;
	typedef typename extension_policy::underlying_field_type underlying_field_type;

	constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
	typedef typename policy_type::integral_type integral_type;

	typedef typename policy_type::extended_integral_type extended_integral_type;

	constexpr static const std::size_t number_bits = policy_type::number_bits;
	typedef typename policy_type::modular_type modular_type;
	typedef typename policy_type::modular_backend modular_backend;

	constexpr static const integral_type modulus = policy_type::modulus;

	typedef typename detail::element_fp2<extension_policy> value_type;

	constexpr static const std::size_t arity = 2;
	constexpr static const std::size_t value_bits = arity * modulus_bits;
};
```

In the above BLS base field example, we can see an `element_fp` type used which adheres to traits of `fp`

```cpp
typedef typename detail::element_fp<params<bls12_base_field<381>>> value_type;
```
