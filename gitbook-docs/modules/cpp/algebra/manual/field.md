# field

`field` type is a generic type which is an extension of `boost::multiprecision` . It is optimised for arithmetic in the finite field.

All fields implemented in algebra library conform to the concept of a field type. A field must conform to the field traits defined in `algebra/include/nil/crypto3/algebra/type_traits.hpp`

Field is generally specialised per curve and it holds the domain and other curve specific constants.

## Usage

Fields are defined under the namespace `nil::crypto3::algebra::fields` and header need to be included ex: `nil/crypto3/algebra/fields/<curve>/scalar_field.hpp`

A field can be instantiated as

```cpp
field<254> //254 - is the modulus Bits
```

Specialised for curves as base fields and scalar fields are usually defined as

```cpp
//fields/secp/secp_k1
struct secp_k1_base_field<256> : public field<256>
struct secp_k1_scalar_field<256> : public field<256>
```

### Example#1

Below we see a specialisation of a field type to a bls12\_base\_field.

```cpp
template<std::size_t Version>
struct bls12_base_field;

template<>
struct bls12_base_field<381> : public field<381> {
	typedef field<381> policy_type;

	constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
	typedef typename policy_type::integral_type integral_type;

	typedef typename policy_type::extended_integral_type extended_integral_type;

	constexpr static const std::size_t number_bits = policy_type::number_bits;

	constexpr static const integral_type modulus =
		0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB_cppui381;

	typedef typename policy_type::modular_backend modular_backend;
	constexpr static const modular_params_type modulus_params = modulus;
	typedef nil::crypto3::multiprecision::number<
		nil::crypto3::multiprecision::backends::modular_adaptor<
			modular_backend,
			nil::crypto3::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
		modular_type;

	typedef typename detail::element_fp<params<bls12_base_field<381>>> value_type;

	constexpr static const std::size_t value_bits = modulus_bits;
	constexpr static const std::size_t arity = 1;
};
```

## Field Extensions

Following field extensions are already built in and are used in the suite.

* FP2
* FP3
* FP4
* FP6\_2OVER3
* FP6\_3OVER2
* FP12\_2OVER3OVER2

Each of the above define a type trait which is then exhibited by specialisations.

### Example#1

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

In the above BLS base field example we can see an `element_fp` type used which adheres to traits of `fp`

```cpp
typedef typename detail::element_fp<params<bls12_base_field<381>>> value_type;
```
