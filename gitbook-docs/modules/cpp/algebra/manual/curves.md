---
description: Crypto3.Algebra Elliptic curves
---

# curves

The following elliptic curves are implemented&#x20;

* Barreto-Naehrig
* Babyjubjub
* BLS12 variants
* Brainpool
* [Curve25519](https://datatracker.ietf.org/doc/html/rfc7748#section-4.1)
* ed25519
* Edwards
* GOST
* Jubjub
* mnt4/mnt6
* NIST P-192/P-224/P-384/P-521
* [Pallas](https://zips.z.cash/protocol/protocol.pdf#pallasandvesta)
* secpk1
* secpr1
* secpv1
* sm2p
* vesta
* X9.62

All curves implemented in algebra library conform to the concept of a curve type. They can be swapped in any policies or schemes which they are taken as input in the crypto3 suite. A curve must conform to the traits defined in `algebra/include/nil/crypto3/algebra/type_traits.hpp`

Curves variants defined are defined as `typedef` so it is suggested to check this before writing out an extension.

## Usage

Curves are defined under the namespace `nil::crypto3::algebra::curves` and header need to be included ex: `nil/crypto3/algebra/curves/<curve_name.hpp>`



A curve type is `policy` passed as a parameter to a cryptographic scheme. The template type can be instantiated as follows by including the relevant header:

```cpp
#include <nil/crypto3/algebra/curves/bls12.hpp>
using namespace nil::crypto3::algebra;
using curve_bls_381 = curves::bls12_381; // As an existing typedef 
using curve_bls_377 = curves::bls12<377> // Explicityly passing variant
```

Curves encompass one or more `field` types definitions (via `typedef` )which respect the curve specific constants and domain. Curves are generally used along with the [pubkey](https://github.com/NilFoundation/crypto3-pubkey) library which enables a user to create public/private keys and perform cryptographic operations.

### Example #1&#x20;

The class below describes a BLS curve which accepts a template parameter for variants. &#x20;

```cpp
template<std::size_t Version>
class bls12 {

	typedef detail::bls12_types<Version> policy_type;

public:
	typedef typename policy_type::base_field_type base_field_type;
	typedef typename policy_type::scalar_field_type scalar_field_type;

	template<typename Coordinates = coordinates::jacobian_with_a4_0,
			 typename Form = forms::short_weierstrass>
	using g1_type = typename detail::bls12_g1<Version, Form, Coordinates>;

	template<typename Coordinates = coordinates::jacobian_with_a4_0,
			 typename Form = forms::short_weierstrass>
	using g2_type = typename detail::bls12_g2<Version, Form, Coordinates>;

	constexpr static const bool has_affine_pairing = false;

	typedef typename policy_type::gt_field_type gt_type;
};

typedef bls12<381> bls12_381;
typedef bls12<377> bls12_377;

```

### Example#2

```cpp
using curve_type = curves::bls12_381;
using scheme_type = bls<bls_default_public_params<>, bls_mss_ro_version, bls_basic_scheme, curve_type>;
```
