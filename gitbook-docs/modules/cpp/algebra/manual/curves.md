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

Curves encompass one or more `field elements` types definitions (via `typedef` )which respect the curve specific constants and domain. Curves are generally used along with the [pubkey](https://github.com/NilFoundation/crypto3-pubkey) library which enables a user to create public/private keys and perform cryptographic operations.

### Example #1&#x20;

Some curves support additional transformations for co-ordinates ex : babyjubjub supports transformation from `twisted_edwards` to `montgomery`

```cpp
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::algebra::fields;
using namespace nil::crypto3::multiprecision;

//Define curve policy - type & co-ordinates
using policy_type = curves::babyjubjub::g1_type<curves::coordinates::affine, curves::forms::montgomery>;

// Get underlying representation types from policy
typedef typename policy_type::field_type::value_type field_value_type;
typedef typename policy_type::value_type curve_element_type;

int main() {

    auto x_ = field_value_type(0x1);
    auto y_ = field_value_type(0x2);

    auto p = curve_element_type (x_,y_);

    p.to_affine();

    //Convert to twisted edwards from montgomery
    auto p_ed = p.to_twisted_edwards();

    //Convert to montgomery from twisted edwards
    auto p_mt = p_ed.to_montgomery();

    return 0;
}
```

### Example#2

This example shows how a curve can be used in a cryptographic scheme , based on which a user can create public/private keys & sign message (see `pubkey`)

```cpp
using curve_type = curves::bls12_381;
using scheme_type = bls<bls_default_public_params<>, bls_mss_ro_version, bls_basic_scheme, curve_type>;
```



Also see examples in [field elements ](field.md)section.
