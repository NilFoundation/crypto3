# Usage {#pubkey_usage_manual}

@tableofcontents

## Quick Start

The easiest way to use Crypto3.Pubkey library is to use an algorithm with implicit state usage. Following example pubkey
with BLS:

```cpp

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/pubkey/bls.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;

    using curve_type = curves::bls12_381;
    using scheme_type = bls<bls_default_public_params<>, bls_mps_ro_version, bls_basic_scheme, curve_type>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;

int main(int argc, const char * argv[]) {
    std::string msg_str = "Hello, World!\n";

    std::cout << msg_str;

    std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
    privkey_type sk = privkey_type(random_element<typename _privkey_type::field_type>());

    signature_type sig = ::nil::crypto3::sign(msg, sk);
    pubkey_type &pubkey = sk;

    return !(nil::crypto3::verify(msg, sig, pubkey));
}
```

## Stateful Processing

In case of public-key scheme source data accumulation necessity is present, following example demonstrates
[accumulator](@ref accumulator_set) usage:

```cpp
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/pubkey/bls.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;

    using curve_type = curves::bls12_381;
    using scheme_type = bls<bls_default_public_params<>, bls_mps_ro_version, bls_basic_scheme, curve_type>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using modulus_type = typename _privkey_type::modulus_type;

    using signing_isomorphic_mode =
    typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
        template bind<::nil::crypto3::pubkey::signing_policy<Scheme>>::type;
    using verification_isomorphic_mode =
    typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
        template bind<::nil::crypto3::pubkey::verification_policy<scheme_type>>::type;

    using verification_acc_set = verification_accumulator_set<verification_isomorphic_mode>;
    using verification_acc = typename boost::mpl::front<typename verification_acc_set::features_type>::type;

    using signing_acc_set = signing_accumulator_set<signing_isomorphic_mode>;
    using signing_acc = typename boost::mpl::front<typename signing_acc_set::features_type>::type;  

int main(int argc, const char * argv[]) {
    std::string msg_str = "Hello, World!\n";

    std::cout << msg_str;

    std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
    
    privkey_type sk = privkey_type(random_element<typename _privkey_type::field_type>());
    pubkey_type &pubkey = sk;
    signing_acc_set sign_acc(sk);
    
    nil::crypto3::sign<scheme_type>(msg, sign_acc);
    
    signature_type sig = boost::accumulators::extract_result<signing_acc>(sign_acc);
    verification_acc_set verify_acc(pubkey, nil::crypto3::accumulators::signature = sig);
    
    return !(nil::crypto3::verify<scheme_type>(msg, verify_acc));
}
```
