//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE bls_signature_pubkey_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/multiprecision/cpp_int.hpp>

// #include <nil/crypto3/pubkey/detail/bls/bls_basic_policy.hpp>
// #include <nil/crypto3/pubkey/detail/bls/bls_core_functions.hpp>
#include <nil/crypto3/pubkey/bls.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <vector>
#include <string>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace boost::multiprecision;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )" << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os << std::hex << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<typename curves::bls12<381>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<381>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g2_type::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

const std::string BasicSchemeDstMss_str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const std::vector<std::uint8_t> BasicSchemeDstMss(BasicSchemeDstMss_str.begin(), BasicSchemeDstMss_str.end());

const std::string BasicSchemeDstMps_str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const std::vector<std::uint8_t> BasicSchemeDstMps(BasicSchemeDstMps_str.begin(), BasicSchemeDstMps_str.end());

BOOST_AUTO_TEST_SUITE(bls_signature_manual_tests)

// BOOST_AUTO_TEST_CASE(core_functions_test) {
//     using curve_type = bls12_381;
//     using hash_type = sha2<256>;
//     using key_policy_type = detail::bls_policy_mps_ro<bls12_381, hash_type>;
//     using core_functions = detail::bls_core_functions<key_policy_type>;
//
//     using private_key_type = typename key_policy_type::private_key_type;
//     using number_type = typename key_policy_type::number_type;
//     using signature_type = typename key_policy_type::signature_type;
//
//     private_key_type sk = private_key_type(number_type("454086624460063511464984254936031011189294057512315937409637584344757371137"));
//     std::vector<std::uint8_t> msg = {3, 1, 4, 1, 5, 9};
//     signature_type sig = core_functions::core_sign(sk, msg, BasicSchemeDst);
//     print_fp2_curve_group_element(std::cout, sig);
// }

BOOST_AUTO_TEST_CASE(bls_schemes_test) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;

    using policy_type = bls_signature_mps_ro_policy<curve_type, hash_type>;
    using basic_scheme = modes::bls_basic_scheme<policy_type>;

    using private_key_type = typename policy_type::policy_type::private_key_type;
    using public_key_type = typename policy_type::policy_type::public_key_type;
    using signature_type = typename policy_type::policy_type::signature_type;
    using modulus_type = typename policy_type::policy_type::modulus_type;

    private_key_type sk = private_key_type(modulus_type("38080721612557889248860097181231592324315794185661552620565714489512711535193"));
    // print_field_element(std::cout, sk);
    const std::string msg_str = "hello foo";
    const std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());

    signature_type sig = basic_scheme::sign(sk, msg, BasicSchemeDstMps);
    print_fp2_curve_group_element(std::cout, sig.to_affine_coordinates());
}

BOOST_AUTO_TEST_SUITE_END()
