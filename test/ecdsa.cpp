//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE ecdsa_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>

#include <nil/crypto3/pubkey/ecdsa.hpp>

#include <nil/crypto3/algebra/curves/secp_r1.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/pkpad/emsa/emsa1.hpp>

#include <nil/crypto3/hash/sha2.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data;
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )";
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os << std::hex << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")";
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<typename curves::secp_r1<256>::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename curves::secp_r1<256>::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::secp_k1<256>::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename curves::secp_k1<256>::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
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

BOOST_AUTO_TEST_SUITE(ecdsa_test_suite)

BOOST_AUTO_TEST_CASE(ecdsa_range_sign) {
    using curve_type = algebra::curves::secp256r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using hash_type = hashes::sha2<256>;
    using padding_type = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::algebraic_random_device<scalar_field_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_type, generator_type>;
    using signature_type = typename pubkey::public_key<policy_type>::signature_type;

    generator_type key_gen;
    pubkey::private_key<policy_type> privkey(key_gen());

    std::string text = "Hello, world!";
    std::vector<std::uint8_t> text_bytes(text.begin(), text.end());
    signature_type sig = sign<policy_type>(text_bytes, privkey);
    bool result = verify<policy_type>(text_bytes, sig, privkey);
    std::cout << result << std::endl;

    bool wrong_result = verify<policy_type>(text_bytes.begin(), text_bytes.end() - 1, sig, privkey);
    std::cout << wrong_result << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()