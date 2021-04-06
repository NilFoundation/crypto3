//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE threshold_test

#include <nil/crypto3/pubkey/modes/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/part_verify.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/aggregate.hpp>
#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>

#include <nil/crypto3/pubkey/modes/threshold.hpp>

#include <nil/crypto3/pubkey/bls.hpp>

#include <nil/crypto3/pubkey/secret_sharing.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <iostream>
#include <string>
#include <cassert>
#include <unordered_map>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::pubkey;

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

const std::string msg_str = "hello foo";
const std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());

BOOST_AUTO_TEST_SUITE(threshold_self_test_suite)

BOOST_AUTO_TEST_CASE(threshold_bls_shamir_self_test) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;
    using bls_variant = bls_mps_ro_variant<curve_type, hash_type>;
    using base_scheme_type = bls<bls_variant, bls_basic_scheme>;
    using mode_type = modes::threshold<base_scheme_type, shamir_sss, nop_padding>;
    using scheme_type = typename mode_type::scheme_type;
    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using no_key_type = no_key_ops<scheme_type>;

    std::size_t n = 20;
    std::size_t t = 10;

    //===========================================================================
    // dealer creates participants keys and its public key
    auto [PK, privkeys] = key_gen<scheme_type>(t, n);
    std::vector<typename privkey_type::part_signature_type> part_signatures;

    //===========================================================================
    // participants sign messages and verify its signatures
    for (auto &sk : privkeys) {
        part_signatures.emplace_back(nil::crypto3::sign<mode_type>(msg, sk));
        // BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(msg, part_signatures.back(), sk)));
    }

    //===========================================================================
    // threshold number of participants aggregate partial signatures
    typename no_key_type::signature_type sig = nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.begin() + t);
    BOOST_CHECK(static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig, PK)));

    //===========================================================================
    // less than threshold number of participants cannot aggregate partial signatures
    typename no_key_type::signature_type wrong_sig = nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.begin() + t - 1);
    BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<mode_type>(msg, wrong_sig, PK)));
}

BOOST_AUTO_TEST_CASE(threshold_bls_weighted_shamir_test) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;
    using bls_variant = bls_mps_ro_variant<curve_type, hash_type>;
    using base_scheme_type = bls<bls_variant, bls_basic_scheme>;
    using mode_type = modes::threshold<base_scheme_type, weighted_shamir_sss, nop_padding>;
    using scheme_type = typename mode_type::scheme_type;
    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using no_key_type = no_key_ops<scheme_type>;

    std::size_t n = 20;
    std::size_t t = 10;

    auto i = 1;
    auto j = 1;
    typename privkey_type::sss_public_key_no_key_ops_type::weights_type weights;
    std::generate_n(std::inserter(weights, weights.end()), n, [&i, &j, &t]() {
        j = j >= t ? 1 : j;
        return typename privkey_type::sss_public_key_no_key_ops_type::weight_type(i++, j++);
    });

    auto privkeys = key_gen<privkey_type>(t, n, weights);


}

BOOST_AUTO_TEST_SUITE_END()