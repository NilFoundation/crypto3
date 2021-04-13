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
#include <nil/crypto3/pubkey/modes/algorithm/create_key.hpp>

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

BOOST_AUTO_TEST_CASE(threshold_bls_feldman_self_test) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;
    using bls_variant = bls_mps_ro_variant<curve_type, hash_type>;
    using base_scheme_type = bls<bls_variant, bls_basic_scheme>;
    using mode_type = modes::threshold<base_scheme_type, feldman_sss, nop_padding>;
    using scheme_type = typename mode_type::scheme_type;
    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using no_key_type = no_key_ops<scheme_type>;
    using sss_pubkey_no_key_type = typename privkey_type::sss_public_key_no_key_ops_type;

    std::size_t n = 20;
    std::size_t t = 10;

    //===========================================================================
    // dealer creates participants keys and its public key
    typename sss_pubkey_no_key_type::coeffs_type coeffs = sss_pubkey_no_key_type::get_poly(t, n);
    typename sss_pubkey_no_key_type::public_coeffs_type public_coeffs =
        sss_pubkey_no_key_type::get_public_coeffs(coeffs);
    typename sss_pubkey_no_key_type::public_coeffs_type public_coeffs_wrong(public_coeffs.begin(),
                                                                            public_coeffs.end() - 1);
    auto [PK, privkeys] = nil::crypto3::create_key<scheme_type>(coeffs, n);

    //===========================================================================
    // participants should check received shares before key creating
    std::vector<privkey_type> verified_privkeys;
    typename sss_pubkey_no_key_type::shares_type verified_shares =
        nil::crypto3::deal_shares<typename privkey_type::sss_public_key_group_type>(coeffs, n);
    for (auto &s : verified_shares) {
        verified_privkeys.emplace_back(nil::crypto3::create_key<scheme_type>(public_coeffs, s, n));
        BOOST_CHECK(verified_privkeys.back().verify_key(public_coeffs));
        BOOST_CHECK(!verified_privkeys.back().verify_key(public_coeffs_wrong));
    }

    //===========================================================================
    // participants sign messages and verify its signatures
    std::vector<typename privkey_type::part_signature_type> part_signatures;
    for (auto &sk : privkeys) {
        part_signatures.emplace_back(nil::crypto3::sign<mode_type>(msg, sk));
        BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(msg, part_signatures.back(), sk)));
    }

    //===========================================================================
    // threshold number of participants aggregate partial signatures
    typename no_key_type::signature_type sig =
        nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.begin() + t);
    BOOST_CHECK(static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig, PK)));

    //===========================================================================
    // less than threshold number of participants cannot aggregate partial signatures
    typename no_key_type::signature_type wrong_sig =
        nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.begin() + t - 1);
    BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<mode_type>(msg, wrong_sig, PK)));
}

BOOST_AUTO_TEST_CASE(threshold_bls_pedersen_self_test) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;
    using bls_variant = bls_mps_ro_variant<curve_type, hash_type>;
    using base_scheme_type = bls<bls_variant, bls_basic_scheme>;
    using mode_type = modes::threshold<base_scheme_type, pedersen_dkg, nop_padding>;
    using scheme_type = typename mode_type::scheme_type;
    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using no_key_type = no_key_ops<scheme_type>;
    using sss_pubkey_group_type = typename privkey_type::sss_public_key_group_type;
    using sss_pubkey_no_key_type = typename privkey_type::sss_public_key_no_key_ops_type;

    std::size_t n = 20;
    std::size_t t = 10;

    //===========================================================================
    // every participant generates polynomial

    std::vector<typename sss_pubkey_no_key_type::coeffs_type> P_polys;
    std::generate_n(std::back_inserter(P_polys), n, [t, n]() { return sss_pubkey_no_key_type::get_poly(t, n); });

    //===========================================================================
    // each participant calculates public values representing coefficients of its polynomial,
    // then he broadcasts these values

    std::vector<typename sss_pubkey_no_key_type::public_coeffs_type> P_public_polys;
    std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_public_polys),
                   [](const auto &poly_i) { return sss_pubkey_no_key_type::get_public_coeffs(poly_i); });

    //===========================================================================
    // every participant generates shares for each participant in group,
    // which he then transmits to the intended parties

    std::vector<typename sss_pubkey_no_key_type::shares_type> P_generated_shares;
    std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_generated_shares), [n, t](const auto &poly_i) {
        return static_cast<typename sss_pubkey_no_key_type::shares_type>(
            nil::crypto3::deal_shares<sss_pubkey_group_type>(poly_i, n));
    });

    std::vector<std::vector<typename sss_pubkey_no_key_type::share_type>> P_received_shares(n);
    for (auto &i_generated_shares : P_generated_shares) {
        for (auto it = i_generated_shares.begin(); it != i_generated_shares.end(); it++) {
            P_received_shares.at(it->first - 1).emplace_back(*it);
        }
    }

    //===========================================================================
    // each participant check received share and create key

    std::vector<pubkey_type> PKs;
    std::vector<privkey_type> privkeys;
    for (auto &shares : P_received_shares) {
        auto [PK_temp, privkey] = nil::crypto3::create_key<scheme_type>(P_public_polys, shares, n);
        PKs.emplace_back(PK_temp);
        privkeys.emplace_back(privkey);
    }

    //===========================================================================
    // participants sign messages and verify its signatures
    std::vector<typename privkey_type::part_signature_type> part_signatures;
    for (auto &sk : privkeys) {
        part_signatures.emplace_back(nil::crypto3::sign<mode_type>(msg, sk));
        BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(msg, part_signatures.back(), sk)));
    }

    //===========================================================================
    // threshold number of participants aggregate partial signatures
    typename no_key_type::signature_type sig =
        nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.begin() + t);
    BOOST_CHECK(static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig, PKs.back())));

    //===========================================================================
    // less than threshold number of participants cannot aggregate partial signatures
    typename no_key_type::signature_type wrong_sig =
        nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.begin() + t - 1);
    BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<mode_type>(msg, wrong_sig, PKs.back())));
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
    using sss_pubkey_no_key_type = typename privkey_type::sss_public_key_no_key_ops_type;

    std::size_t n = 20;
    std::size_t t = 10;

    auto i = 1;
    auto j = 1;
    typename privkey_type::sss_public_key_no_key_ops_type::weights_type weights;
    std::generate_n(std::inserter(weights, weights.end()), n, [&i, &j, &t]() {
        j = j >= t ? 1 : j;
        return typename privkey_type::sss_public_key_no_key_ops_type::weight_type(i++, j++);
    });

    //===========================================================================
    // dealer creates participants keys and its public key
    typename sss_pubkey_no_key_type::coeffs_type coeffs = sss_pubkey_no_key_type::get_poly(t, n);
    auto [PK, privkeys] = nil::crypto3::create_key<scheme_type>(coeffs, weights);

    //===========================================================================
    // participants sign messages and verify its signatures
    std::vector<typename privkey_type::part_signature_type> part_signatures;
    for (auto &sk : privkeys) {
        part_signatures.emplace_back(
            nil::crypto3::sign<mode_type>(msg.begin(), msg.end(), weights.begin(), weights.end(), sk));
        BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(msg.begin(), msg.end(), weights.begin(),
                                                                           weights.end(), part_signatures.back(), sk)));
    }

    //===========================================================================
    // confirmed group of participants aggregate partial signatures
    typename no_key_type::signature_type sig =
        nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.end());
    BOOST_CHECK(static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig, PK)));

    //===========================================================================
    // not confirmed group of participants cannot aggregate partial signatures
    typename no_key_type::signature_type wrong_sig =
        nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.end() - 1);
    BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<mode_type>(msg, wrong_sig, PK)));

    //===========================================================================
    // threshold number of participants sign messages and verify its signatures

    std::vector<typename privkey_type::part_signature_type> part_signatures_t;
    typename privkey_type::sss_public_key_no_key_ops_type::weights_type confirmed_weights;
    std::vector<privkey_type> confirmed_keys;
    auto it_weight_t = privkeys.begin();
    auto weight = 0;
    while (true) {
        weight += it_weight_t->get_weight();
        if (weight >= t) {
            confirmed_keys.emplace_back(*it_weight_t);
            confirmed_weights.emplace(it_weight_t->get_index(), weights.at(it_weight_t->get_index()));
            it_weight_t++;
            break;
        }
        confirmed_keys.emplace_back(*it_weight_t);
        confirmed_weights.emplace(it_weight_t->get_index(), weights.at(it_weight_t->get_index()));
        it_weight_t++;
    }

    for (auto &sk : confirmed_keys) {
        part_signatures_t.emplace_back(nil::crypto3::sign<mode_type>(msg.begin(), msg.end(), confirmed_weights.begin(),
                                                                     confirmed_weights.end(), sk));
        BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(
            msg.begin(), msg.end(), confirmed_weights.begin(), confirmed_weights.end(), part_signatures_t.back(), sk)));
    }

    //===========================================================================
    // threshold number of participants aggregate partial signatures

    typename no_key_type::signature_type sig_t =
        nil::crypto3::aggregate<mode_type>(part_signatures_t.begin(), part_signatures_t.end());
    BOOST_CHECK(static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig_t, PK)));

    //===========================================================================
    // less than threshold number of participants sign messages and verify its signatures

    std::vector<typename privkey_type::part_signature_type> part_signatures_less_t;
    typename privkey_type::sss_public_key_no_key_ops_type::weights_type confirmed_weights_less_t;
    std::vector<privkey_type> confirmed_keys_less_t;
    auto it_weight_less_t = privkeys.begin();
    auto weight_less_t = 0;
    while (true) {
        weight_less_t += it_weight_less_t->get_weight();
        if (weight_less_t >= t) {
            break;
        }
        confirmed_keys_less_t.emplace_back(*it_weight_less_t);
        confirmed_weights_less_t.emplace(it_weight_less_t->get_index(), weights.at(it_weight_less_t->get_index()));
        it_weight_t++;
    }

    for (auto &sk : confirmed_keys_less_t) {
        part_signatures_less_t.emplace_back(nil::crypto3::sign<mode_type>(
            msg.begin(), msg.end(), confirmed_weights_less_t.begin(), confirmed_weights_less_t.end(), sk));
        BOOST_CHECK(static_cast<bool>(
            nil::crypto3::part_verify<mode_type>(msg.begin(), msg.end(), confirmed_weights_less_t.begin(),
                                                 confirmed_weights_less_t.end(), part_signatures_less_t.back(), sk)));
    }

    //===========================================================================
    // less than threshold number of participants cannot aggregate partial signatures

    typename no_key_type::signature_type sig_less_t =
        nil::crypto3::aggregate<mode_type>(part_signatures_less_t.begin(), part_signatures_less_t.end());
    BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig_less_t, PK)));
}

BOOST_AUTO_TEST_SUITE_END()