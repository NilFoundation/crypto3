//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <iostream>
#include <string>
#include <cassert>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/bls.hpp>
#include <nil/crypto3/pubkey/modes/threshold_bls.hpp>

#include <nil/crypto3/pubkey/secret_sharing/pedersen.hpp>

#include <nil/crypto3/pubkey/modes/threshold.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/part_verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>

#include <nil/crypto3/pubkey/modes/algorithm/create_key.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/part_verify.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::pubkey;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os
        // << std::hex
        << e.data;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os
        // << std::hex
        << e.data[0].data << ", " << e.data[1].data;
}

template<typename CurveGroupElement>
void print_projective_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << "( ";
    print_field_element(e.X);
    os << " : ";
    print_field_element(e.Y);
    os << " : ";
    print_field_element(e.Z);
    os << " )";
}

template<typename CurveGroupElement>
void print_jacobian_with_a4_0_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    print_projective_curve_group_element(os, e);
}

template<typename CurveGroupElement>
void print_extended_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << "( ";
    print_field_element(e.X);
    os << " : ";
    print_field_element(e.Y);
    os << " : ";
    print_field_element(e.T);
    os << " : ";
    print_field_element(e.Z);
    os << " )";
}

template<typename CurveGroupElement>
void print_affine_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << "( ";
    print_field_element(e.X);
    os << " : ";
    print_field_element(e.Y);
    os << " )";
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename CurveParams>
            struct print_log_value<curves::detail::curve_element<CurveParams, curves::forms::short_weierstrass,
                                                                 curves::coordinates::jacobian_with_a4_0>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams, curves::forms::short_weierstrass,
                                                              curves::coordinates::jacobian_with_a4_0> const &p) {
                    print_projective_curve_group_element(os, p);
                }
            };

            template<typename CurveParams>
            struct print_log_value<curves::detail::curve_element<CurveParams, curves::forms::short_weierstrass,
                                                                 curves::coordinates::affine>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams, curves::forms::short_weierstrass,
                                                              curves::coordinates::affine> const &p) {
                    print_affine_curve_group_element(os, p);
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
    using curve_type = algebra::curves::bls12_381;
    using base_scheme_type = bls<bls_default_public_params<>, bls_mps_ro_version, bls_basic_scheme, curve_type>;

    using mode_type = modes::threshold<base_scheme_type, feldman_sss>;
    using scheme_type = typename mode_type::scheme_type;
    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;

    using sss_public_key_group_type = typename pubkey_type::sss_public_key_group_type;
    using shares_dealing_processing_mode = typename pubkey::modes::isomorphic<sss_public_key_group_type>::template bind<
        pubkey::shares_dealing_policy<sss_public_key_group_type>>::type;
    using signing_processing_mode_type = typename mode_type::template bind<typename mode_type::signing_policy>::type;
    using verification_processing_mode_type =
        typename mode_type::template bind<typename mode_type::verification_policy>::type;
    using aggregation_processing_mode_type =
        typename mode_type::template bind<typename mode_type::aggregation_policy>::type;

    std::size_t n = 20;
    std::size_t t = 10;

    //===========================================================================
    // dealer creates participants keys and its public key
    // TODO: add public interface for get_poly and get_public_coeffs
    auto coeffs = sss_public_key_group_type::get_poly(t, n);
    auto public_coeffs = sss_public_key_group_type::get_public_coeffs(coeffs);

    decltype(public_coeffs) public_coeffs_wrong(public_coeffs.begin(), public_coeffs.end() - 1);
    auto [PK, privkeys] = nil::crypto3::create_key<scheme_type>(coeffs, n);

    //===========================================================================
    // participants should check received shares before key creating
    std::vector<privkey_type> verified_privkeys;
    typename shares_dealing_processing_mode::result_type verified_shares =
        nil::crypto3::deal_shares<sss_public_key_group_type>(coeffs, n);
    for (auto &s : verified_shares) {
        verified_privkeys.emplace_back(nil::crypto3::create_key<scheme_type>(public_coeffs, s, n));

        // TODO: add public interface verify_key
        BOOST_CHECK(verified_privkeys.back().verify_key(public_coeffs));
        BOOST_CHECK(!verified_privkeys.back().verify_key(public_coeffs_wrong));
    }

    //===========================================================================
    // participants sign messages and verify its signatures
    std::vector<typename privkey_type::part_signature_type> part_signatures;
    for (auto &sk : privkeys) {
        // TODO: add simplified call interface for sign
        part_signatures.emplace_back(
            nil::crypto3::sign<scheme_type, decltype(msg), signing_processing_mode_type>(msg, sk));
        BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(msg, part_signatures.back(), sk)));
        BOOST_CHECK(!static_cast<bool>(nil::crypto3::part_verify<mode_type>(
            msg, typename privkey_type::part_signature_type(part_signatures.back().get_index()), sk)));
    }

    //===========================================================================
    // threshold number of participants aggregate partial signatures
    // TODO: add simplified call interface for aggregate and verify
    typename pubkey_type::signature_type sig =
        nil::crypto3::aggregate<scheme_type, decltype(std::cbegin(part_signatures)), aggregation_processing_mode_type>(
            std::cbegin(part_signatures), std::cbegin(part_signatures) + t);
    BOOST_CHECK(static_cast<bool>(
        nil::crypto3::verify<scheme_type, decltype(msg), verification_processing_mode_type>(msg, sig, PK)));

    //===========================================================================
    // less than threshold number of participants cannot aggregate partial signatures
    // TODO: add simplified call interface for aggregate and verify
    typename pubkey_type::signature_type wrong_sig =
        nil::crypto3::aggregate<scheme_type, decltype(std::cbegin(part_signatures)), aggregation_processing_mode_type>(
            std::cbegin(part_signatures), std::cbegin(part_signatures) + t - 1);
    BOOST_CHECK(!static_cast<bool>(
        nil::crypto3::verify<scheme_type, decltype(msg), verification_processing_mode_type>(msg, wrong_sig, PK)));
}

BOOST_AUTO_TEST_CASE(threshold_bls_pedersen_self_test) {
    using curve_type = algebra::curves::bls12_381;
    using base_scheme_type = bls<bls_default_public_params<>, bls_mps_ro_version, bls_basic_scheme, curve_type>;

    using mode_type = modes::threshold<base_scheme_type, pedersen_dkg>;
    using scheme_type = typename mode_type::scheme_type;
    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;

    using sss_public_key_group_type = typename pubkey_type::sss_public_key_group_type;
    using shares_dealing_processing_mode = typename pubkey::modes::isomorphic<sss_public_key_group_type>::template bind<
        pubkey::shares_dealing_policy<sss_public_key_group_type>>::type;
    using share_dealing_processing_mode = typename pubkey::modes::isomorphic<sss_public_key_group_type>::template bind<
        pubkey::share_dealing_policy<sss_public_key_group_type>>::type;
    using signing_processing_mode_type = typename mode_type::template bind<typename mode_type::signing_policy>::type;
    using verification_processing_mode_type =
        typename mode_type::template bind<typename mode_type::verification_policy>::type;
    using aggregation_processing_mode_type =
        typename mode_type::template bind<typename mode_type::aggregation_policy>::type;

    std::size_t n = 20;
    std::size_t t = 10;

    //===========================================================================
    // every participant generates polynomial

    // TODO: add public interface for get_poly and get_public_coeffs
    std::vector<typename sss_public_key_group_type::coeffs_type> P_polys;
    std::generate_n(std::back_inserter(P_polys), n, [t, n]() { return sss_public_key_group_type::get_poly(t, n); });

    //===========================================================================
    // each participant calculates public values representing coefficients of its polynomial,
    // then he broadcasts these values

    std::vector<typename sss_public_key_group_type::public_coeffs_type> P_public_polys;
    std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_public_polys),
                   [](const auto &poly_i) { return sss_public_key_group_type::get_public_coeffs(poly_i); });

    //===========================================================================
    // every participant generates shares for each participant in group,
    // which he then transmits to the intended parties

    std::vector<typename shares_dealing_processing_mode::result_type> P_generated_shares;
    std::transform(std::cbegin(P_polys), std::cend(P_polys), std::back_inserter(P_generated_shares),
                   [n, t](const auto &poly_i) {
                       return static_cast<typename shares_dealing_processing_mode::result_type>(
                           nil::crypto3::deal_shares<sss_public_key_group_type>(poly_i, n));
                   });

    std::vector<std::vector<share_sss<sss_public_key_group_type>>> P_received_shares(n);
    for (auto &i_generated_shares : P_generated_shares) {
        for (auto it = std::cbegin(i_generated_shares); it != std::cend(i_generated_shares); it++) {
            P_received_shares.at(it->get_index() - 1).emplace_back(*it);
        }
    }

    //===========================================================================
    // each participant check received share and create key

    std::vector<pubkey_type> PKs;
    std::vector<privkey_type> privkeys;
    for (auto &shares : P_received_shares) {
        auto [PK_i, privkey] = nil::crypto3::create_key<scheme_type>(P_public_polys, shares, n);
        PKs.emplace_back(PK_i);
        privkeys.emplace_back(privkey);
    }

    //===========================================================================
    // participants sign messages and verify its signatures

    std::vector<typename privkey_type::part_signature_type> part_signatures;
    for (auto &sk : privkeys) {
        // TODO: add simplified call interface for sign
        part_signatures.emplace_back(
            nil::crypto3::sign<scheme_type, decltype(msg), signing_processing_mode_type>(msg, sk));
        BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(msg, part_signatures.back(), sk)));
        BOOST_CHECK(!static_cast<bool>(nil::crypto3::part_verify<mode_type>(
            msg, typename privkey_type::part_signature_type(part_signatures.back().get_index()), sk)));
    }

    //===========================================================================
    // threshold number of participants aggregate partial signatures

    // TODO: add simplified call interface for aggregate and verify
    typename pubkey_type::signature_type sig =
        nil::crypto3::aggregate<scheme_type, decltype(std::cbegin(part_signatures)), aggregation_processing_mode_type>(
            std::cbegin(part_signatures), std::cbegin(part_signatures) + t);
    BOOST_CHECK(static_cast<bool>(
        nil::crypto3::verify<scheme_type, decltype(msg), verification_processing_mode_type>(msg, sig, PKs.back())));

    //===========================================================================
    // less than threshold number of participants cannot aggregate partial signatures

    // TODO: add simplified call interface for aggregate and verify
    typename pubkey_type::signature_type wrong_sig =
        nil::crypto3::aggregate<scheme_type, decltype(std::cbegin(part_signatures)), aggregation_processing_mode_type>(
            std::cbegin(part_signatures), std::cbegin(part_signatures) + t - 1);
    BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<scheme_type, decltype(msg), verification_processing_mode_type>(
        msg, wrong_sig, PKs.back())));
}

// BOOST_AUTO_TEST_CASE(threshold_bls_weighted_shamir_test) {
//     using curve_type = curves::bls12_381;
//     using hash_type = sha2<256>;
//     using bls_variant = bls_mps_ro_variant<curve_type, hash_type>;
//     using base_scheme_type = bls<bls_variant, bls_basic_scheme>;
//     using mode_type = modes::threshold<base_scheme_type, weighted_shamir_sss, nop_padding>;
//     using scheme_type = typename mode_type::scheme_type;
//     using privkey_type = private_key<scheme_type>;
//     using pubkey_type = public_key<scheme_type>;
//     using no_key_type = no_key_ops<scheme_type>;
//     using sss_pubkey_no_key_type = typename privkey_type::sss_public_key_no_key_ops_type;
//
//     std::size_t n = 20;
//     std::size_t t = 10;
//
//     auto i = 1;
//     auto j = 1;
//     typename privkey_type::sss_public_key_no_key_ops_type::weights_type weights;
//     std::generate_n(std::inserter(weights, weights.end()), n, [&i, &j, &t]() {
//         j = j >= t ? 1 : j;
//         return typename privkey_type::sss_public_key_no_key_ops_type::weight_type(i++, j++);
//     });
//
//     //===========================================================================
//     // dealer creates participants keys and its public key
//     typename sss_pubkey_no_key_type::coeffs_type coeffs = sss_pubkey_no_key_type::get_poly(t, n);
//     auto [PK, privkeys] = nil::crypto3::create_key<scheme_type>(coeffs, weights);
//
//     //===========================================================================
//     // participants sign messages and verify its signatures
//     std::vector<typename privkey_type::part_signature_type> part_signatures;
//     for (auto &sk : privkeys) {
//         part_signatures.emplace_back(
//             nil::crypto3::sign<mode_type>(msg.begin(), msg.end(), weights.begin(), weights.end(), sk));
//         BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(msg.begin(), msg.end(), weights.begin(),
//                                                                            weights.end(), part_signatures.back(),
//                                                                            sk)));
//     }
//
//     //===========================================================================
//     // confirmed group of participants aggregate partial signatures
//     typename no_key_type::signature_type sig =
//         nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.end());
//     BOOST_CHECK(static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig, PK)));
//
//     //===========================================================================
//     // not confirmed group of participants cannot aggregate partial signatures
//     typename no_key_type::signature_type wrong_sig =
//         nil::crypto3::aggregate<mode_type>(part_signatures.begin(), part_signatures.end() - 1);
//     BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<mode_type>(msg, wrong_sig, PK)));
//
//     //===========================================================================
//     // threshold number of participants sign messages and verify its signatures
//
//     std::vector<typename privkey_type::part_signature_type> part_signatures_t;
//     typename privkey_type::sss_public_key_no_key_ops_type::weights_type confirmed_weights;
//     std::vector<privkey_type> confirmed_keys;
//     auto it_weight_t = privkeys.begin();
//     auto weight = 0;
//     while (true) {
//         weight += it_weight_t->get_weight();
//         if (weight >= t) {
//             confirmed_keys.emplace_back(*it_weight_t);
//             confirmed_weights.emplace(it_weight_t->get_index(), weights.at(it_weight_t->get_index()));
//             it_weight_t++;
//             break;
//         }
//         confirmed_keys.emplace_back(*it_weight_t);
//         confirmed_weights.emplace(it_weight_t->get_index(), weights.at(it_weight_t->get_index()));
//         it_weight_t++;
//     }
//
//     for (auto &sk : confirmed_keys) {
//         part_signatures_t.emplace_back(nil::crypto3::sign<mode_type>(msg.begin(), msg.end(),
//         confirmed_weights.begin(),
//                                                                      confirmed_weights.end(), sk));
//         BOOST_CHECK(static_cast<bool>(nil::crypto3::part_verify<mode_type>(
//             msg.begin(), msg.end(), confirmed_weights.begin(), confirmed_weights.end(), part_signatures_t.back(),
//             sk)));
//     }
//
//     //===========================================================================
//     // threshold number of participants aggregate partial signatures
//
//     typename no_key_type::signature_type sig_t =
//         nil::crypto3::aggregate<mode_type>(part_signatures_t.begin(), part_signatures_t.end());
//     BOOST_CHECK(static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig_t, PK)));
//
//     //===========================================================================
//     // less than threshold number of participants sign messages and verify its signatures
//
//     std::vector<typename privkey_type::part_signature_type> part_signatures_less_t;
//     typename privkey_type::sss_public_key_no_key_ops_type::weights_type confirmed_weights_less_t;
//     std::vector<privkey_type> confirmed_keys_less_t;
//     auto it_weight_less_t = privkeys.begin();
//     auto weight_less_t = 0;
//     while (true) {
//         weight_less_t += it_weight_less_t->get_weight();
//         if (weight_less_t >= t) {
//             break;
//         }
//         confirmed_keys_less_t.emplace_back(*it_weight_less_t);
//         confirmed_weights_less_t.emplace(it_weight_less_t->get_index(), weights.at(it_weight_less_t->get_index()));
//         it_weight_t++;
//     }
//
//     for (auto &sk : confirmed_keys_less_t) {
//         part_signatures_less_t.emplace_back(nil::crypto3::sign<mode_type>(
//             msg.begin(), msg.end(), confirmed_weights_less_t.begin(), confirmed_weights_less_t.end(), sk));
//         BOOST_CHECK(static_cast<bool>(
//             nil::crypto3::part_verify<mode_type>(msg.begin(), msg.end(), confirmed_weights_less_t.begin(),
//                                                  confirmed_weights_less_t.end(), part_signatures_less_t.back(),
//                                                  sk)));
//     }
//
//     //===========================================================================
//     // less than threshold number of participants cannot aggregate partial signatures
//
//     typename no_key_type::signature_type sig_less_t =
//         nil::crypto3::aggregate<mode_type>(part_signatures_less_t.begin(), part_signatures_less_t.end());
//     BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify<mode_type>(msg, sig_less_t, PK)));
// }

BOOST_AUTO_TEST_SUITE_END()