//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE secret_sharing_test

#include <algorithm>
#include <iterator>
#include <functional>
#include <utility>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/detail/dkg/pedersen.hpp>
#include <nil/crypto3/pubkey/scheme_state.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

using namespace nil::crypto3::algebra;
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
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

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

BOOST_AUTO_TEST_SUITE(base_functional_test)

BOOST_AUTO_TEST_CASE(feldman_sss_self_scheme) {
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type;
    using scheme_type = nil::crypto3::pubkey::detail::feldman_sss<group_type>;
    using shares_dealing_acc_type = shares_dealing_accumulator_set<scheme_type>;
    using share_verification_acc_type = share_verification_accumulator_set<scheme_type>;

    auto t = 5;
    auto n = 10;

    auto coeffs = scheme_type::get_poly(t, n);
    auto pub_coeffs = scheme_type::get_public_poly(coeffs);
    auto shares = scheme_type::deal_shares(coeffs, n);

    //===========================================================================
    // check shares dealing accumulator

    shares_dealing_acc_type deal_shares_acc(n);
    for (const auto &c : coeffs) {
        deal_shares_acc(c);
    }
    auto acc_shares = nil::crypto3::accumulators::extract::scheme<scheme_type>(deal_shares_acc);
    BOOST_CHECK_EQUAL(shares, acc_shares);

    //===========================================================================
    // each participant check its share using accumulator
    std::size_t i = 1;
    for (const auto &s_i : shares) {
        share_verification_acc_type verification_acc(typename scheme_type::indexed_public_element_type(i++, scheme_type::get_public_element(s_i)));
        for (const auto &pc : pub_coeffs) {
            verification_acc(pc);
        }
        BOOST_CHECK(nil::crypto3::accumulators::extract::scheme<scheme_type>(verification_acc));
    }

    //===========================================================================

    BOOST_CHECK_EQUAL(scheme_type::recover_secret(
                          t, std::vector<typename decltype(shares)::value_type>(shares.begin(), shares.begin() + t)),
                      coeffs[0]);
    BOOST_CHECK_NE(scheme_type::recover_secret(
                       std::vector<typename decltype(shares)::value_type>(shares.begin(), shares.begin() + t - 1)),
                   coeffs[0]);

    BOOST_CHECK(scheme_type::verify_share(shares[0], 1, pub_coeffs));
}

BOOST_AUTO_TEST_CASE(pedersen_dkg_self_scheme) {
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type;
    using scheme_type = nil::crypto3::pubkey::detail::pedersen_dkg<group_type>;

    auto t = 10;
    auto n = 20;

    //===========================================================================
    // every participant generates polynomial

    std::vector<typename scheme_type::private_elements_type> P_polys;
    std::generate_n(std::back_inserter(P_polys), n, [t, n]() { return scheme_type::get_poly(t, n); });

    //===========================================================================
    // each participant calculates public values representing coefficients of its polynomial,
    // then he broadcasts these values

    std::vector<typename scheme_type::public_elements_type> P_public_polys;
    std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_public_polys),
                   [](const auto &poly_i) { return scheme_type::get_public_poly(poly_i); });

    //===========================================================================
    // every participant generates shares for each participant in group,
    // which he then transmits to the intended parties

    std::vector<typename scheme_type::private_elements_type> P_generated_shares;
    std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_generated_shares),
                   [n](const auto &poly_i) { return scheme_type::deal_shares(poly_i, n); });

    //===========================================================================
    // each participant verify shares received from other parties

    for (auto i = 1; i <= n; i++) {
        for (auto j = 1; j <= n; j++) {
            BOOST_CHECK(scheme_type::verify_share(P_generated_shares[i - 1][j - 1], j, P_public_polys[i - 1]));
        }
    }

    //===========================================================================
    // each participant calculate its share as sum of shares generated by others for him

    std::vector<typename scheme_type::private_elements_sum_acc_type> P_shares_acc(n);
    for (const auto &i_generated_shares : P_generated_shares) {
        auto it1 = P_shares_acc.begin();
        auto it2 = i_generated_shares.begin();
        while (it1 != P_shares_acc.end() && it2 != i_generated_shares.end()) {
            (*it1)(*it2);
            it1++;
            it2++;
        }
    }
    std::vector<typename scheme_type::private_element_type> P_shares;
    std::transform(P_shares_acc.begin(), P_shares_acc.end(), std::back_inserter(P_shares), [](auto &&acc) {
        return scheme_type::reduce_shares(std::forward<typename scheme_type::private_elements_sum_acc_type>(acc));
    });

    //===========================================================================
    // calculation of public values representing coefficients of real polynomial

    std::vector<typename scheme_type::public_elements_sum_acc_type> P_public_coeffs_acc(t);
    for (const auto &i_poly : P_public_polys) {
        auto it1 = P_public_coeffs_acc.begin();
        auto it2 = i_poly.begin();
        while (it1 != P_public_coeffs_acc.end() && it2 != i_poly.end()) {
            (*it1)(*it2);
            it1++;
            it2++;
        }
    }
    std::vector<typename scheme_type::public_element_type> P_public_poly;
    std::transform(P_public_coeffs_acc.begin(), P_public_coeffs_acc.end(), std::back_inserter(P_public_poly),
                   [](auto &&acc) {
                       return scheme_type::reduce_public_coeffs(
                           std::forward<typename scheme_type::public_elements_sum_acc_type>(acc));
                   });

    //===========================================================================
    // verification of participants shares

    for (auto i = 1; i <= n; i++) {
        BOOST_CHECK(scheme_type::verify_share(P_shares[i - 1], i, P_public_poly));
    }

    //===========================================================================
    // calculation of actual secret
    // (which is not calculated directly by the parties in real application)

    typename scheme_type::private_elements_sum_acc_type secret_acc;
    for (const auto &i_poly : P_polys) {
        secret_acc(i_poly.front());
    }
    auto secret = scheme_type::reduce_shares(std::forward<typename scheme_type::private_elements_sum_acc_type>(secret_acc));

    //===========================================================================

    BOOST_CHECK_EQUAL(scheme_type::recover_secret(
                          std::vector<typename decltype(P_shares)::value_type>(P_shares.begin(), P_shares.begin() + t)),
                      secret);
    BOOST_CHECK_NE(scheme_type::recover_secret(std::vector<typename decltype(P_shares)::value_type>(
                       P_shares.begin(), P_shares.begin() + t - 1)),
                   secret);
}

BOOST_AUTO_TEST_SUITE_END()
