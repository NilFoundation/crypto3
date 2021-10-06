//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE secret_sharing_test

#include <algorithm>
#include <iterator>
#include <functional>
#include <utility>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/pubkey/secret_sharing/shamir.hpp>
#include <nil/crypto3/pubkey/secret_sharing/feldman.hpp>
#include <nil/crypto3/pubkey/secret_sharing/pedersen.hpp>
#include <nil/crypto3/pubkey/secret_sharing/weighted_shamir.hpp>

#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_share.hpp>
#include <nil/crypto3/pubkey/algorithm/reconstruct_secret.hpp>
#include <nil/crypto3/pubkey/algorithm/deal_share.hpp>
// #include <nil/crypto3/pubkey/algorithm/recover_polynomial.hpp>

using namespace nil::crypto3::algebra;
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
template<typename T>
class TD;

// TODO: add verification of wrong values
BOOST_AUTO_TEST_SUITE(secret_sharing_base_functional_self_tests)

BOOST_AUTO_TEST_CASE(feldman_sss) {
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type<>;
    using scheme_type = nil::crypto3::pubkey::feldman_sss<group_type>;

    using shares_dealing_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<shares_dealing_policy<scheme_type>>::type;
    using share_verification_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<share_verification_policy<scheme_type>>::type;
    using secret_reconstructing_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<secret_reconstructing_policy<scheme_type>>::type;

    using shares_dealing_acc_set = shares_dealing_accumulator_set<shares_dealing_isomorphic_mode>;
    using shares_dealing_acc = typename boost::mpl::front<typename shares_dealing_acc_set::features_type>::type;
    using share_verification_acc_set = share_verification_accumulator_set<share_verification_isomorphic_mode>;
    using share_verification_acc = typename boost::mpl::front<typename share_verification_acc_set::features_type>::type;
    using secret_reconstructing_acc_set = reconstructing_accumulator_set<secret_reconstructing_isomorphic_mode>;
    using secret_reconstructing_acc =
        typename boost::mpl::front<typename secret_reconstructing_acc_set::features_type>::type;

    auto t = 5;
    auto n = 10;

    //===========================================================================
    // shares dealing

    // TODO: add public functions for that operations
    auto coeffs = scheme_type::get_poly(t, n);
    auto pub_coeffs = scheme_type::get_public_coeffs(coeffs);

    // deal_shares(rng)
    typename shares_dealing_isomorphic_mode::result_type shares = nil::crypto3::deal_shares<scheme_type>(coeffs, n);
    // deal_shares(first, last)
    typename shares_dealing_isomorphic_mode::result_type shares1 =
        nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n);
    // deal_shares(rng, acc)
    shares_dealing_acc_set deal_shares_acc(n, nil::crypto3::accumulators::threshold_value = t);
    nil::crypto3::deal_shares<scheme_type>(coeffs, deal_shares_acc);
    typename shares_dealing_isomorphic_mode::result_type shares2 =
        boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc);
    // deal_shares(first, last, acc)
    shares_dealing_acc_set deal_shares_acc1(n, nil::crypto3::accumulators::threshold_value = t);
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), deal_shares_acc1);
    typename shares_dealing_isomorphic_mode::result_type shares3 =
        boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc1);
    // deal_shares(rng, out)
    // TODO: output shares in output iterator by elements, do not write vector of shares in output iterator
    std::vector<typename shares_dealing_isomorphic_mode::result_type> shares_out;
    nil::crypto3::deal_shares<scheme_type>(coeffs, n, std::back_inserter(shares_out));
    // deal_shares(first, last, out)
    // TODO: output shares in output iterator by elements, do not write vector of shares in output iterator
    std::vector<typename shares_dealing_isomorphic_mode::result_type> shares_out1;
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n, std::back_inserter(shares_out1));

    BOOST_CHECK(shares == shares1);
    BOOST_CHECK(shares == shares2);
    BOOST_CHECK(shares == shares3);
    BOOST_CHECK(shares == shares_out.back());
    BOOST_CHECK(shares == shares_out1.back());

    //===========================================================================
    // each participant check its share using accumulator

    std::size_t i = 1;
    for (const auto &s_i : shares) {
        // verify_share(rng)
        BOOST_CHECK(static_cast<bool>(
            nil::crypto3::verify_share<scheme_type>(pub_coeffs, static_cast<public_share_sss<scheme_type>>(s_i))));
        // verify_share(first, last)
        BOOST_CHECK(
            static_cast<bool>(nil::crypto3::verify_share<scheme_type>(pub_coeffs.begin(), pub_coeffs.end(), s_i)));
        // verify_share(rng, acc)
        share_verification_acc_set verify_share_acc(s_i);
        BOOST_CHECK(boost::accumulators::extract_result<share_verification_acc>(
            nil::crypto3::verify_share<scheme_type>(pub_coeffs, verify_share_acc)));
        // verify_share(first, last, acc)
        share_verification_acc_set verify_share_acc1(s_i);
        BOOST_CHECK(boost::accumulators::extract_result<share_verification_acc>(
            nil::crypto3::verify_share<scheme_type>(pub_coeffs.begin(), pub_coeffs.end(), verify_share_acc1)));
        // verify_share(rng, out)
        std::vector<bool> res_out;
        nil::crypto3::verify_share<scheme_type>(pub_coeffs, s_i, std::back_inserter(res_out));
        BOOST_CHECK(res_out.back());
        // verify_share(first, last, out)
        std::vector<bool> res_out1;
        nil::crypto3::verify_share<scheme_type>(pub_coeffs.begin(), pub_coeffs.end(), s_i,
                                                std::back_inserter(res_out1));
        BOOST_CHECK(res_out1.back());
    }

    //===========================================================================
    // reconstructing secret using accumulator

    // reconstruct_secret(rng)
    secret_sss<scheme_type> secret = nil::crypto3::reconstruct_secret<scheme_type>(shares);
    // reconstruct_secret(first, last)
    secret_sss<scheme_type> secret1 = nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), shares.end());
    // reconstruct_secret(rng, acc)
    secret_reconstructing_acc_set reconstruct_secret_acc;
    secret_sss<scheme_type> secret_acc = boost::accumulators::extract_result<secret_reconstructing_acc>(
        nil::crypto3::reconstruct_secret<scheme_type>(shares, reconstruct_secret_acc));
    // reconstruct_secret(first, last, acc)
    secret_reconstructing_acc_set reconstruct_secret_acc1;
    secret_sss<scheme_type> secret_acc1 = boost::accumulators::extract_result<secret_reconstructing_acc>(
        nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), shares.end(), reconstruct_secret_acc1));
    // reconstruct_secret(rng, out)
    std::vector<secret_sss<scheme_type>> secret_out;
    nil::crypto3::reconstruct_secret<scheme_type>(shares, std::back_inserter(secret_out));
    // reconstruct_secret(first, last, out)
    std::vector<secret_sss<scheme_type>> secret_out1;
    nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), shares.end(), std::back_inserter(secret_out1));
    BOOST_CHECK(coeffs.front() == secret.get_value());
    BOOST_CHECK(secret == secret1);
    BOOST_CHECK(secret1 == secret_acc);
    BOOST_CHECK(secret_acc == secret_acc1);
    BOOST_CHECK(secret_acc1 == secret_out.back());
    BOOST_CHECK(secret_out.back() == secret_out1.back());

    //===========================================================================
    // check impossibility of secret recovering with group weight less than threshold value

    secret_sss<scheme_type> wrong_secret =
        nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), [t, &shares]() {
            auto it = shares.begin();
            for (auto i = 0; i < t - 1; i++) {
                it++;
            }
            return it;
        }());
    BOOST_CHECK(coeffs.front() != wrong_secret.get_value());
}

BOOST_AUTO_TEST_CASE(shamir_weighted_sss) {
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type<>;
    using scheme_type = nil::crypto3::pubkey::weighted_shamir_sss<group_type>;

    using shares_dealing_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<shares_dealing_policy<scheme_type>>::type;
    using secret_reconstructing_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<secret_reconstructing_policy<scheme_type>>::type;

    using shares_dealing_acc_set = shares_dealing_accumulator_set<shares_dealing_isomorphic_mode>;
    using shares_dealing_acc = typename boost::mpl::front<typename shares_dealing_acc_set::features_type>::type;
    using secret_reconstructing_acc_set = reconstructing_accumulator_set<secret_reconstructing_isomorphic_mode>;
    using secret_reconstructing_acc =
        typename boost::mpl::front<typename secret_reconstructing_acc_set::features_type>::type;

    auto t = 10;
    auto n = 20;

    //===========================================================================
    // participants weights generation

    auto j = 1;
    typename scheme_type::weights_type weights;
    for (auto i = 0; i < n; ++i) {
        j = (j >= t ? 1 : j);
        weights.emplace(i + 1, j++);
    }

    typename scheme_type::weights_type weights_one;
    for (auto i = 0; i < n; ++i) {
        weights_one.emplace(i + 1, 1);
    }

    //===========================================================================
    // polynomial generation

    // TODO: add public functions for that operations
    auto coeffs = scheme_type::get_poly(t, n);
    auto pub_coeffs = scheme_type::get_public_coeffs(coeffs);

    //===========================================================================
    // default shares dealing

    // deal_shares(rng)
    typename shares_dealing_isomorphic_mode::result_type shares_one =
        nil::crypto3::deal_shares<scheme_type>(coeffs, n, weights_one);
    // deal_shares(first, last)
    typename shares_dealing_isomorphic_mode::result_type shares_one1 =
        nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n, weights_one);
    // deal_shares(rng, acc)
    shares_dealing_acc_set deal_shares_one_acc(n, nil::crypto3::accumulators::threshold_value = t,
                                               nil::crypto3::accumulators::weights = weights_one);
    nil::crypto3::deal_shares<scheme_type>(coeffs, deal_shares_one_acc);
    typename shares_dealing_isomorphic_mode::result_type shares_one2 =
        boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_one_acc);
    // deal_shares(first, last, acc)
    shares_dealing_acc_set deal_shares_one_acc1(n, nil::crypto3::accumulators::threshold_value = t,
                                                nil::crypto3::accumulators::weights = weights_one);
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), deal_shares_one_acc1);
    typename shares_dealing_isomorphic_mode::result_type shares_one3 =
        boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_one_acc1);
    // deal_shares(rng, out)
    std::vector<typename shares_dealing_isomorphic_mode::result_type> shares_one_out;
    nil::crypto3::deal_shares<scheme_type>(coeffs, n, weights_one, std::back_inserter(shares_one_out));
    // deal_shares(first, last, out)
    std::vector<typename shares_dealing_isomorphic_mode::result_type> shares_one_out1;
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n, weights_one,
                                           std::back_inserter(shares_one_out1));

    BOOST_CHECK(shares_one == shares_one1);
    BOOST_CHECK(shares_one == shares_one2);
    BOOST_CHECK(shares_one == shares_one3);
    BOOST_CHECK(shares_one == shares_one_out.back());
    BOOST_CHECK(shares_one == shares_one_out1.back());

    //===========================================================================
    // weighted shares dealing

    // deal_shares(rng)
    typename shares_dealing_isomorphic_mode::result_type shares =
        nil::crypto3::deal_shares<scheme_type>(coeffs, n, weights);
    // deal_shares(first, last)
    typename shares_dealing_isomorphic_mode::result_type shares1 =
        nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n, weights);
    // deal_shares(rng, acc)
    shares_dealing_acc_set deal_shares_acc(n, nil::crypto3::accumulators::threshold_value = t,
                                           nil::crypto3::accumulators::weights = weights);
    nil::crypto3::deal_shares<scheme_type>(coeffs, deal_shares_acc);
    typename shares_dealing_isomorphic_mode::result_type shares2 =
        boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc);
    // deal_shares(first, last, acc)
    shares_dealing_acc_set deal_shares_acc1(n, nil::crypto3::accumulators::threshold_value = t,
                                            nil::crypto3::accumulators::weights = weights);
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), deal_shares_acc1);
    typename shares_dealing_isomorphic_mode::result_type shares3 =
        boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc1);
    // deal_shares(rng, out)
    std::vector<typename shares_dealing_isomorphic_mode::result_type> shares_out;
    nil::crypto3::deal_shares<scheme_type>(coeffs, n, weights, std::back_inserter(shares_out));
    // deal_shares(first, last, out)
    std::vector<typename shares_dealing_isomorphic_mode::result_type> shares_out1;
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n, weights, std::back_inserter(shares_out1));

    BOOST_CHECK(shares == shares1);
    BOOST_CHECK(shares == shares2);
    BOOST_CHECK(shares == shares3);
    BOOST_CHECK(shares == shares_out.back());
    BOOST_CHECK(shares == shares_out1.back());

    //===========================================================================
    // reconstructing secret

    // reconstruct_secret(rng)
    secret_sss<scheme_type> secret_one = nil::crypto3::reconstruct_secret<scheme_type>(shares_one);
    // reconstruct_secret(first, last)
    secret_sss<scheme_type> secret_one1 =
        nil::crypto3::reconstruct_secret<scheme_type>(shares_one.begin(), shares_one.end());
    // reconstruct_secret(rng, acc)
    secret_reconstructing_acc_set reconstruct_secret_one_acc;
    secret_sss<scheme_type> secret_one_acc = boost::accumulators::extract_result<secret_reconstructing_acc>(
        nil::crypto3::reconstruct_secret<scheme_type>(shares_one, reconstruct_secret_one_acc));
    // reconstruct_secret(first, last, acc)
    secret_reconstructing_acc_set reconstruct_secret_one_acc1;
    secret_sss<scheme_type> secret_one_acc1 =
        boost::accumulators::extract_result<secret_reconstructing_acc>(nil::crypto3::reconstruct_secret<scheme_type>(
            shares_one.begin(), shares_one.end(), reconstruct_secret_one_acc1));
    // reconstruct_secret(rng, out)
    std::vector<secret_sss<scheme_type>> secret_one_out;
    nil::crypto3::reconstruct_secret<scheme_type>(shares_one, std::back_inserter(secret_one_out));
    // reconstruct_secret(first, last, out)
    std::vector<secret_sss<scheme_type>> secret_one_out1;
    nil::crypto3::reconstruct_secret<scheme_type>(shares_one.begin(), shares_one.end(),
                                                  std::back_inserter(secret_one_out1));
    BOOST_CHECK(coeffs.front() == secret_one.get_value());
    BOOST_CHECK(secret_one == secret_one1);
    BOOST_CHECK(secret_one1 == secret_one_acc);
    BOOST_CHECK(secret_one_acc == secret_one_acc1);
    BOOST_CHECK(secret_one_acc1 == secret_one_out.back());
    BOOST_CHECK(secret_one_out.back() == secret_one_out1.back());

    // reconstruct_secret(rng)
    secret_sss<scheme_type> secret = nil::crypto3::reconstruct_secret<scheme_type>(shares);
    // reconstruct_secret(first, last)
    secret_sss<scheme_type> secret1 = nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), shares.end());
    // reconstruct_secret(rng, acc)
    secret_reconstructing_acc_set reconstruct_secret_acc;
    secret_sss<scheme_type> secret_acc = boost::accumulators::extract_result<secret_reconstructing_acc>(
        nil::crypto3::reconstruct_secret<scheme_type>(shares, reconstruct_secret_acc));
    // reconstruct_secret(first, last, acc)
    secret_reconstructing_acc_set reconstruct_secret_acc1;
    secret_sss<scheme_type> secret_acc1 = boost::accumulators::extract_result<secret_reconstructing_acc>(
        nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), shares.end(), reconstruct_secret_acc1));
    // reconstruct_secret(rng, out)
    std::vector<secret_sss<scheme_type>> secret_out;
    nil::crypto3::reconstruct_secret<scheme_type>(shares, std::back_inserter(secret_out));
    // reconstruct_secret(first, last, out)
    std::vector<secret_sss<scheme_type>> secret_out1;
    nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), shares.end(), std::back_inserter(secret_out1));
    BOOST_CHECK(coeffs.front() == secret.get_value());
    BOOST_CHECK(secret == secret1);
    BOOST_CHECK(secret1 == secret_acc);
    BOOST_CHECK(secret_acc == secret_acc1);
    BOOST_CHECK(secret_acc1 == secret_out.back());
    BOOST_CHECK(secret_out.back() == secret_out1.back());

    //===========================================================================
    // check impossibility of secret recovering with group weight less than threshold value

    secret_sss<scheme_type> wrong_secret =
        nil::crypto3::reconstruct_secret<scheme_type>(shares.begin(), [t, &shares]() {
            auto it = shares.begin();
            auto weight = 0;
            while (true) {
                weight += it->get_value().size();
                if (weight >= t) {
                    break;
                }
                it++;
            }
            return it;
        }());
    BOOST_CHECK(coeffs.front() != wrong_secret.get_value());
}

BOOST_AUTO_TEST_CASE(pedersen_dkg) {
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type<>;
    using scheme_type = nil::crypto3::pubkey::pedersen_dkg<group_type>;

    using shares_dealing_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<shares_dealing_policy<scheme_type>>::type;
    using share_verification_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<share_verification_policy<scheme_type>>::type;
    using secret_reconstructing_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<secret_reconstructing_policy<scheme_type>>::type;
    using share_dealing_isomorphic_mode =
        typename modes::isomorphic<scheme_type>::template bind<share_dealing_policy<scheme_type>>::type;

    using shares_dealing_acc_set = shares_dealing_accumulator_set<shares_dealing_isomorphic_mode>;
    using shares_dealing_acc = typename boost::mpl::front<typename shares_dealing_acc_set::features_type>::type;
    using share_verification_acc_set = share_verification_accumulator_set<share_verification_isomorphic_mode>;
    using share_verification_acc = typename boost::mpl::front<typename share_verification_acc_set::features_type>::type;
    using secret_reconstructing_acc_set = reconstructing_accumulator_set<secret_reconstructing_isomorphic_mode>;
    using secret_reconstructing_acc =
        typename boost::mpl::front<typename secret_reconstructing_acc_set::features_type>::type;
    using share_dealing_acc_set = share_dealing_accumulator_set<share_dealing_isomorphic_mode>;
    using share_dealing_acc = typename boost::mpl::front<typename share_dealing_acc_set::features_type>::type;

    auto t = 5;
    auto n = 10;

    //===========================================================================
    // every participant generates polynomial

    // TODO: add public functions for that operations
    std::vector<typename scheme_type::coeffs_type> P_polys;
    std::generate_n(std::back_inserter(P_polys), n, [t, n]() { return scheme_type::get_poly(t, n); });

    //===========================================================================
    // each participant calculates public values representing coefficients of its polynomial,
    // then he broadcasts these values

    // TODO: add public functions for that operations
    std::vector<typename scheme_type::public_coeffs_type> P_public_polys;
    std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_public_polys),
                   [](const auto &poly_i) { return scheme_type::get_public_coeffs(poly_i); });

    //===========================================================================
    // every participant generates shares for each participant in group,
    // which he then transmits to the intended parties

    std::vector<typename shares_dealing_isomorphic_mode::result_type> P_generated_shares;
    std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_generated_shares), [n](const auto &poly_i) {
        return static_cast<typename shares_dealing_isomorphic_mode::result_type>(
            nil::crypto3::deal_shares<scheme_type>(poly_i, n));
    });

    //===========================================================================
    // each participant verify shares received from other parties

    for (auto i = 1; i <= n; i++) {
        for (const auto &j_share : P_generated_shares[i - 1]) {
            BOOST_CHECK(static_cast<bool>(nil::crypto3::verify_share<scheme_type>(P_public_polys[i - 1], j_share)));
            auto wrong_P_public_polys = P_public_polys[i - 1];
            wrong_P_public_polys[0] = scheme_type::public_coeff_type::zero();
            BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify_share<scheme_type>(wrong_P_public_polys, j_share)));
        }
    }

    //===========================================================================
    // each participant calculate its share as sum of shares generated by others for him

    std::vector<share_dealing_acc_set> P_shares_acc;
    for (std::size_t i = 1; i <= n; ++i) {
        P_shares_acc.emplace_back(share_dealing_acc_set(i));
    }
    for (const auto &i_generated_shares : P_generated_shares) {
        for (const auto &j_share : i_generated_shares) {
            nil::crypto3::deal_share<scheme_type>(std::vector {j_share}, P_shares_acc[j_share.get_index() - 1]);
        }
    }
    std::vector<share_sss<scheme_type>> P_shares;
    for (auto &P_share_acc : P_shares_acc) {
        P_shares.emplace_back(
            nil::crypto3::pubkey::accumulators::extract::deal_share<share_dealing_isomorphic_mode>(P_share_acc));
    }

    //===========================================================================
    // calculation of public values representing coefficients of real polynomial

    // TODO: implement public interface
    std::vector<typename scheme_type::public_coeff_type> P_public_poly(t, scheme_type::public_coeff_type::zero());
    for (const auto &i_poly : P_public_polys) {
        auto it1 = P_public_poly.begin();
        auto it2 = i_poly.begin();
        while (it1 != P_public_poly.end() && it2 != i_poly.end()) {
            *it1 = *it1 + *it2;
            ++it1;
            ++it2;
        }
    }

    //===========================================================================
    // verification of participants shares

    for (const auto &i_share : P_shares) {
        BOOST_CHECK(static_cast<bool>(nil::crypto3::verify_share<scheme_type>(P_public_poly, i_share)));
        auto wrong_P_public_polys = P_public_poly;
        wrong_P_public_polys[0] = scheme_type::public_coeff_type::zero();
        BOOST_CHECK(!static_cast<bool>(nil::crypto3::verify_share<scheme_type>(wrong_P_public_polys, i_share)));
    }

    //===========================================================================
    // calculation of actual secret
    // (which is not calculated directly by the parties in real application)

    typename scheme_type::coeff_type secret = scheme_type::coeff_type::zero();
    for (const auto &i_poly : P_polys) {
        secret = secret + i_poly.front();
    }

    secret_sss<scheme_type> reconstructed_secret =
        nil::crypto3::reconstruct_secret<scheme_type>(P_shares.begin(), P_shares.begin() + t);
    BOOST_CHECK_EQUAL(reconstructed_secret.get_value(), secret);

    //===========================================================================
    // check impossibility of secret recovering with group weight less than threshold value

    secret_sss<scheme_type> wrong_secret =
        nil::crypto3::reconstruct_secret<scheme_type>(P_shares.begin(), P_shares.begin() + t - 1);
    BOOST_CHECK_NE(wrong_secret.get_value(), secret);
}

BOOST_AUTO_TEST_SUITE_END()
