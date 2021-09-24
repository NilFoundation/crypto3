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

#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_share.hpp>
#include <nil/crypto3/pubkey/algorithm/reconstruct_secret.hpp>
// #include <nil/crypto3/pubkey/algorithm/deal_share.hpp>
// #include <nil/crypto3/pubkey/algorithm/recover_polynomial.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << std::hex << e.data;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << std::hex << e.data[0].data << ", " << e.data[1].data;
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
            struct print_log_value<curves::detail::curve_element<CurveParams,
                                                                 curves::forms::short_weierstrass,
                                                                 curves::coordinates::jacobian_with_a4_0>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams,
                                                              curves::forms::short_weierstrass,
                                                              curves::coordinates::jacobian_with_a4_0> const &p) {
                    print_projective_curve_group_element(os, p);
                }
            };
            
            template<typename CurveParams>
            struct print_log_value<curves::detail::curve_element<CurveParams,
                                                                 curves::forms::short_weierstrass,
                                                                 curves::coordinates::affine>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams,
                                                              curves::forms::short_weierstrass,
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

    using shares_dealing_isomorphic_mode = typename modes::isomorphic<scheme_type>::template bind<shares_dealing_policy<scheme_type>>::type;
    using share_verification_isomorphic_mode = typename modes::isomorphic<scheme_type>::template bind<share_verification_policy<scheme_type>>::type;
    using secret_reconstructing_isomorphic_mode = typename modes::isomorphic<scheme_type>::template bind<secret_reconstructing_policy<scheme_type>>::type;

    using shares_dealing_acc_type = shares_dealing_accumulator_set<shares_dealing_isomorphic_mode>;
    using shares_dealing_acc = typename boost::mpl::front<typename shares_dealing_acc_type::features_type>::type;
    using share_verification_acc_type = share_verification_accumulator_set<share_verification_isomorphic_mode>;
    using share_verification_acc =
        typename boost::mpl::front<typename share_verification_acc_type::features_type>::type;
    using secret_reconstructing_acc_type = secret_reconstructing_accumulator_set<secret_reconstructing_isomorphic_mode>;
    using secret_reconstructing_acc =
        typename boost::mpl::front<typename secret_reconstructing_acc_type::features_type>::type;

    auto t = 5;
    auto n = 10;

    //===========================================================================
    // shares dealing

    // TODO: add public functions for that operations
    auto coeffs = scheme_type::get_poly(t, n);
    auto pub_coeffs = scheme_type::get_public_coeffs(coeffs);

    // deal_shares(rng)
    typename scheme_type::shares_type shares = nil::crypto3::deal_shares<scheme_type>(coeffs, n);
    // deal_shares(first, last)
    typename scheme_type::shares_type shares1 = nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n);
    // deal_shares(rng, acc)
    shares_dealing_acc_type deal_shares_acc(n, nil::crypto3::accumulators::threshold_value = t);
    nil::crypto3::deal_shares<scheme_type>(coeffs, deal_shares_acc);
    typename scheme_type::shares_type shares2 = boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc);
    // deal_shares(first, last, acc)
    shares_dealing_acc_type deal_shares_acc1(n, nil::crypto3::accumulators::threshold_value = t);
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), deal_shares_acc1);
    typename scheme_type::shares_type shares3 = boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc1);
    // deal_shares(rng, out)
    std::vector<typename scheme_type::shares_type> shares_out;
    nil::crypto3::deal_shares<scheme_type>(coeffs, n, std::back_inserter(shares_out));
    // deal_shares(first, last, out)
    std::vector<typename scheme_type::shares_type> shares_out1;
    nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n, std::back_inserter(shares_out1));

    BOOST_CHECK(shares == shares1);
    BOOST_CHECK(shares == shares2);
    BOOST_CHECK(shares == shares3);
    BOOST_CHECK(shares == shares_out.front());
    BOOST_CHECK(shares == shares_out1.front());

    //===========================================================================
    // each participant check its share using accumulator

    std::size_t i = 1;
    for (const auto &s_i : shares) {
        // verify_share(rng)
        BOOST_CHECK(static_cast<bool>(nil::crypto3::verify_share<scheme_type>(pub_coeffs, s_i)));
        // verify_share(first, last)
        BOOST_CHECK(
            static_cast<bool>(nil::crypto3::verify_share<scheme_type>(pub_coeffs.begin(), pub_coeffs.end(), s_i)));
        // verify_share(rng, acc)
        share_verification_acc_type verify_share_acc(s_i);
        BOOST_CHECK(boost::accumulators::extract_result<share_verification_acc>(
            nil::crypto3::verify_share<scheme_type>(pub_coeffs, verify_share_acc)));
        // verify_share(first, last, acc)
        share_verification_acc_type verify_share_acc1(s_i);
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

    // reconstruct(rng)
    typename scheme_type::basic_policy::secret_t secret = nil::crypto3::reconstruct<scheme_type>(shares);
    // reconstruct(first, last)
    typename scheme_type::basic_policy::secret_t secret1 =
        nil::crypto3::reconstruct<scheme_type>(shares.begin(), shares.end());
    // reconstruct(rng, acc)
    secret_reconstructing_acc_type reconstruct_secret_acc;
    typename scheme_type::basic_policy::secret_t secret_acc =
        boost::accumulators::extract_result<secret_reconstructing_acc>(
            nil::crypto3::reconstruct<scheme_type>(shares, reconstruct_secret_acc));
    // reconstruct(first, last, acc)
    secret_reconstructing_acc_type reconstruct_secret_acc1;
    typename scheme_type::basic_policy::secret_t secret_acc1 =
        boost::accumulators::extract_result<secret_reconstructing_acc>(
            nil::crypto3::reconstruct<scheme_type>(shares.begin(), shares.end(), reconstruct_secret_acc1));
    // reconstruct(rng, out)
    std::vector<typename scheme_type::basic_policy::secret_t> secret_out;
    nil::crypto3::reconstruct<scheme_type>(shares, std::back_inserter(secret_out));
    // reconstruct(first, last, out)
    std::vector<typename scheme_type::basic_policy::secret_t> secret_out1;
    nil::crypto3::reconstruct<scheme_type>(shares.begin(), shares.end(), std::back_inserter(secret_out1));
    BOOST_CHECK(coeffs.front() == secret);
    BOOST_CHECK(secret == secret1);
    BOOST_CHECK(secret1 == secret_acc);
    BOOST_CHECK(secret_acc == secret_acc1);
    BOOST_CHECK(secret_acc1 == secret_out.back());
    BOOST_CHECK(secret_out.back() == secret_out1.back());

    //===========================================================================
    // check impossibility of secret recovering with group weight less than threshold value

    typename scheme_type::basic_policy::secret_t wrong_secret =
        nil::crypto3::reconstruct<scheme_type>(shares.begin(), [t, &shares]() {
            auto it = shares.begin();
            for (auto i = 0; i < t - 1; i++) {
                it++;
            }
            return it;
        }());
    BOOST_CHECK(coeffs.front() != wrong_secret);
}

// BOOST_AUTO_TEST_CASE(shamir_weighted_sss) {
//     using curve_type = curves::bls12_381;
//     using group_type = typename curve_type::g1_type;
//     using scheme_type = nil::crypto3::pubkey::weighted_shamir_sss<group_type>;
//     using key_type = no_key_ops<scheme_type>;
//     using shares_dealing_acc_type = shares_dealing_accumulator_set<
//         typename modes::isomorphic<scheme_type>::template bind<shares_dealing_policy<scheme_type>>::type>;
//     using shares_dealing_acc = typename boost::mpl::front<typename shares_dealing_acc_type::features_type>::type;
//     using secret_reconstructing_acc_type = secret_reconstructing_accumulator_set<typename modes::isomorphic<
//         scheme_type>::template bind<secret_reconstructing_policy<scheme_type>>::type>;
//     using secret_reconstructing_acc =
//         typename boost::mpl::front<typename secret_reconstructing_acc_type::features_type>::type;
//
//     auto t = 10;
//     auto n = 20;
//
//     //===========================================================================
//     // participants weights generation
//
//     auto i = 1;
//     auto j = 1;
//     typename scheme_type::weights_type weights;
//     std::generate_n(std::inserter(weights, weights.end()), n, [&i, &j, &t]() {
//         j = j >= t ? 1 : j;
//         return typename scheme_type::weight_type(i++, j++);
//     });
//
//     i = 1;
//     typename scheme_type::weights_type weights_one;
//     std::generate_n(std::inserter(weights_one, weights_one.end()), n,
//                     [&i]() { return typename scheme_type::weight_type(i++, 1); });
//
//     //===========================================================================
//     // polynomial generation
//     auto coeffs = key_type::get_poly(t, n);
//     auto pub_coeffs = key_type::get_public_coeffs(coeffs);
//
//     //===========================================================================
//     // default shares dealing
//
//     // deal_shares(rng)
//     typename key_type::shares_type shares_one = nil::crypto3::deal_shares<scheme_type>(coeffs, n);
//     // deal_shares(first, last)
//     typename key_type::shares_type shares_one1 =
//         nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n);
//     // deal_shares(rng, acc)
//     shares_dealing_acc_type deal_shares_one_acc(n, nil::crypto3::accumulators::threshold_value = t);
//     nil::crypto3::deal_shares<scheme_type>(coeffs, deal_shares_one_acc);
//     typename key_type::shares_type shares_one2 =
//         boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_one_acc);
//     // deal_shares(first, last, acc)
//     shares_dealing_acc_type deal_shares_one_acc1(n, nil::crypto3::accumulators::threshold_value = t);
//     nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), deal_shares_one_acc1);
//     typename key_type::shares_type shares_one3 =
//         boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_one_acc1);
//     // deal_shares(rng, out)
//     std::vector<typename key_type::shares_type> shares_one_out;
//     nil::crypto3::deal_shares<scheme_type>(coeffs, n, std::back_inserter(shares_one_out));
//     // deal_shares(first, last, out)
//     std::vector<typename key_type::shares_type> shares_one_out1;
//     nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), n, std::back_inserter(shares_one_out1));
//
//     BOOST_CHECK(shares_one == shares_one1);
//     BOOST_CHECK(shares_one == shares_one2);
//     BOOST_CHECK(shares_one == shares_one3);
//     BOOST_CHECK(shares_one == shares_one_out.front());
//     BOOST_CHECK(shares_one == shares_one_out1.front());
//
//     //===========================================================================
//     // weighted shares dealing
//
//     // deal_shares(rng, acc)
//     shares_dealing_acc_type deal_shares_acc(n, nil::crypto3::accumulators::threshold_value = t);
//     nil::crypto3::deal_shares<scheme_type>(coeffs, deal_shares_acc);
//     for (const auto &w : weights) {
//         deal_shares_acc(w);
//     }
//     typename key_type::shares_type shares = boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc);
//     // deal_shares(first, last, acc)
//     shares_dealing_acc_type deal_shares_acc1(n, nil::crypto3::accumulators::threshold_value = t);
//     nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), deal_shares_acc1);
//     for (const auto &w : weights) {
//         deal_shares_acc1(w);
//     }
//     typename key_type::shares_type shares1 = boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc1);
//     typename key_type::shares_type shares2 =
//         nil::crypto3::deal_shares<scheme_type>(coeffs.begin(), coeffs.end(), weights.begin(), weights.end(), n);
//     BOOST_CHECK(shares == shares1);
//     BOOST_CHECK(shares == shares2);
//
//     //===========================================================================
//     // reconstructing secret
//
//     // reconstruct(rng)
//     typename scheme_type::private_element_type secret_one = nil::crypto3::reconstruct<scheme_type>(shares_one);
//     // reconstruct(first, last)
//     typename scheme_type::private_element_type secret_one1 =
//         nil::crypto3::reconstruct<scheme_type>(shares_one.begin(), shares_one.end());
//     // reconstruct(rng, acc)
//     secret_reconstructing_acc_type reconstruct_secret_one_acc;
//     typename scheme_type::private_element_type secret_one_acc =
//         boost::accumulators::extract_result<secret_reconstructing_acc>(
//             nil::crypto3::reconstruct<scheme_type>(shares_one, reconstruct_secret_one_acc));
//     // reconstruct(first, last, acc)
//     secret_reconstructing_acc_type reconstruct_secret_one_acc1;
//     typename scheme_type::private_element_type secret_one_acc1 =
//         boost::accumulators::extract_result<secret_reconstructing_acc>(
//             nil::crypto3::reconstruct<scheme_type>(shares_one.begin(), shares_one.end(), reconstruct_secret_one_acc1));
//     // reconstruct(rng, out)
//     std::vector<typename scheme_type::private_element_type> secret_one_out;
//     nil::crypto3::reconstruct<scheme_type>(shares_one, std::back_inserter(secret_one_out));
//     // reconstruct(first, last, out)
//     std::vector<typename scheme_type::private_element_type> secret_one_out1;
//     nil::crypto3::reconstruct<scheme_type>(shares_one.begin(), shares_one.end(), std::back_inserter(secret_one_out1));
//     BOOST_CHECK(coeffs.front() == secret_one);
//     BOOST_CHECK(secret_one == secret_one1);
//     BOOST_CHECK(secret_one1 == secret_one_acc);
//     BOOST_CHECK(secret_one_acc == secret_one_acc1);
//     BOOST_CHECK(secret_one_acc1 == secret_one_out.back());
//     BOOST_CHECK(secret_one_out.back() == secret_one_out1.back());
//
//     // reconstruct(rng)
//     typename scheme_type::private_element_type secret = nil::crypto3::reconstruct<scheme_type>(shares);
//     // reconstruct(first, last)
//     typename scheme_type::private_element_type secret1 =
//         nil::crypto3::reconstruct<scheme_type>(shares.begin(), shares.end());
//     // reconstruct(rng, acc)
//     secret_reconstructing_acc_type reconstruct_secret_acc;
//     typename scheme_type::private_element_type secret_acc =
//         boost::accumulators::extract_result<secret_reconstructing_acc>(
//             nil::crypto3::reconstruct<scheme_type>(shares, reconstruct_secret_acc));
//     // reconstruct(first, last, acc)
//     secret_reconstructing_acc_type reconstruct_secret_acc1;
//     typename scheme_type::private_element_type secret_acc1 =
//         boost::accumulators::extract_result<secret_reconstructing_acc>(
//             nil::crypto3::reconstruct<scheme_type>(shares.begin(), shares.end(), reconstruct_secret_acc1));
//     // reconstruct(rng, out)
//     std::vector<typename scheme_type::private_element_type> secret_out;
//     nil::crypto3::reconstruct<scheme_type>(shares, std::back_inserter(secret_out));
//     // reconstruct(first, last, out)
//     std::vector<typename scheme_type::private_element_type> secret_out1;
//     nil::crypto3::reconstruct<scheme_type>(shares.begin(), shares.end(), std::back_inserter(secret_out1));
//     BOOST_CHECK(coeffs.front() == secret);
//     BOOST_CHECK(secret == secret1);
//     BOOST_CHECK(secret1 == secret_acc);
//     BOOST_CHECK(secret_acc == secret_acc1);
//     BOOST_CHECK(secret_acc1 == secret_out.back());
//     BOOST_CHECK(secret_out.back() == secret_out1.back());
//
//     //===========================================================================
//     // check impossibility of secret recovering with group weight less than threshold value
//
//     typename scheme_type::private_element_type wrong_secret =
//         nil::crypto3::reconstruct<scheme_type>(shares.begin(), [t, &shares]() {
//             auto it = shares.begin();
//             auto weight = 0;
//             while (true) {
//                 weight += it->second.size();
//                 if (weight >= t) {
//                     break;
//                 }
//                 it++;
//             }
//             return it;
//         }());
//     BOOST_CHECK(coeffs.front() != wrong_secret);
// }
//
// BOOST_AUTO_TEST_CASE(pedersen_dkg) {
//     using curve_type = curves::bls12_381;
//     using group_type = typename curve_type::g1_type;
//     using scheme_type = nil::crypto3::pubkey::pedersen_dkg<group_type>;
//     using key_type = no_key_ops<scheme_type>;
//     using shares_dealing_acc_type = shares_dealing_accumulator_set<
//         typename modes::isomorphic<scheme_type>::template bind<shares_dealing_policy<scheme_type>>::type>;
//     using shares_dealing_acc = typename boost::mpl::front<typename shares_dealing_acc_type::features_type>::type;
//     using share_verification_acc_type = share_verification_accumulator_set<typename modes::isomorphic<
//         scheme_type>::template bind<share_verification_policy<scheme_type>>::type>;
//     using share_verification_acc =
//         typename boost::mpl::front<typename share_verification_acc_type::features_type>::type;
//     using secret_reconstructing_acc_type = secret_reconstructing_accumulator_set<typename modes::isomorphic<
//         scheme_type>::template bind<secret_reconstructing_policy<scheme_type>>::type>;
//     using secret_reconstructing_acc =
//         typename boost::mpl::front<typename secret_reconstructing_acc_type::features_type>::type;
//     using share_dealing_acc_type = share_dealing_accumulator_set<
//         typename modes::isomorphic<scheme_type>::template bind<share_dealing_policy<scheme_type>>::type>;
//     using share_dealing_acc = typename boost::mpl::front<typename share_dealing_acc_type::features_type>::type;
//     using polynomial_recovering_acc_type = polynomial_recovering_accumulator_set<scheme_type>;
//     using polynomial_recovering_acc =
//         typename boost::mpl::front<typename polynomial_recovering_acc_type::features_type>::type;
//
//     auto t = 5;
//     auto n = 10;
//
//     //===========================================================================
//     // every participant generates polynomial
//
//     std::vector<typename scheme_type::coeffs_type> P_polys;
//     std::generate_n(std::back_inserter(P_polys), n, [t, n]() { return key_type::get_poly(t, n); });
//
//     //===========================================================================
//     // each participant calculates public values representing coefficients of its polynomial,
//     // then he broadcasts these values
//
//     std::vector<typename scheme_type::public_coeffs_type> P_public_polys;
//     std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_public_polys),
//                    [](const auto &poly_i) { return key_type::get_public_coeffs(poly_i); });
//
//     //===========================================================================
//     // every participant generates shares for each participant in group,
//     // which he then transmits to the intended parties
//
//     std::vector<typename scheme_type::shares_type> P_generated_shares;
//     std::transform(P_polys.begin(), P_polys.end(), std::back_inserter(P_generated_shares), [n, t](const auto &poly_i) {
//         return static_cast<typename key_type::shares_type>(nil::crypto3::deal_shares<scheme_type>(poly_i, n));
//     });
//
//     //===========================================================================
//     // each participant verify shares received from other parties
//
//     for (auto i = 1; i <= n; i++) {
//         for (const auto &j_share : P_generated_shares[i - 1]) {
//             BOOST_CHECK(static_cast<bool>(nil::crypto3::verify_share<scheme_type>(P_public_polys[i - 1], j_share)));
//         }
//     }
//
//     //===========================================================================
//     // each participant calculate its share as sum of shares generated by others for him
//
//     std::unordered_map<std::size_t, share_dealing_acc_type> P_shares_acc;
//     for (const auto &i_generated_shares : P_generated_shares) {
//         for (const auto &j_share : i_generated_shares) {
//             if (!P_shares_acc.count(j_share.first)) {
//                 assert(P_shares_acc.emplace(j_share.first, share_dealing_acc_type()).second);
//             }
//             P_shares_acc.at(j_share.first)(j_share);
//         }
//     }
//     typename scheme_type::shares_type P_shares;
//     for (auto &[j, j_acc] : P_shares_acc) {
//         assert(P_shares.emplace(boost::accumulators::extract_result<share_dealing_acc>(j_acc)).second);
//     }
//
//     //===========================================================================
//     // calculation of public values representing coefficients of real polynomial
//
//     std::vector<polynomial_recovering_acc_type> P_public_coeffs_acc(t);
//     for (const auto &i_poly : P_public_polys) {
//         auto it1 = P_public_coeffs_acc.begin();
//         auto it2 = i_poly.begin();
//         while (it1 != P_public_coeffs_acc.end() && it2 != i_poly.end()) {
//             (*it1)(*it2);
//             it1++;
//             it2++;
//         }
//     }
//     typename scheme_type::public_coeffs_type P_public_poly;
//     std::transform(P_public_coeffs_acc.begin(), P_public_coeffs_acc.end(), std::back_inserter(P_public_poly),
//                    [](auto &&acc) { return scheme_type::public_coeff_type(boost::accumulators::sum(acc)); });
//
//     //===========================================================================
//     // verification of participants shares
//
//     for (const auto &i_share : P_shares) {
//         BOOST_CHECK(static_cast<bool>(nil::crypto3::verify_share<scheme_type>(P_public_poly, i_share)));
//     }
//
//     //===========================================================================
//     // calculation of actual secret
//     // (which is not calculated directly by the parties in real application)
//
//     typename scheme_type::private_element_type secret = scheme_type::private_element_type::zero();
//     for (const auto &i_poly : P_polys) {
//         secret = secret + i_poly.front();
//     }
//
//     //===========================================================================
//
//     BOOST_CHECK_EQUAL(static_cast<typename scheme_type::private_element_type>(
//                           nil::crypto3::reconstruct<scheme_type>(P_shares.begin(),
//                                                                  [t, &P_shares]() {
//                                                                      auto it = P_shares.begin();
//                                                                      for (auto i = 0; i < t; i++) {
//                                                                          it++;
//                                                                      }
//                                                                      return it;
//                                                                  }())),
//                       secret);
//
//     //===========================================================================
//     // check impossibility of secret recovering with group weight less than threshold value
//
//     typename scheme_type::private_element_type wrong_secret =
//         nil::crypto3::reconstruct<scheme_type>(P_shares.begin(), [t, &P_shares]() {
//             auto it = P_shares.begin();
//             for (auto i = 0; i < t - 1; i++) {
//                 it++;
//             }
//             return it;
//         }());
//     BOOST_CHECK(secret != wrong_secret);
// }

BOOST_AUTO_TEST_SUITE_END()
