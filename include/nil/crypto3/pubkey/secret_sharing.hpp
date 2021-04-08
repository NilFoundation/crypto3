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

#ifndef CRYPTO3_PUBKEY_SECRET_SHARING_HPP
#define CRYPTO3_PUBKEY_SECRET_SHARING_HPP

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/pubkey/detail/stream_processor.hpp>

#include <nil/crypto3/pubkey/detail/secret_sharing/shamir.hpp>
#include <nil/crypto3/pubkey/detail/secret_sharing/weighted_shamir.hpp>
#include <nil/crypto3/pubkey/detail/secret_sharing/feldman.hpp>

#include <nil/crypto3/pubkey/no_key_ops.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Ops>
            struct secret_sharing_policy {
                typedef Ops ops_type;

                typedef typename ops_type::group_type group_type;
                typedef typename ops_type::private_element_type private_element_type;
                typedef typename ops_type::public_element_type public_element_type;
                typedef typename ops_type::indexed_private_element_type indexed_private_element_type;
                typedef typename ops_type::indexed_public_element_type indexed_public_element_type;
                typedef typename ops_type::share_type share_type;
                typedef typename ops_type::shares_type shares_type;
                typedef typename ops_type::public_share_type public_share_type;
                typedef typename ops_type::public_shares_type public_shares_type;
                typedef typename ops_type::coeff_type coeff_type;
                typedef typename ops_type::coeffs_type coeffs_type;
                typedef typename ops_type::public_coeff_type public_coeff_type;
                typedef typename ops_type::public_coeffs_type public_coeffs_type;

                template<typename Share>
                using check_indexed_public_element =
                    typename ops_type::template check_indexed_public_element_type<Share>;

                template<typename Share>
                using check_share_type = typename ops_type::template check_indexed_private_element_type<Share>;

                template<typename Shares>
                using check_shares_type = typename ops_type::template check_indexed_private_elements_type<Shares>;

                template<typename PublicShare>
                using check_public_share_type =
                    typename ops_type::template check_indexed_public_element_type<PublicShare>;

                template<typename PublicShares>
                using check_public_shares_type =
                    typename ops_type::template check_indexed_public_elements_type<PublicShares>;

                template<typename Coeff>
                using check_coeff_type = typename ops_type::template check_private_element_type<Coeff>;

                template<typename PublicCoeff>
                using check_public_coeff_type = typename ops_type::template check_public_element_type<PublicCoeff>;

                template<typename Mode, typename AccumulatorSet, std::size_t ValueBits = 0>
                struct stream_processor {
                    struct params_type {
                        typedef stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                    };
                    typedef ::nil::crypto3::pubkey::stream_processor<Mode, AccumulatorSet, params_type> type;
                };
            };

            template<typename Group>
            struct shamir_sss : secret_sharing_policy<detail::shamir_sss<Group>> { };

            template<typename Group>
            struct weighted_shamir_sss : secret_sharing_policy<detail::weighted_shamir_sss<Group>> {
            private:
                typedef secret_sharing_policy<detail::weighted_shamir_sss<Group>> base_type;

            public:
                typedef typename base_type::ops_type::weight_type weight_type;
                typedef typename base_type::ops_type::weights_type weights_type;

                template<typename Weight>
                using check_weight_type = typename base_type::ops_type::template check_indexed_weight_type<Weight>;

                template<typename Weights>
                using check_weights_type = typename base_type::ops_type::template check_indexed_weights_type<Weights>;

                template<typename Share>
                using check_share_type =
                    typename base_type::ops_type::template check_indexed_weighted_share_type<Share>;

                template<typename Shares>
                using check_shares_type =
                    typename base_type::ops_type::template check_indexed_weighted_shares_type<Shares>;

                template<typename PublicShare>
                using check_public_share_type =
                    typename base_type::ops_type::template check_indexed_weighted_public_share_type<PublicShare>;

                template<typename PublicShares>
                using check_public_shares_type =
                    typename base_type::ops_type::template check_indexed_weighted_public_shares_type<PublicShares>;
            };

            template<typename Group>
            struct feldman_sss : secret_sharing_policy<detail::feldman_sss<Group>> { };

            template<typename Group>
            struct no_key_ops<shamir_sss<Group>> : shamir_sss<Group> {
                typedef shamir_sss<Group> scheme_type;

                template<typename Number1, typename Number2>
                static inline typename scheme_type::coeffs_type get_poly(Number1 t, Number2 n) {
                    return scheme_type::ops_type::get_poly(t, n);
                }

                template<typename Shares>
                static inline typename scheme_type::public_shares_type get_public_shares(const Shares &shares) {
                    return scheme_type::ops_type::get_public_shares(shares);
                }

                template<typename Share>
                static inline typename scheme_type::public_share_type get_public_share(const Share &share) {
                    return scheme_type::ops_type::get_public_share(share);
                }

                template<typename Coeffs>
                static inline typename scheme_type::public_coeffs_type get_public_coeffs(const Coeffs &coeffs) {
                    return scheme_type::ops_type::get_public_coeffs(coeffs);
                }

                template<typename Coeffs, typename Number>
                static inline typename scheme_type::shares_type deal_shares(const Coeffs &coeffs, Number n) {
                    return scheme_type::ops_type::deal_shares(coeffs, n);
                }

                template<typename Shares>
                static inline typename scheme_type::private_element_type reconstruct_secret(const Shares &shares) {
                    return scheme_type::ops_type::reconstruct_secret(shares);
                }

                template<typename PublicShares>
                static inline typename scheme_type::public_element_type
                    reconstruct_public_element(const PublicShares &public_shares) {
                    return scheme_type::ops_type::reconstruct_public_element(public_shares);
                }

                template<typename Number1, typename Number2>
                static inline bool check_t(Number1 t, Number2 n) {
                    return scheme_type::ops_type::check_t(t, n);
                }

                template<typename Number>
                static inline bool check_minimal_size(Number n) {
                    return scheme_type::ops_type::check_minimal_size(n);
                }

                template<typename Number>
                static inline bool check_participant_index(Number i) {
                    return scheme_type::ops_type::check_participant_index(i);
                }

                template<typename Number1, typename Number2>
                static inline bool check_participant_index(Number1 i, Number2 n) {
                    return scheme_type::ops_type::check_participant_index(i, n);
                }

                template<typename Coeff, typename Number, typename Share>
                static inline typename scheme_type::share_type partial_eval_share(const Coeff &coeff, Number exp,
                                                                                  const Share &init_share_value) {
                    return scheme_type::ops_type::partial_eval_share(coeff, exp, init_share_value);
                }
            };

            template<typename Group>
            struct no_key_ops<weighted_shamir_sss<Group>> : weighted_shamir_sss<Group> {
                typedef weighted_shamir_sss<Group> scheme_type;

                template<typename Number1, typename Number2>
                static inline typename scheme_type::coeffs_type get_poly(Number1 t, Number2 n) {
                    return scheme_type::ops_type::get_poly(t, n);
                }

                template<typename Shares>
                static inline typename scheme_type::public_shares_type get_public_shares(const Shares &shares) {
                    return scheme_type::ops_type::get_public_shares(shares);
                }

                template<typename Share>
                static inline typename scheme_type::public_share_type get_public_share(const Share &share) {
                    return scheme_type::ops_type::get_public_share(share);
                }

                template<typename Coeffs>
                static inline typename scheme_type::public_coeffs_type get_public_coeffs(const Coeffs &coeffs) {
                    return scheme_type::ops_type::get_public_coeffs(coeffs);
                }

                template<typename Coeffs, typename Number>
                static inline typename scheme_type::shares_type deal_shares(const Coeffs &coeffs, Number n) {
                    return scheme_type::ops_type::deal_shares(coeffs, n);
                }

                template<typename Shares>
                static inline typename scheme_type::private_element_type reconstruct_secret(const Shares &shares) {
                    return scheme_type::ops_type::reconstruct_secret(shares);
                }

                template<typename Shares, typename Weights, typename Number>
                static inline typename scheme_type::private_element_type
                    reconstruct_part_secret(const Shares &shares, const Weights &weights, Number t) {
                    return scheme_type::ops_type::reconstruct_part_secret(shares, weights, t);
                }

                template<typename PublicShares, typename Weights, typename Number>
                static inline typename scheme_type::public_element_type
                    reconstruct_part_public_element(const PublicShares &public_shares, const Weights &weights,
                                                        Number t) {
                    return scheme_type::ops_type::reconstruct_part_public_element(public_shares, weights, t);
                }

                template<typename PublicShares>
                static inline typename scheme_type::public_element_type
                    reconstruct_public_element(const PublicShares &public_shares) {
                    return scheme_type::ops_type::reconstruct_public_element(public_shares);
                }

                template<typename PublicElements>
                static inline typename scheme_type::public_element_type
                    reduce_public_elements(const PublicElements &public_elements) {
                    return scheme_type::ops_type::reduce_public_elements(public_elements);
                }

                template<typename Number1, typename Number2>
                static inline bool check_t(Number1 t, Number2 n) {
                    return scheme_type::ops_type::check_t(t, n);
                }

                template<typename Number>
                static inline bool check_minimal_size(Number n) {
                    return scheme_type::ops_type::check_minimal_size(n);
                }

                template<typename Number>
                static inline bool check_participant_index(Number i) {
                    return scheme_type::ops_type::check_participant_index(i);
                }

                template<typename Number1, typename Number2>
                static inline bool check_participant_index(Number1 i, Number2 n) {
                    return scheme_type::ops_type::check_participant_index(i, n);
                }

                template<typename Weight, typename Number>
                static inline bool check_weight(const Weight &w, Number n) {
                    return scheme_type::ops_type::check_weight(w, n);
                }
            };

            template<typename Group>
            struct no_key_ops<feldman_sss<Group>> : feldman_sss<Group> {
                typedef feldman_sss<Group> scheme_type;

                template<typename Number1, typename Number2>
                static inline typename scheme_type::coeffs_type get_poly(Number1 t, Number2 n) {
                    return scheme_type::ops_type::get_poly(t, n);
                }

                template<typename Shares>
                static inline typename scheme_type::public_shares_type get_public_shares(const Shares &shares) {
                    return scheme_type::ops_type::get_public_shares(shares);
                }

                template<typename Share>
                static inline typename scheme_type::public_share_type get_public_share(const Share &share) {
                    return scheme_type::ops_type::get_public_share(share);
                }

                template<typename Coeffs>
                static inline typename scheme_type::public_coeffs_type get_public_coeffs(const Coeffs &coeffs) {
                    return scheme_type::ops_type::get_public_coeffs(coeffs);
                }

                template<typename Coeffs, typename Number>
                static inline typename scheme_type::shares_type deal_shares(const Coeffs &coeffs, Number n) {
                    return scheme_type::ops_type::deal_shares(coeffs, n);
                }

                template<typename Shares>
                static inline typename scheme_type::private_element_type reconstruct_secret(const Shares &shares) {
                    return scheme_type::ops_type::reconstruct_secret(shares);
                }

                template<typename PublicShares>
                static inline typename scheme_type::public_element_type
                    reconstruct_public_element(const PublicShares &public_shares) {
                    return scheme_type::ops_type::reconstruct_public_element(public_shares);
                }

                template<typename Number1, typename Number2>
                static inline bool check_t(Number1 t, Number2 n) {
                    return scheme_type::ops_type::check_t(t, n);
                }

                template<typename Number>
                static inline bool check_minimal_size(Number n) {
                    return scheme_type::ops_type::check_minimal_size(n);
                }

                template<typename Number>
                static inline bool check_participant_index(Number i) {
                    return scheme_type::ops_type::check_participant_index(i);
                }

                template<typename Number1, typename Number2>
                static inline bool check_participant_index(Number1 i, Number2 n) {
                    return scheme_type::ops_type::check_participant_index(i, n);
                }

                template<typename PublicCoeffs, typename Share>
                static inline bool verify_share(const PublicCoeffs &public_coeffs, const Share &share) {
                    return scheme_type::ops_type::verify_share(public_coeffs, share);
                }

                template<typename Coeff, typename Number, typename Share>
                static inline typename scheme_type::share_type partial_eval_share(const Coeff &coeff, Number exp,
                                                                                  const Share &init_share_value) {
                    return scheme_type::ops_type::partial_eval_share(coeff, exp, init_share_value);
                }

                template<typename PublicCoeff, typename Number, typename PublicShare>
                static inline typename scheme_type::public_share_type
                    partial_eval_verification_value(const PublicCoeff &public_coeff, Number exp,
                                                    const PublicShare &init_verification_value) {
                    return scheme_type::ops_type::partial_eval_verification_value(public_coeff, exp,
                                                                                  init_verification_value);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SECRET_SHARING_HPP
