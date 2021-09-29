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

#ifndef CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP

#include <nil/crypto3/pubkey/secret_sharing/weighted_basic_policy.hpp>
#include <nil/crypto3/pubkey/secret_sharing/shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct weighted_shamir_sss : public sss_weighted_basic_policy<Group>, public shamir_sss<Group> {
                typedef sss_weighted_basic_policy<Group> basic_policy;
                typedef shamir_sss<Group> base_type;

                typedef typename basic_policy::share_type share_type;
                typedef typename basic_policy::public_share_type public_share_type;
                typedef typename basic_policy::coeff_type coeff_type;
                typedef typename basic_policy::public_coeff_type public_coeff_type;

                //===========================================================================
                // shares dealing functions

                // template<typename Coeffs, typename Weights,
                //          typename base_type::template check_private_element_type<
                //              typename std::iterator_traits<typename Coeffs::iterator>::value_type> = true,
                //          check_indexed_weight_type<
                //              typename std::iterator_traits<typename Weights::iterator>::value_type> = true>
                // static inline shares_type deal_shares(const Coeffs &coeffs, const Weights &weights) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
                //     return deal_shares(coeffs.begin(), coeffs.end(), weights.begin(), weights.end());
                // }
                //
                // template<typename CoeffsIterator, typename WeightsIterator,
                //          typename WeightsValueType = typename std::iterator_traits<WeightsIterator>::value_type,
                //          typename base_type::template check_private_element_type<
                //              typename std::iterator_traits<CoeffsIterator>::value_type> = true,
                //          check_indexed_weight_type<WeightsValueType> = true>
                // static inline shares_type deal_shares(CoeffsIterator first1, CoeffsIterator last1,
                //                                       WeightsIterator first2, WeightsIterator last2) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIterator>));
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<WeightsIterator>));
                //
                //     auto t = std::distance(first1, last1);
                //     auto n = std::distance(first2, last2);
                //     assert(base_type::check_t(t, n));
                //
                //     shares_type shares;
                //     for (auto it2 = first2; it2 != last2; it2++) {
                //         assert(check_weight(*it2, n));
                //         typename share_type::second_type i_shares;
                //         for (typename WeightsValueType::second_type j = 1; j <= it2->second; j++) {
                //             typename WeightsValueType::second_type id_ij = it2->first * t + j;
                //             assert(i_shares.emplace(base_type::deal_share(first1, last1, id_ij)).second);
                //         }
                //         assert(shares.emplace(it2->first, i_shares).second);
                //     }
                //     return shares;
                // }

                static inline void partial_eval_share(const coeff_type &coeff, std::size_t exp,
                                                      share_type &share_value) {
                    assert(basic_policy::check_participant_index(share_value.first));
                    assert(basic_policy::check_exp(exp));

                    for (auto &j_share : share_value.second) {
                        j_share.second = base_type::partial_eval_share(coeff, exp, j_share).second;
                    }
                }

                // // TODO: REFACTOR RECONSTRUCTION FUNCTIONAL
                // using base_type::reconstruct_secret;
                //
                // // TODO: implement without temporary variable _shares
                // template<typename Shares, check_indexed_weighted_share_type<typename std::iterator_traits<
                //                               typename Shares::iterator>::value_type> = true>
                // static inline private_element_type reconstruct_secret(const Shares &shares) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                //     return reconstruct_secret(shares.begin(), shares.end());
                // }
                //
                // template<typename SharesIterator, check_indexed_weighted_share_type<typename std::iterator_traits<
                //                                       SharesIterator>::value_type> = true>
                // static inline private_element_type reconstruct_secret(SharesIterator first, SharesIterator last) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIterator>));
                //
                //     typename base_type::shares_type _shares;
                //     for (auto it = first; it != last; it++) {
                //         for (const auto &part_s : it->second) {
                //             assert(_shares.emplace(part_s).second);
                //         }
                //     }
                //     return base_type::reconstruct_secret(_shares);
                // }
                //
                // template<typename Shares, typename Weights, typename Number,
                //          typename base_type::template check_indexed_private_element_type<
                //              typename std::iterator_traits<typename Shares::iterator>::value_type> = true,
                //          check_indexed_weight_type<
                //              typename std::iterator_traits<typename Weights::iterator>::value_type> = true,
                //          typename base_type::template check_number_type<Number> = true>
                // static inline private_element_type reconstruct_part_secret(const Shares &shares,
                //                                                            const Weights &weights, Number t) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
                //     return reconstruct_part_secret(shares.begin(), shares.end(), weights.begin(), weights.end(), t);
                // }
                //
                // template<
                //     typename SharesIterator, typename WeightsIterator, typename Number,
                //     typename base_type::template check_indexed_private_element_type<
                //         typename std::iterator_traits<SharesIterator>::value_type> = true,
                //     check_indexed_weight_type<typename std::iterator_traits<WeightsIterator>::value_type> = true,
                //     typename base_type::template check_number_type<Number> = true>
                // static inline private_element_type
                //     reconstruct_part_secret(SharesIterator first1, SharesIterator last1, WeightsIterator first2,
                //                             WeightsIterator last2, Number t) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIterator>));
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<WeightsIterator>));
                //
                //     private_element_type secret = private_element_type::zero();
                //     typename base_type::indexes_type indexes = get_weighted_indexes(first2, last2, t);
                //     for (auto it1 = first1; it1 != last1; it1++) {
                //         assert(indexes.count(it1->first));
                //         secret = secret + it1->second * base_type::eval_basis_poly(indexes, it1->first);
                //     }
                //     return secret;
                // }
                //
                // template<typename PublicShares, typename Weights, typename Number,
                //          typename base_type::template check_indexed_public_element_type<
                //              typename std::iterator_traits<typename PublicShares::iterator>::value_type> = true,
                //          check_indexed_weight_type<
                //              typename std::iterator_traits<typename Weights::iterator>::value_type> = true,
                //          typename base_type::template check_number_type<Number> = true>
                // static inline public_element_type reconstruct_part_public_element(const PublicShares &public_shares,
                //                                                                   const Weights &weights,
                //                                                                   Number t) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicShares>));
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
                //     return reconstruct_part_public_element(public_shares.begin(), public_shares.end(),
                //                                            weights.begin(), weights.end(), t);
                // }
                //
                // template<
                //     typename PublicSharesIterator, typename WeightsIterator, typename Number,
                //     typename base_type::template check_indexed_public_element_type<
                //         typename std::iterator_traits<PublicSharesIterator>::value_type> = true,
                //     check_indexed_weight_type<typename std::iterator_traits<WeightsIterator>::value_type> = true,
                //     typename base_type::template check_number_type<Number> = true>
                // static inline public_element_type
                //     reconstruct_part_public_element(PublicSharesIterator first1, PublicSharesIterator last1,
                //                                     WeightsIterator first2, WeightsIterator last2, Number t) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicSharesIterator>));
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<WeightsIterator>));
                //
                //     public_element_type result = public_element_type::zero();
                //     typename base_type::indexes_type indexes = get_weighted_indexes(first2, last2, t);
                //     for (auto it1 = first1; it1 != last1; it1++) {
                //         assert(indexes.count(it1->first));
                //         result = result + it1->second * base_type::eval_basis_poly(indexes, it1->first);
                //     }
                //     return result;
                // }
                //
                // template<typename Weights, typename Number,
                //          check_indexed_weight_type<
                //              typename std::iterator_traits<typename Weights::iterator>::value_type> = true,
                //          typename base_type::template check_number_type<Number> = true>
                // static inline typename base_type::indexes_type get_weighted_indexes(const Weights &weights,
                //                                                                     Number t) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
                //     return get_weighted_indexes(weights.begin(), weights.end(), t);
                // }
                //
                // template<typename WeightsIterator,
                //          typename WeightsValueType = typename std::iterator_traits<WeightsIterator>::value_type,
                //          typename Number, check_indexed_weight_type<WeightsValueType> = true,
                //          typename base_type::template check_number_type<Number> = true>
                // static inline typename base_type::indexes_type
                //     get_weighted_indexes(WeightsIterator first, WeightsIterator last, Number t) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<WeightsIterator>));
                //
                //     typename base_type::indexes_type indexes;
                //     for (auto it = first; it != last; it++) {
                //         for (typename WeightsValueType::second_type j = 1; j <= it->second; j++) {
                //             assert(indexes.emplace(it->first * t + j).second);
                //         }
                //     }
                //     return indexes;
                // }
                //
                // template<typename Shares, check_indexed_weighted_share_type<typename std::iterator_traits<
                //                               typename Shares::iterator>::value_type> = true>
                // static inline public_shares_type get_public_shares(const Shares &shares) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                //     return get_public_shares(shares.begin(), shares.end());
                // }
                //
                // template<typename SharesIterator, check_indexed_weighted_share_type<typename std::iterator_traits<
                //                                       SharesIterator>::value_type> = true>
                // static inline public_shares_type get_public_shares(SharesIterator first, SharesIterator last) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIterator>));
                //     assert(check_minimal_size(std::distance(first, last)));
                //
                //     public_shares_type public_shares;
                //     for (auto it = first; it != last; it++) {
                //         assert(public_shares.emplace(get_public_share(*it)).second);
                //     }
                //     return public_shares;
                // }
                //
                // template<typename Share, check_indexed_weighted_share_type<Share> = true>
                // static inline public_share_type get_public_share(const Share &s) {
                //     assert(base_type::check_participant_index(s.first));
                //     public_share_type public_share;
                //     public_share.first = s.first;
                //     for (const auto &part_s : s.second) {
                //         assert(public_share.second.emplace(base_type::get_public_share(part_s)).second);
                //     }
                //     return public_share;
                // }
            };

            template<typename Group>
            struct public_share_sss<weighted_shamir_sss<Group>> {
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef typename scheme_type::public_share_type public_share_type;

                public_share_sss() = default;

                public_share_sss(const public_share_type &in_public_share) : public_share(in_public_share) {
                }

                inline typename public_share_type::first_type get_index() const {
                    return public_share.first;
                }

                inline typename public_share_type::second_type get_value() const {
                    return public_share.second;
                }

            protected:
                public_share_type public_share;
            };

            template<typename Group>
            struct share_sss<weighted_shamir_sss<Group>> : public public_share_sss<weighted_shamir_sss<Group>> {
                typedef public_share_sss<weighted_shamir_sss<Group>> base_type;
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef typename scheme_type::share_type share_type;

                share_sss(const share_type &in_share) :
                    base_type(scheme_type::get_weighted_public_share(in_share)), share(in_share) {
                }

                inline typename share_type::first_type get_index() const {
                    return share.first;
                }

                inline typename share_type::second_type get_value() const {
                    return share.second;
                }

                inline share_type get_data() const {
                    return share;
                }

                bool operator==(const share_sss &other) const {
                    return this->share == other.share;
                }

            protected:
                share_type share;
            };

            template<typename Group>
            struct secret_sss<weighted_shamir_sss<Group>> : public secret_sss<shamir_sss<Group>> {
                typedef secret_sss<shamir_sss<Group>> base_type;
                typedef weighted_shamir_sss<Group> scheme_type;

                template<typename Shares>
                secret_sss(const Shares &shares, const typename base_type::indexes_type &indexes) :
                    secret_sss(std::cbegin(shares), std::cend(shares), indexes) {
                }

                template<typename ShareIt,
                         typename std::enable_if<
                             std::is_same<typename std::remove_cv<typename std::remove_reference<
                                                     typename std::iterator_traits<ShareIt>::value_type>::type>::type,
                                                 share_sss<scheme_type>>::value,
                             bool>::type = true>
                secret_sss(ShareIt first, ShareIt last, const typename base_type::indexes_type &indexes) :
                    base_type(first, last, indexes) {
                }

            protected:
                // static inline
            };

            template<typename Group>
            struct deal_shares_op<weighted_shamir_sss<Group>> {
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef std::vector<share_type> shares_type;
                typedef std::vector<typename share_type::share_type> internal_accumulator_type;

                template<typename Weights>
                static inline typename std::enable_if<std::is_unsigned<
                    typename std::iterator_traits<typename Weights::iterator>::value_type>::value>::type
                    init_accumulator(internal_accumulator_type &acc, std::size_t n, std::size_t t,
                                     const Weights &weights) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
                    assert(n == std::distance(std::cbegin(weights), std::cend(weights)));
                    assert(scheme_type::check_threshold_value(t, n));

                    std::size_t i = 1;
                    for (auto w_i : weights) {
                        assert(scheme_type::check_weight(w_i));
                        typename share_type::share_type::second_type i_shares;
                        for (auto j = 1; j <= w_i; ++j) {
                            std::size_t id_ij = i * t + j;
                            assert(i_shares.emplace(id_ij, scheme_type::private_element_type::zero()).second);
                        }
                        acc.emplace_back(i++, i_shares);
                    }
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::coeff_type &coeff) {
                    for (auto shares_iter = std::begin(acc); shares_iter != std::end(acc); ++shares_iter) {
                        scheme_type::partial_eval_share(coeff, exp, *shares_iter);
                    }
                }

                static inline shares_type process(internal_accumulator_type &acc) {
                    shares_type result;
                    for (auto &share : acc) {
                        result.emplace_back(share);
                    }
                    return result;
                }
            };

            // template<typename Group>
            // struct reconstruct_secret_op<weighted_shamir_sss<Group>> {
            //     typedef weighted_shamir_sss<Group> scheme_type;
            //     typedef share_sss<scheme_type> share_type;
            //     typedef secret_sss<scheme_type> secret_type;
            //     typedef std::pair<typename scheme_type::indexes_type, std::vector<share_type>>
            //         internal_accumulator_type;
            //
            // public:
            //     static inline void init_accumulator() {
            //     }
            //
            //     static inline void update(internal_accumulator_type &acc, const share_type &share) {
            //         base_type::_update(acc, share);
            //     }
            //
            //     static inline secret_type process(internal_accumulator_type &acc) {
            //         return base_type::template _process<secret_type>(acc);
            //     }
            // };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
