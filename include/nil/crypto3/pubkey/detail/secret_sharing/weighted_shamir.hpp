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

#ifndef CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP

#include <nil/crypto3/pubkey/detail/secret_sharing/shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Group>
                struct weighted_shamir_sss : shamir_sss<Group> {
                    typedef shamir_sss<Group> base_type;

                    //===========================================================================
                    // secret sharing scheme logical types
                    typedef typename base_type::private_element_type private_element_type;
                    typedef typename base_type::public_element_type public_element_type;

                    typedef std::pair<std::size_t, std::size_t> weight_type;
                    typedef std::unordered_map<std::size_t, std::size_t> weights_type;
                    typedef std::pair<std::size_t, typename base_type::shares_type> share_type;
                    typedef std::unordered_map<std::size_t, typename base_type::shares_type> shares_type;
                    typedef std::pair<std::size_t, typename base_type::public_shares_type> public_share_type;
                    typedef std::unordered_map<std::size_t, typename base_type::public_shares_type> public_shares_type;

                    //===========================================================================
                    // constraints checking meta-functions

                    template<typename IndexedWeight, typename Index = typename IndexedWeight::first_type,
                             typename Weight = typename IndexedWeight::second_type,
                             typename base_type::template check_index_type<Index> = true,
                             typename base_type::template check_number_type<Weight> = true>
                    using get_indexed_weight_type = std::pair<Index, Weight>;

                    template<typename IndexedWeight>
                    using check_indexed_weight_type = typename std::enable_if<
                        std::is_same<get_indexed_weight_type<IndexedWeight>, IndexedWeight>::value, bool>::type;

                    template<typename IndexedWeightedShare, typename Index = typename IndexedWeightedShare::first_type,
                             typename WeightedShare = typename IndexedWeightedShare::second_type,
                             typename base_type::template check_index_type<Index> = true,
                             typename base_type::template check_indexed_private_elements_type<WeightedShare> = true>
                    using get_indexed_weighted_share_type = std::pair<Index, WeightedShare>;

                    template<typename IndexedPublicWeightedShare,
                             typename Index = typename IndexedPublicWeightedShare::first_type,
                             typename WeightedPublicShare = typename IndexedPublicWeightedShare::second_type,
                             typename base_type::template check_index_type<Index> = true,
                             typename base_type::template check_indexed_public_elements_type<WeightedPublicShare> =
                                 true>
                    using get_indexed_weighted_public_share_type = std::pair<Index, WeightedPublicShare>;

                    template<typename IndexesWeights>
                    using check_indexed_weights_type = check_indexed_weight_type<
                        typename std::iterator_traits<typename IndexesWeights::iterator>::value_type>;

                    template<typename IndexedWeightedShare>
                    using check_indexed_weighted_share_type =
                        typename std::enable_if<std::is_same<get_indexed_weighted_share_type<IndexedWeightedShare>,
                                                             IndexedWeightedShare>::value,
                                                bool>::type;

                    template<typename IndexedWeightedPublicShare>
                    using check_indexed_weighted_public_share_type = typename std::enable_if<
                        std::is_same<get_indexed_weighted_public_share_type<IndexedWeightedPublicShare>,
                                     IndexedWeightedPublicShare>::value,
                        bool>::type;

                    template<typename IndexedWeightedShares>
                    using check_indexed_weighted_shares_type = check_indexed_weighted_share_type<
                        typename std::iterator_traits<typename IndexedWeightedShares::iterator>::value_type>;

                    template<typename IndexedWeightedPublicShares>
                    using check_indexed_weighted_public_shares_type = check_indexed_weighted_public_share_type<
                        typename std::iterator_traits<typename IndexedWeightedPublicShares::iterator>::value_type>;

                    //===========================================================================
                    // shares dealing functions

                    template<
                        typename Coeffs, typename Weights,
                        typename base_type::template check_private_element_type<typename Coeffs::value_type> = true,
                        check_indexed_weights_type<Weights> = true>
                    static inline shares_type deal_shares(const Coeffs &coeffs, const Weights &weights) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        std::size_t n = std::distance(weights.begin(), weights.end());
                        assert(base_type::check_t(t, n));

                        shares_type shares;
                        for (auto w_i : weights) {
                            assert(check_weight(w_i, n));
                            typename share_type::second_type i_shares;
                            for (typename Weights::value_type::second_type j = 1; j <= w_i.second; j++) {
                                std::size_t id_ij = w_i.first * t + j;
                                assert(i_shares.emplace(base_type::deal_share(coeffs, id_ij)).second);
                            }
                            assert(shares.emplace(w_i.first, i_shares).second);
                        }
                        return shares;
                    }

                    // TODO: REFACTOR RECONSTRUCTION FUNCTIONAL
                    using base_type::reconstruct_secret;

                    // TODO: implement without temporary variable _shares
                    template<typename Shares, check_indexed_weighted_shares_type<Shares> = true>
                    static inline private_element_type reconstruct_secret(const Shares &shares) {
                        typename base_type::shares_type _shares;
                        for (const auto &[i, s] : shares) {
                            for (const auto &part_s : s) {
                                assert(_shares.emplace(part_s).second);
                            }
                        }
                        return base_type::reconstruct_secret(_shares);
                    }

                    template<typename Shares, typename Weights, typename Number,
                             typename base_type::template check_indexed_private_elements_type<Shares> = true,
                             check_indexed_weights_type<Weights> = true,
                             typename base_type::template check_number_type<Number> = true>
                    static inline private_element_type reconstruct_weighted_secret(const Shares &shares,
                                                                                   const Weights &weights, Number t) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));

                        private_element_type secret = private_element_type::zero();
                        typename base_type::indexes_type indexes = get_weighted_indexes(weights, t);
                        for (const auto &[i, s] : shares) {
                            assert(indexes.count(i));
                            secret = secret + s * base_type::eval_basis_poly(indexes, i);
                        }
                        return secret;
                    }

                    template<typename PublicShares, typename Weights, typename Number,
                        typename base_type::template check_indexed_public_elements_type<PublicShares> = true,
                             check_indexed_weights_type<Weights> = true,
                             typename base_type::template check_number_type<Number> = true>
                    static inline public_element_type reconstruct_weighted_public_element(const PublicShares &public_shares,
                                                                                 const Weights &weights, Number t) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicShares>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));

                        public_element_type result = public_element_type::zero();
                        typename base_type::indexes_type indexes = get_weighted_indexes(weights, t);
                        for (const auto &[i, e_i] : public_shares) {
                            result = result + base_type::eval_basis_poly(indexes, i) * e_i;
                        }
                        return result;
                    }

                    template<typename Weights, typename Number, check_indexed_weights_type<Weights> = true,
                             typename base_type::template check_number_type<Number> = true>
                    static inline typename base_type::indexes_type get_weighted_indexes(const Weights &weights,
                                                                                        Number t) {
                        typename base_type::indexes_type indexes;
                        for (auto [i, w] : weights) {
                            for (typename Weights::value_type::second_type j = 1; j <= w; j++) {
                                assert(indexes.emplace(i * t + j).second);
                            }
                        }
                        return indexes;
                    }

                    template<typename Shares, check_indexed_weighted_shares_type<Shares> = true>
                    static inline public_shares_type get_public_shares(const Shares &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                        assert(check_minimal_size(std::distance(shares.begin(), shares.end())));

                        public_shares_type public_shares;
                        for (const auto &s : shares) {
                            assert(public_shares.emplace(get_public_share(s)).second);
                        }
                        return public_shares;
                    }

                    template<typename Share, check_indexed_weighted_share_type<Share> = true>
                    static inline public_share_type get_public_share(const Share &s) {
                        assert(base_type::check_participant_index(s.first));
                        public_share_type public_share;
                        public_share.first = s.first;
                        for (const auto &part_s : s.second) {
                            assert(public_share.second.emplace(base_type::get_public_share(part_s)).second);
                        }
                        return public_share;
                    }

                    template<typename Weight, typename Number, check_indexed_weight_type<Weight> = true,
                             typename base_type::template check_number_type<Number> = true>
                    static inline bool check_weight(const Weight &w, Number n) {
                        return base_type::check_participant_index(w.first, n) && w.second > 0;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
