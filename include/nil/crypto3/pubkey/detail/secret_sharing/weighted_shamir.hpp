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

                    typedef std::pair<std::size_t, std::size_t> weight_type;
                    typedef std::unordered_map<std::size_t, std::size_t> weights_type;
                    typedef std::pair<std::size_t, typename base_type::shares_type> separated_share_type;
                    typedef std::unordered_map<std::size_t, typename base_type::shares_type> separated_shares_type;
                    typedef std::pair<std::size_t, std::pair<private_element_type, typename base_type::shares_type>> share_type;
                    typedef std::unordered_map<std::size_t, std::pair<private_element_type, typename base_type::shares_type>> shares_type;

                    //===========================================================================
                    // constraints checking meta-functions

                    template<typename IndexedWeight,
                             typename Index = typename IndexedWeight::first_type,
                             typename Weight = typename IndexedWeight::second_type,
                             typename base_type::template check_index_type<Index> = true,
                             typename base_type::template check_number_type<Weight> = true>
                    using get_indexed_weight_type = std::pair<Index, Weight>;

                    template<typename IndexedWeight>
                    using check_indexed_weight_type = typename std::enable_if<
                        std::is_same<get_indexed_weight_type<IndexedWeight>, IndexedWeight>::value,
                        bool>::type;

                    //===========================================================================
                    // shares dealing functions

                    template<
                        typename Coeffs,
                        typename Weights,
                        typename base_type::template check_private_element_type<typename Coeffs::value_type> = true,
                        check_indexed_weight_type<typename Weights::value_type> = true>
                    static inline shares_type deal_shares(const Coeffs &coeffs, const Weights &weights) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));

                        separated_shares_type separated_shares = deal_separated_shares(coeffs, weights);
                        shares_type shares;
                        for (const auto &[i, i_shares] : separated_shares) {
                            assert(shares.emplace(i, std::make_pair(join_separated_share(i, i_shares), i_shares)).second);
                        }
                        return shares;
                    }

                    template<
                        typename Coeffs,
                        typename Weights,
                        typename base_type::template check_private_element_type<typename Coeffs::value_type> = true,
                        check_indexed_weight_type<typename Weights::value_type> = true>
                    static inline separated_shares_type deal_separated_shares(const Coeffs &coeffs,
                                                                              const Weights &weights) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        std::size_t n = std::distance(weights.begin(), weights.end());
                        assert(base_type::check_t(t, n));

                        separated_shares_type separated_shares;
                        for (auto [i, w_i] : weights) {
                            assert(check_weight(w_i));
                            typename separated_share_type::second_type i_shares;
                            for (std::size_t j = 1; j <= w_i; j++) {
                                std::size_t id_ij = i * t + j;
                                assert(i_shares.emplace(base_type::deal_share(coeffs, id_ij)).second);
                            }
                            assert(separated_shares.emplace(i, i_shares).second);
                        }
                        return separated_shares;
                    }

                    template<typename Number,
                             typename SeparatedShare,
                             typename base_type::template check_number_type<Number> = true,
                             typename base_type::template check_indexed_private_elements_type<SeparatedShare> = true>
                    static inline private_element_type join_separated_share(Number i, const SeparatedShare &separated_share) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SeparatedShare>));
                        assert(base_type::check_participant_index(i));
                        return base_type::reconstruct_secret(separated_share, i);
                    }

                    template<typename Number, typename base_type::template check_number_type<Number> = true>
                    static inline bool check_weight(Number w) {
                        return w > 0;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
