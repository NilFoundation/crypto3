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
                    typedef typename base_type::indexed_private_element_type indexed_private_element_type;
                    typedef typename base_type::indexed_private_elements_type indexed_private_elements_type;

                    typedef std::vector<std::size_t> weights_type;
                    // TODO: use indexed_weights_type instead weights_type
                    typedef std::unordered_map<std::size_t, std::size_t> indexed_weights_type;
                    typedef std::unordered_map<std::size_t, indexed_private_elements_type>
                        indexed_weighted_private_elements_type;

                    //===========================================================================
                    // constraints checking meta-functions

                    template<typename Weight>
                    using check_weight_type = typename base_type::template check_number_type<Weight>;

                    template<typename IndexedWeight,
                             typename Index = typename IndexedWeight::first_type,
                             typename Weight = typename IndexedWeight::second_type,
                             typename base_type::template check_index_type<Index> = true,
                             check_weight_type<Weight> = true>
                    using get_indexed_weight_type = std::pair<Index, Weight>;

                    template<typename IndexedWeight>
                    using check_indexed_weight_type = typename std::enable_if<
                        std::is_same<get_indexed_weight_type<IndexedWeight>, IndexedWeight>::value,
                        bool>::type;

                    template<typename IndexedWeightedPrivateElement,
                             typename Index = typename IndexedWeightedPrivateElement::first_type,
                             typename WeightedPrivateElement = typename IndexedWeightedPrivateElement::second_type,
                             typename base_type::template check_index_type<Index> = true,
                             typename base_type::template check_indexed_private_elements_type<WeightedPrivateElement> =
                                 true>
                    using get_indexed_weighted_private_element_type = std::pair<Index, WeightedPrivateElement>;

                    template<typename IndexedWeightedPrivateElement>
                    using check_indexed_weighted_private_element_type = typename std::enable_if<
                        std::is_same<get_indexed_weighted_private_element_type<IndexedWeightedPrivateElement>,
                                     IndexedWeightedPrivateElement>::value,
                        bool>::type;

                    //===========================================================================
                    // shares dealing functions

                    template<
                        typename Coeffs,
                        typename WeightsRange,
                        typename base_type::template check_private_element_type<typename Coeffs::value_type> = true,
                        check_weight_type<typename WeightsRange::value_type> = true>
                    static inline indexed_weighted_private_elements_type
                        deal_indexed_weighted_shares(const Coeffs &coeffs, const WeightsRange &weights) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const WeightsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        std::size_t n = std::distance(weights.begin(), weights.end());
                        assert(base_type::check_t(t, n));

                        std::size_t i = 1;
                        indexed_weighted_private_elements_type indexed_weighted_shares;
                        for (auto w_i : weights) {
                            assert(w_i > 0);
                            indexed_private_elements_type i_shares;
                            for (std::size_t j = 1; j <= w_i; j++) {
                                std::size_t id_ij = i * t + j;
                                assert(i_shares.emplace(id_ij, base_type::deal_share(coeffs, id_ij)).second);
                            }
                            assert(indexed_weighted_shares.emplace(i, i_shares).second);
                            ++i;
                        }
                        return indexed_weighted_shares;
                    }

                    template<
                        typename Coeffs,
                        typename WeightsRange,
                        typename base_type::template check_private_element_type<typename Coeffs::value_type> = true,
                        check_weight_type<typename WeightsRange::value_type> = true>
                    static inline indexed_private_elements_type
                        deal_indexed_weighted_joined_shares(const Coeffs &coeffs, const WeightsRange &weights) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const WeightsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        indexed_weighted_private_elements_type indexed_weighted_shares =
                            deal_indexed_weighted_shares(coeffs, weights);

                        indexed_private_elements_type indexed_weighted_joined_shares;
                        for (const auto &[i, i_shares] : indexed_weighted_shares) {
                            assert(indexed_weighted_joined_shares.emplace(join_weighted_share(i_shares, i)).second);
                        }
                        return indexed_weighted_joined_shares;
                    }

                    template<typename WeightedShare,
                             typename Number,
                             typename base_type::template check_indexed_private_elements_type<WeightedShare> = true,
                             typename base_type::template check_number_type<Number> = true>
                    static inline indexed_private_element_type join_weighted_share(const WeightedShare &i_share,
                                                                                   Number i) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const WeightedShare>));
                        assert(base_type::check_participant_index(i));

                        return indexed_private_element_type(i, base_type::recover_private_element(i_share));
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
