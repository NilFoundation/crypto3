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

#ifndef CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_SHAMIR_SSS_HPP

#include <vector>
#include <type_traits>
#include <unordered_map>

#include <boost/concept_check.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Group>
                struct shamir_sss {
                    typedef Group group_type;
                    typedef typename group_type::policy_type::base_field_type base_field_type;
                    typedef typename group_type::policy_type::scalar_field_type scalar_field_type;

                    typedef typename group_type::value_type group_value_type;
                    typedef typename base_field_type::value_type base_field_value_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;

                    //===========================================================================
                    // secret sharing scheme logical types

                    typedef scalar_field_value_type private_element_type;
                    typedef group_value_type public_element_type;
                    typedef std::vector<private_element_type> private_elements_type;
                    typedef std::vector<public_element_type> public_elements_type;
                    typedef std::pair<std::size_t, private_element_type> indexed_private_element_type;
                    typedef std::pair<std::size_t, public_element_type> indexed_public_element_type;
                    typedef std::unordered_map<std::size_t, private_element_type> indexed_private_elements_type;
                    typedef std::unordered_map<std::size_t, indexed_private_elements_type>
                        indexed_weighted_private_elements_type;
                    typedef std::set<std::size_t> indexes_type;

                    //===========================================================================
                    // constraints checking meta-functions

                    // TODO: indexes sufficiently to be integral according to checks,
                    //  however in code unsigned type is used, so overflows could appear
                    template<typename IndexedPrivateElement,
                             typename Index = typename IndexedPrivateElement::first_type,
                             typename std::enable_if<std::is_unsigned<Index>::value, bool>::type = true>
                    using get_indexed_private_element_type = std::pair<Index, private_element_type>;

                    template<typename IndexedPublicElement, typename Index = typename IndexedPublicElement::first_type,
                             typename std::enable_if<std::is_unsigned<Index>::value, bool>::type = true>
                    using get_indexed_public_element_type = std::pair<Index, public_element_type>;

                    template<typename IndexedPrivateElementsContainer>
                    using check_indexed_private_elements_container_type = typename std::enable_if<
                        std::is_same<
                            get_indexed_private_element_type<typename IndexedPrivateElementsContainer::value_type>,
                            typename IndexedPrivateElementsContainer::value_type>::value,
                        bool>::type;

                    //===========================================================================
                    // shares dealing functions

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<private_element_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline private_elements_type deal_shares(const CoeffsRange &coeffs, std::size_t n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        assert(check_t(t, n));

                        private_elements_type shares;
                        for (std::size_t i = 1; i <= n; i++) {
                            shares.emplace_back(deal_share(coeffs, i));
                        }
                        return shares;
                    }

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<private_element_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline indexed_private_elements_type deal_indexed_shares(const CoeffsRange &coeffs,
                                                                                    std::size_t n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        assert(check_t(t, n));

                        indexed_private_elements_type shares;
                        for (std::size_t i = 1; i <= n; i++) {
                            assert(shares.emplace(i, deal_share(coeffs, i)).second);
                        }
                        return shares;
                    }

                    template<typename CoeffsRange, typename WeightsRange,
                             typename std::enable_if<
                                 std::is_same<private_element_type, typename CoeffsRange::value_type>::value &&
                                     std::is_unsigned<typename WeightsRange::value_type>::value,
                                 bool>::type = true>
                    static inline indexed_weighted_private_elements_type
                        deal_indexed_weighted_shares(const CoeffsRange &coeffs, const WeightsRange &weights) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const WeightsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        std::size_t n = std::distance(weights.begin(), weights.end());
                        assert(check_t(t, n));

                        std::size_t i = 1;
                        indexed_weighted_private_elements_type indexed_weighted_shares;
                        for (auto w_i : weights) {
                            assert(w_i > 0);
                            indexed_private_elements_type i_shares;
                            for (std::size_t j = 1; j <= w_i; j++) {
                                std::size_t id_ij = i * t + j;
                                assert(i_shares.emplace(id_ij, deal_share(coeffs, id_ij)).second);
                            }
                            assert(indexed_weighted_shares.emplace(i, i_shares).second);
                            ++i;
                        }
                        return indexed_weighted_shares;
                    }

                    template<typename CoeffsRange, typename WeightsRange,
                             typename std::enable_if<
                                 std::is_same<private_element_type, typename CoeffsRange::value_type>::value &&
                                     std::is_unsigned<typename WeightsRange::value_type>::value,
                                 bool>::type = true>
                    static inline indexed_private_elements_type
                        deal_indexed_weighted_shares_with_additional_step(const CoeffsRange &coeffs,
                                                                          const WeightsRange &weights) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const WeightsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        indexed_weighted_private_elements_type indexed_weighted_shares =
                            deal_indexed_weighted_shares(coeffs, weights);

                        indexed_private_elements_type indexed_weighted_joined_shares;
                        for (const auto &[i, i_shares] : indexed_weighted_shares) {
                            assert(
                                indexed_weighted_joined_shares.emplace(join_weighted_shares(i_shares, i)).second);
                        }
                        return indexed_weighted_joined_shares;
                    }

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<private_element_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline private_element_type deal_share(const CoeffsRange &coeffs, std::size_t i) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));
                        assert(check_participant_index(i));

                        private_element_type e_i(i);
                        private_element_type temp = private_element_type::one();
                        private_element_type share = private_element_type::zero();

                        for (const auto &c : coeffs) {
                            share = share + c * temp;
                            temp = temp * e_i;
                        }
                        return share;
                    }

                    //
                    //  0 <= k < t
                    //
                    static inline private_element_type eval_partial_share(
                        const private_element_type &coeff, std::size_t i, std::size_t k,
                        const private_element_type &init_share_value = private_element_type::zero()) {
                        assert(check_participant_index(i));
                        return init_share_value + coeff * private_element_type(i).pow(k);
                    }

                    template<typename WeightedSharesContainer,
                             check_indexed_private_elements_container_type<WeightedSharesContainer> = true>
                    static inline indexed_private_element_type
                        join_weighted_shares(const WeightedSharesContainer &i_shares, std::size_t i) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const WeightedSharesContainer>));
                        assert(check_participant_index(i));

                        return indexed_private_element_type(i, recover_secret(i_shares));
                    }

                    //===========================================================================
                    // secret recovering functions

                    template<typename IndexedSharesContainer,
                             check_indexed_private_elements_container_type<IndexedSharesContainer> = true>
                    static inline private_element_type recover_secret(std::size_t t,
                                                                      const IndexedSharesContainer &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedSharesContainer>));

                        std::size_t shares_len = std::distance(shares.begin(), shares.end());
                        assert(check_minimal_size(t));
                        assert(shares_len >= t);

                        return recover_secret(shares);
                    }

                    template<typename IndexedSharesContainer,
                             check_indexed_private_elements_container_type<IndexedSharesContainer> = true>
                    static inline private_element_type recover_secret(const IndexedSharesContainer &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedSharesContainer>));

                        std::size_t shares_len = std::distance(shares.begin(), shares.end());
                        private_element_type result = private_element_type::zero();
                        indexes_type indexes = get_indexes(shares);

                        for (const auto &[i, s_i] : shares) {
                            result = result + s_i * eval_basis_poly(indexes, i);
                        }
                        return result;
                    }

                    static inline private_element_type eval_basis_poly(const indexes_type &indexes, std::size_t i) {
                        assert(check_participant_index(i));
                        assert(indexes.count(i));

                        private_element_type e_i(i);
                        private_element_type result = private_element_type::one();

                        for (auto j : indexes) {
                            if (j != i) {
                                result = result * (private_element_type(j) / (private_element_type(j) - e_i));
                            }
                        }
                        return result;
                    }

                    //===========================================================================
                    // polynomial generation functions

                    static inline private_elements_type get_poly(const std::size_t &t, const std::size_t &n) {
                        assert(check_t(t, n));

                        return get_poly(t);
                    }

                    // TODO: add custom random generation
                    static inline private_elements_type get_poly(const std::size_t &t) {
                        assert(check_minimal_size(t));

                        private_elements_type coeffs;

                        for (std::size_t i = 0; i < t; i++) {
                            coeffs.emplace_back(algebra::random_element<scalar_field_type>());
                        }
                        return coeffs;
                    }

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<private_element_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline public_elements_type get_public_poly(const CoeffsRange &coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        public_elements_type public_coeffs;

                        for (const auto &c : coeffs) {
                            public_coeffs.emplace_back(get_public_element(c));
                        }
                        return public_coeffs;
                    }

                    //===========================================================================
                    // general purposes functions

                    template<typename IndexedSharesContainer,
                             check_indexed_private_elements_container_type<IndexedSharesContainer> = true>
                    static inline indexes_type get_indexes(const IndexedSharesContainer &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedSharesContainer>));

                        indexes_type indexes;
                        for (const auto &s : shares) {
                            assert(check_participant_index(s.first) && indexes.emplace(s.first).second);
                        }
                        return indexes;
                    }

                    static inline public_element_type get_public_element(const private_element_type &s_i) {
                        return s_i * public_element_type::one();
                    }

                    static inline bool check_minimal_size(std::size_t size) {
                        return size >= 2;
                    }

                    static inline bool check_t(std::size_t t, std::size_t n) {
                        return check_minimal_size(t) && t <= n;
                    }

                    static inline bool strong_check_t(std::size_t t, std::size_t n) {
                        return check_t(t, n) && t >= get_minimal_t(n);
                    }

                    static inline bool check_participant_index(std::size_t i) {
                        return i > 0;
                    }

                    static inline std::size_t get_minimal_t(std::size_t n) {
                        assert(check_minimal_size(n));
                        return (n + 1) / 2;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
