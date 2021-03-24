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

#ifndef CRYPTO3_PUBKEY_DETAIL_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_DETAIL_SHAMIR_SSS_HPP

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
                    typedef typename group_type::policy_type::scalar_field_type scalar_field_type;

                    typedef typename group_type::value_type group_value_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;

                    typedef scalar_field_value_type private_element_type;
                    typedef group_value_type public_element_type;

                    //===========================================================================
                    // secret sharing scheme logical types

                    typedef private_element_type coeff_type;
                    typedef public_element_type public_coeff_type;
                    typedef std::vector<coeff_type> coeffs_type;
                    typedef std::vector<public_coeff_type> public_coeffs_type;
                    typedef std::pair<std::size_t, private_element_type> share_type;
                    typedef std::pair<std::size_t, public_element_type> public_share_type;
                    typedef std::unordered_map<std::size_t, private_element_type> shares_type;
                    typedef std::unordered_map<std::size_t, public_element_type> public_shares_type;
                    typedef std::set<std::size_t> indexes_type;

                    //===========================================================================
                    // constraints checking meta-functions

                    // TODO: indexes sufficiently to be integral according to checks,
                    //  however in code unsigned type is used, so overflows could appear
                    template<typename Number>
                    using check_number_type = typename std::enable_if<std::is_integral<Number>::value, bool>::type;

                    template<typename Index>
                    using check_index_type = check_number_type<Index>;

                    template<typename PrivateElement>
                    using check_private_element_type =
                        typename std::enable_if<std::is_same<private_element_type, PrivateElement>::value, bool>::type;

                    template<typename PublicElement>
                    using check_public_element_type =
                        typename std::enable_if<std::is_same<public_element_type, PublicElement>::value, bool>::type;

                    template<typename IndexedPrivateElement,
                             typename Index = typename IndexedPrivateElement::first_type,
                             check_index_type<Index> = true>
                    using get_indexed_private_element_type = std::pair<Index, private_element_type>;

                    template<typename IndexedPublicElement, typename Index = typename IndexedPublicElement::first_type,
                             check_index_type<Index> = true>
                    using get_indexed_public_element_type = std::pair<Index, public_element_type>;

                    template<typename IndexedElement, typename Index = typename IndexedElement::first_type,
                             check_index_type<Index> = true>
                    using get_indexed_element_type = std::pair<Index, typename IndexedElement::second_type>;

                    template<typename IndexedPrivateElement>
                    using check_indexed_private_element_type =
                        typename std::enable_if<std::is_same<get_indexed_private_element_type<IndexedPrivateElement>,
                                                             IndexedPrivateElement>::value,
                                                bool>::type;

                    template<typename IndexedPublicElement>
                    using check_indexed_public_element_type =
                        typename std::enable_if<std::is_same<get_indexed_public_element_type<IndexedPublicElement>,
                                                             IndexedPublicElement>::value,
                                                bool>::type;

                    template<typename IndexedElement>
                    using check_indexed_element_type = typename std::enable_if<
                        std::is_same<get_indexed_element_type<IndexedElement>, IndexedElement>::value, bool>::type;

                    template<typename IndexedPrivateElements>
                    using check_indexed_private_elements_type =
                        check_indexed_private_element_type<typename IndexedPrivateElements::value_type>;

                    template<typename IndexedPublicElements>
                    using check_indexed_public_elements_type =
                        check_indexed_public_element_type<typename IndexedPublicElements::value_type>;

                    template<typename IndexedElements>
                    using check_indexed_elements_type =
                        check_indexed_element_type<typename IndexedElements::value_type>;

                    //===========================================================================
                    // shares dealing functions

                    template<typename Coeffs, typename Number,
                             check_private_element_type<typename Coeffs::value_type> = true,
                             check_number_type<Number> = true>
                    static inline shares_type deal_shares(const Coeffs &coeffs, Number n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        assert(check_t(t, n));

                        shares_type shares;
                        for (std::size_t i = 1; i <= n; i++) {
                            assert(shares.emplace(deal_share(coeffs, i)).second);
                        }
                        return shares;
                    }

                    template<typename Coeffs, typename Number,
                             check_private_element_type<typename Coeffs::value_type> = true,
                             check_number_type<Number> = true>
                    static inline share_type deal_share(const Coeffs &coeffs, Number i) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                        assert(check_participant_index(i));
                        assert(check_minimal_size(std::distance(coeffs.begin(), coeffs.end())));

                        private_element_type e_i(i);
                        private_element_type temp = private_element_type::one();
                        private_element_type share = private_element_type::zero();

                        for (const auto &c : coeffs) {
                            share = share + c * temp;
                            temp = temp * e_i;
                        }
                        return share_type(i, share);
                    }

                    //
                    //  0 <= k < t
                    //
                    template<typename Number, check_number_type<Number> = true>
                    static inline share_type partial_eval_share(const coeff_type &coeff, Number exp,
                                                                const share_type &init_share_value) {
                        assert(check_participant_index(init_share_value.first));
                        assert(check_exp(exp));
                        return share_type(init_share_value.first,
                                          init_share_value.second +
                                              coeff * private_element_type(init_share_value.first).pow(exp));
                    }

                    //===========================================================================
                    // secret recovering functions

                    template<typename Shares, typename Number = std::size_t, check_indexed_private_elements_type<Shares> = true,
                        check_number_type<Number> = true>
                    static inline private_element_type reconstruct_secret(const Shares &shares, Number id_i = 0) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));

                        private_element_type secret = private_element_type::zero();
                        indexes_type indexes = get_shares_indexes(shares);
                        for (const auto &[i, s_i] : shares) {
                            secret = secret + s_i * eval_basis_poly(indexes, id_i ? id_i : i);
                        }
                        return secret;
                    }

                    template<typename PublicShares, check_indexed_public_elements_type<PublicShares> = true>
                    static inline public_element_type reconstruct_public_element(const PublicShares &public_shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicShares>));
                        assert(check_minimal_size(std::distance(public_shares.begin(), public_shares.end())));

                        public_element_type result = public_element_type::zero();
                        indexes_type indexes = get_shares_indexes(public_shares);

                        for (const auto &[i, e_i] : public_shares) {
                            result = result + eval_basis_poly(indexes, i) * e_i;
                        }
                        return result;
                    }

                    template<typename Number, check_number_type<Number> = true>
                    static inline private_element_type eval_basis_poly(const indexes_type &indexes, Number i) {
                        assert(check_participant_index(i));

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

                    template<typename Number1, typename Number2, check_number_type<Number1> = true,
                             check_number_type<Number2> = true>
                    static inline coeffs_type get_poly(Number1 t, Number2 n) {
                        assert(check_t(t, n));
                        return get_poly(t);
                    }

                    // TODO: add custom random generation
                    template<typename Number, check_number_type<Number> = true>
                    static inline coeffs_type get_poly(Number t) {
                        assert(check_minimal_size(t));
                        coeffs_type coeffs;
                        for (std::size_t i = 0; i < t; i++) {
                            coeffs.emplace_back(algebra::random_element<scalar_field_type>());
                        }
                        return coeffs;
                    }

                    //===========================================================================
                    // general purposes functions

                    template<typename IndexedElements, check_indexed_elements_type<IndexedElements> = true>
                    static inline indexes_type get_shares_indexes(const IndexedElements &elements) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedElements>));

                        indexes_type indexes;
                        for (const auto &e : elements) {
                            assert(check_participant_index(e.first) && indexes.emplace(e.first).second);
                        }
                        return indexes;
                    }

                    template<typename Coeffs, check_private_element_type<typename Coeffs::value_type> = true>
                    static inline public_coeffs_type get_public_coeffs(const Coeffs &coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                        assert(check_minimal_size(std::distance(coeffs.begin(), coeffs.end())));

                        public_coeffs_type public_coeffs;
                        for (const auto &c : coeffs) {
                            public_coeffs.emplace_back(get_public_element(c));
                        }
                        return public_coeffs;
                    }

                    template<typename Shares, check_indexed_private_elements_type<Shares> = true>
                    static inline public_shares_type get_public_shares(const Shares &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                        assert(check_minimal_size(std::distance(shares.begin(), shares.end())));

                        public_shares_type public_shares;
                        for (const auto &s : shares) {
                            assert(public_shares.emplace(get_public_share(s)).second);
                        }
                        return public_shares;
                    }

                    template<typename Share, check_indexed_private_element_type<Share> = true>
                    static inline public_share_type get_public_share(const Share &s) {
                        return public_share_type(s.first, get_public_element(s.second));
                    }

                    static inline public_element_type get_public_element(const private_element_type &s) {
                        return s * public_element_type::one();
                    }

                    template<typename Number, check_number_type<Number> = true>
                    static inline bool check_minimal_size(Number size) {
                        return size >= 2;
                    }

                    template<typename Number, check_number_type<Number> = true>
                    static inline bool check_participant_index(Number i) {
                        return i > 0;
                    }

                    template<typename Number, check_number_type<Number> = true>
                    static inline std::size_t get_minimal_t(Number n) {
                        assert(check_minimal_size(n));
                        return (n + 1) / 2;
                    }

                    template<typename Number1, typename Number2, check_number_type<Number1> = true,
                             check_number_type<Number2> = true>
                    static inline bool check_t(Number1 t, Number2 n) {
                        return check_minimal_size(t) && n >= t && t >= get_minimal_t(n);
                    }

                    template<typename Number, check_number_type<Number> = true>
                    static inline bool check_exp(Number exp) {
                        return exp >= 0;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_DETAIL_SHAMIR_SSS_HPP
